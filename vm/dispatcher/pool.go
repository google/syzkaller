// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package dispatcher

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/stat"
)

type Instance interface {
	io.Closer
}

type UpdateInfo func(cb func(info *Info))
type Runner[T Instance] func(ctx context.Context, inst T, updInfo UpdateInfo)
type CreateInstance[T Instance] func(context.Context, int) (T, error)

// Pool[T] provides the functionality of a generic pool of instances.
// The instance is assumed to boot, be controlled by one Runner and then be re-created.
// The pool is assumed to have one default Runner (e.g. to be used for fuzzing), while a
// dynamically controlled sub-pool might be reserved for the arbitrary Runners.
type Pool[T Instance] struct {
	BootErrors chan error
	BootTime   stat.AverageValue[time.Duration]

	creator    CreateInstance[T]
	defaultJob Runner[T]
	jobs       chan Runner[T]

	// The mutex serializes ReserveForRun() and SetDefault() calls.
	mu        *sync.Mutex
	cv        *sync.Cond
	instances []*poolInstance[T]
	paused    bool
}

const bootErrorChanCap = 16

func NewPool[T Instance](count int, creator CreateInstance[T], def Runner[T]) *Pool[T] {
	instances := make([]*poolInstance[T], count)
	for i := 0; i < count; i++ {
		inst := &poolInstance[T]{
			job: def,
			idx: i,
		}
		inst.reset(func() {})
		instances[i] = inst
	}
	mu := new(sync.Mutex)
	return &Pool[T]{
		BootErrors: make(chan error, bootErrorChanCap),
		creator:    creator,
		defaultJob: def,
		instances:  instances,
		jobs:       make(chan Runner[T]),
		mu:         mu,
		cv:         sync.NewCond(mu),
	}
}

// UpdateDefault forces all VMs to restart.
func (p *Pool[T]) SetDefault(def Runner[T]) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.defaultJob = def
	p.kickDefault()
}

func (p *Pool[T]) kickDefault() {
	for _, inst := range p.instances {
		if !inst.reserved() {
			inst.free(p.defaultJob)
		}
	}
}

func (p *Pool[T]) TogglePause(paused bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.paused = paused
	if paused {
		p.kickDefault()
	} else {
		p.cv.Broadcast()
	}
}

func (p *Pool[T]) waitUnpaused() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for p.paused {
		p.cv.Wait()
	}
}

func (p *Pool[T]) Loop(ctx context.Context) {
	var wg sync.WaitGroup
	wg.Add(len(p.instances))
	for _, inst := range p.instances {
		go func() {
			for ctx.Err() == nil {
				p.runInstance(ctx, inst)
			}
			wg.Done()
		}()
	}
	wg.Wait()
}

func (p *Pool[T]) runInstance(ctx context.Context, inst *poolInstance[T]) {
	p.waitUnpaused()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	log.Logf(2, "pool: booting instance %d", inst.idx)

	inst.reset(cancel)

	start := time.Now()
	inst.status(StateBooting)
	defer inst.status(StateOffline)

	obj, err := p.creator(ctx, inst.idx)
	if err != nil {
		p.reportBootError(ctx, err)
		return
	}
	defer obj.Close()

	p.BootTime.Save(time.Since(start))

	inst.status(StateWaiting)
	// The job and jobChan fields are subject to concurrent updates.
	inst.mu.Lock()
	job, jobChan := inst.job, inst.jobChan
	inst.mu.Unlock()

	if job == nil {
		select {
		case newJob := <-jobChan:
			job = newJob
		case newJob := <-inst.switchToJob:
			job = newJob
		case <-ctx.Done():
			return
		}
	}

	inst.status(StateRunning)
	job(ctx, obj, inst.updateInfo)
}

func (p *Pool[T]) reportBootError(ctx context.Context, err error) {
	select {
	case p.BootErrors <- err:
		log.Logf(0, "boot error: %s", err)
		return
	default:
		// Print some log message to make it visible.
		log.Logf(0, "WARNING: boot error channel is full!")
	}
	select {
	case p.BootErrors <- err:
	case <-ctx.Done():
		// On context cancellation, no one might be listening on the channel.
	}
}

// ReserveForRun specifies the size of the sub-pool for the execution of custom runners.
// The reserved instances will be booted, but the pool will not start the default runner.
// To unreserve all instances, execute ReserveForRun(0).
func (p *Pool[T]) ReserveForRun(count int) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if count > len(p.instances) {
		panic("trying to reserve more VMs than present")
	}

	var free, reserved []*poolInstance[T]
	for _, inst := range p.instances {
		if inst.reserved() {
			reserved = append(reserved, inst)
		} else {
			free = append(free, inst)
		}
	}

	needReserve := count - len(reserved)
	for i := 0; i < needReserve; i++ {
		log.Logf(2, "pool: reserving instance %d", free[i].idx)
		free[i].reserve(p.jobs)
	}

	needFree := len(reserved) - count
	for i := 0; i < needFree; i++ {
		log.Logf(2, "pool: releasing instance %d", reserved[i].idx)
		reserved[i].free(p.defaultJob)
	}
}

// Run blocks until it has found an instance to execute job and until job has finished.
// Returns an error if the job was aborted by cancelling the context.
func (p *Pool[T]) Run(ctx context.Context, job Runner[T]) error {
	done := make(chan error)
	// Submit the job.
	select {
	case p.jobs <- func(jobCtx context.Context, inst T, upd UpdateInfo) {
		mergedCtx, cancel := mergeContextCancel(jobCtx, ctx)
		defer cancel()

		job(mergedCtx, inst, upd)
		done <- mergedCtx.Err()
	}:
	case <-ctx.Done():
		// If the loop is aborted, no one is going to pick up the job.
		return ctx.Err()
	}
	// Await the job.
	return <-done
}

func (p *Pool[T]) Total() int {
	return len(p.instances)
}

type Info struct {
	State      InstanceState
	Status     string
	LastUpdate time.Time
	Reserved   bool

	// The optional callbacks.
	MachineInfo    func() []byte
	DetailedStatus func() []byte
}

func (p *Pool[T]) State() []Info {
	p.mu.Lock()
	defer p.mu.Unlock()

	ret := make([]Info, len(p.instances))
	for i, inst := range p.instances {
		ret[i] = inst.getInfo()
	}
	return ret
}

// poolInstance is not thread safe.
type poolInstance[T Instance] struct {
	mu   sync.Mutex
	info Info
	idx  int

	// Either job or jobChan will be set.
	job         Runner[T]
	jobChan     chan Runner[T]
	switchToJob chan Runner[T]
	stop        func()
}

type InstanceState int

const (
	StateOffline InstanceState = iota
	StateBooting
	StateWaiting
	StateRunning
)

// reset() and status() may be called concurrently to all other methods.
// Other methods themselves are serialized.
func (pi *poolInstance[T]) reset(stop func()) {
	pi.mu.Lock()
	defer pi.mu.Unlock()

	pi.info = Info{
		State:      StateOffline,
		LastUpdate: time.Now(),
		Reserved:   pi.info.Reserved,
	}
	pi.stop = stop
	pi.switchToJob = make(chan Runner[T])
}

func (pi *poolInstance[T]) updateInfo(upd func(*Info)) {
	pi.mu.Lock()
	defer pi.mu.Unlock()
	upd(&pi.info)
	pi.info.LastUpdate = time.Now()
}

func (pi *poolInstance[T]) status(status InstanceState) {
	pi.updateInfo(func(info *Info) {
		info.State = status
	})
}

func (pi *poolInstance[T]) reserved() bool {
	return pi.jobChan != nil
}

func (pi *poolInstance[T]) getInfo() Info {
	pi.mu.Lock()
	defer pi.mu.Unlock()
	return pi.info
}

func (pi *poolInstance[T]) reserve(ch chan Runner[T]) {
	pi.mu.Lock()
	// If we don't take the lock, it's possible that instance restart would race with job/jobChan update.
	pi.stop()
	pi.jobChan = ch
	pi.job = nil
	pi.info.Reserved = true
	pi.mu.Unlock()
}

func (pi *poolInstance[T]) free(job Runner[T]) {
	pi.mu.Lock()
	if pi.job != nil {
		// A change of a default job, let's force restart the instance.
		pi.stop()
	}
	pi.job = job
	pi.jobChan = nil
	switchToJob := pi.switchToJob
	pi.info.Reserved = false
	pi.mu.Unlock()

	select {
	case switchToJob <- job:
		// Just in case the instance has been waiting.
		return
	default:
	}
}

//nolint:syz-linter
func mergeContextCancel(main, monitor context.Context) (context.Context, func()) {
	withCancel, cancel := context.WithCancel(main)
	go func() {
		select {
		case <-withCancel.Done():
		case <-monitor.Done():
		}
		cancel()
	}()
	return withCancel, cancel
}
