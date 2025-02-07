// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package queue

import (
	"bytes"
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/stat"
	"github.com/google/syzkaller/prog"
)

type Request struct {
	// Type of the request.
	// RequestTypeProgram executes Prog, and is used by most requests (also the default zero value).
	// RequestTypeBinary executes binary with file name stored in Data.
	// RequestTypeGlob expands glob pattern stored in Data.
	Type        flatrpc.RequestType
	ExecOpts    flatrpc.ExecOpts
	Prog        *prog.Prog // for RequestTypeProgram
	BinaryFile  string     // for RequestTypeBinary
	GlobPattern string     // for 	RequestTypeGlob

	// Return all signal for these calls instead of new signal.
	ReturnAllSignal []int
	ReturnError     bool
	ReturnOutput    bool

	// This stat will be incremented on request completion.
	Stat *stat.Val

	// Important requests will be retried even from crashed VMs.
	Important bool

	// Avoid specifies set of executors that are preferable to avoid when executing this request.
	// The restriction is soft since there can be only one executor at all or available right now.
	Avoid []ExecutorID

	// The callback will be called on request completion in the LIFO order.
	// If it returns false, all further processing will be stopped.
	// It allows wrappers to intercept Done() requests.
	callback DoneCallback

	onceCrashed  bool
	delayedSince uint64

	mu     sync.Mutex
	result *Result
	done   chan struct{}
}

type ExecutorID struct {
	VM   int
	Proc int
}

type DoneCallback func(*Request, *Result) bool

func (r *Request) OnDone(cb DoneCallback) {
	oldCallback := r.callback
	r.callback = func(req *Request, res *Result) bool {
		r.callback = oldCallback
		if !cb(req, res) {
			return false
		}
		if oldCallback == nil {
			return true
		}
		return oldCallback(req, res)
	}
}

func (r *Request) Done(res *Result) {
	if r.callback != nil {
		if !r.callback(r, res) {
			return
		}
	}
	if r.Stat != nil {
		r.Stat.Add(1)
	}
	r.initChannel()
	r.result = res
	close(r.done)
}

var ErrRequestAborted = errors.New("context closed while waiting the result")

// Wait() blocks until we have the result.
func (r *Request) Wait(ctx context.Context) *Result {
	r.initChannel()
	select {
	case <-ctx.Done():
		return &Result{Status: ExecFailure, Err: ErrRequestAborted}
	case <-r.done:
		return r.result
	}
}

// Risky() returns true if there's a substantial risk of the input crashing the VM.
func (r *Request) Risky() bool {
	return r.onceCrashed
}

func (r *Request) Validate() error {
	collectSignal := r.ExecOpts.ExecFlags&flatrpc.ExecFlagCollectSignal > 0
	if len(r.ReturnAllSignal) != 0 && !collectSignal {
		return fmt.Errorf("ReturnAllSignal is set, but FlagCollectSignal is not")
	}
	collectComps := r.ExecOpts.ExecFlags&flatrpc.ExecFlagCollectComps > 0
	collectCover := r.ExecOpts.ExecFlags&flatrpc.ExecFlagCollectCover > 0
	if (collectComps) && (collectSignal || collectCover) {
		return fmt.Errorf("hint collection is mutually exclusive with signal/coverage")
	}
	switch r.Type {
	case flatrpc.RequestTypeProgram:
		if r.Prog == nil {
			return fmt.Errorf("program is not set")
		}
		sandboxes := flatrpc.ExecEnvSandboxNone | flatrpc.ExecEnvSandboxSetuid |
			flatrpc.ExecEnvSandboxNamespace | flatrpc.ExecEnvSandboxAndroid
		if r.ExecOpts.EnvFlags&sandboxes == 0 {
			return fmt.Errorf("no sandboxes set")
		}
	case flatrpc.RequestTypeBinary:
		if r.BinaryFile == "" {
			return fmt.Errorf("binary file name is not set")
		}
	case flatrpc.RequestTypeGlob:
		if r.GlobPattern == "" {
			return fmt.Errorf("glob pattern is not set")
		}
	default:
		return fmt.Errorf("unknown request type")
	}
	return nil
}

func (r *Request) hash() hash.Sig {
	buf := new(bytes.Buffer)
	enc := gob.NewEncoder(buf)
	if err := enc.Encode(r.Type); err != nil {
		panic(err)
	}
	if err := enc.Encode(r.ExecOpts); err != nil {
		panic(err)
	}
	var data []byte
	switch r.Type {
	case flatrpc.RequestTypeProgram:
		data = r.Prog.Serialize()
	case flatrpc.RequestTypeBinary:
		data = []byte(r.BinaryFile)
	case flatrpc.RequestTypeGlob:
		data = []byte(r.GlobPattern)
	default:
		panic("unknown request type")
	}
	return hash.Hash(data, buf.Bytes())
}

func (r *Request) initChannel() {
	r.mu.Lock()
	if r.done == nil {
		r.done = make(chan struct{})
	}
	r.mu.Unlock()
}

type Result struct {
	Info     *flatrpc.ProgInfo
	Executor ExecutorID
	Output   []byte
	Status   Status
	Err      error // More details in case of ExecFailure.
}

func (r *Result) clone() *Result {
	ret := *r
	ret.Info = ret.Info.Clone()
	return &ret
}

func (r *Result) Stop() bool {
	switch r.Status {
	case Success, Restarted:
		return false
	case ExecFailure, Crashed, Hanged:
		return true
	default:
		panic(fmt.Sprintf("unhandled status %v", r.Status))
	}
}

// Globs returns result of RequestTypeGlob.
func (r *Result) GlobFiles() []string {
	out := strings.Trim(string(r.Output), "\000")
	if out == "" {
		return nil
	}
	return strings.Split(out, "\000")
}

type Status int

const (
	Success     Status = iota
	ExecFailure        // For e.g. serialization errors.
	Crashed            // The VM crashed holding the request.
	Restarted          // The VM was restarted holding the request.
	Hanged             // The program has hanged (can't be killed/waited).
)

// Executor describes the interface wanted by the producers of requests.
// After a Request is submitted, it's expected that the consumer will eventually
// take it and report the execution result via Done().
type Executor interface {
	Submit(req *Request)
}

// Source describes the interface wanted by the consumers of requests.
type Source interface {
	Next() *Request
}

// PlainQueue is a straighforward thread-safe Request queue implementation.
type PlainQueue struct {
	mu    sync.Mutex
	queue []*Request
	pos   int
}

func Plain() *PlainQueue {
	return &PlainQueue{}
}

func (pq *PlainQueue) Len() int {
	pq.mu.Lock()
	defer pq.mu.Unlock()
	return len(pq.queue) - pq.pos
}

func (pq *PlainQueue) Submit(req *Request) {
	pq.mu.Lock()
	defer pq.mu.Unlock()

	// It doesn't make sense to compact the queue too often.
	const minSizeToCompact = 128
	if pq.pos > len(pq.queue)/2 && len(pq.queue) >= minSizeToCompact {
		copy(pq.queue, pq.queue[pq.pos:])
		for pq.pos > 0 {
			newLen := len(pq.queue) - 1
			pq.queue[newLen] = nil
			pq.queue = pq.queue[:newLen]
			pq.pos--
		}
	}
	pq.queue = append(pq.queue, req)
}

func (pq *PlainQueue) Next() *Request {
	pq.mu.Lock()
	defer pq.mu.Unlock()
	return pq.nextLocked()
}

func (pq *PlainQueue) tryNext() *Request {
	if !pq.mu.TryLock() {
		return nil
	}
	defer pq.mu.Unlock()
	return pq.nextLocked()
}

func (pq *PlainQueue) nextLocked() *Request {
	if pq.pos == len(pq.queue) {
		return nil
	}
	ret := pq.queue[pq.pos]
	pq.queue[pq.pos] = nil
	pq.pos++
	return ret
}

// Order combines several different sources in a particular order.
type orderImpl struct {
	sources []Source
}

func Order(sources ...Source) Source {
	return &orderImpl{sources: sources}
}

func (o *orderImpl) Next() *Request {
	for _, s := range o.sources {
		req := s.Next()
		if req != nil {
			return req
		}
	}
	return nil
}

type callback struct {
	cb func() *Request
}

// Callback produces a source that calls the callback to serve every Next() request.
func Callback(cb func() *Request) Source {
	return &callback{cb}
}

func (cb *callback) Next() *Request {
	return cb.cb()
}

type alternate struct {
	base Source
	nth  int
	seq  atomic.Int64
}

// Alternate proxies base, but returns nil every nth Next() call.
func Alternate(base Source, nth int) Source {
	return &alternate{
		base: base,
		nth:  nth,
	}
}

func (a *alternate) Next() *Request {
	if a.seq.Add(1)%int64(a.nth) == 0 {
		return nil
	}
	return a.base.Next()
}

type DynamicOrderer struct {
	mu       sync.Mutex
	currPrio int
	ops      *priorityQueueOps[*Request]
}

// DynamicOrder() can be used to form nested queues dynamically.
// That is, if
// q1 := pq.Append()
// q2 := pq.Append()
// All elements added via q2.Submit() will always have a *lower* priority
// than all elements added via q1.Submit().
func DynamicOrder() *DynamicOrderer {
	return &DynamicOrderer{
		ops: &priorityQueueOps[*Request]{},
	}
}

func (do *DynamicOrderer) Append() Executor {
	do.mu.Lock()
	defer do.mu.Unlock()
	do.currPrio++
	return &dynamicOrdererItem{
		parent: do,
		prio:   do.currPrio,
	}
}

func (do *DynamicOrderer) submit(req *Request, prio int) {
	do.mu.Lock()
	defer do.mu.Unlock()
	do.ops.Push(req, prio)
}

func (do *DynamicOrderer) Next() *Request {
	do.mu.Lock()
	defer do.mu.Unlock()
	return do.ops.Pop()
}

type dynamicOrdererItem struct {
	parent *DynamicOrderer
	prio   int
}

func (doi *dynamicOrdererItem) Submit(req *Request) {
	doi.parent.submit(req, doi.prio)
}

type DynamicSourceCtl struct {
	value atomic.Pointer[Source]
}

// DynamicSource is assumed never to point to nil.
func DynamicSource(source Source) *DynamicSourceCtl {
	var ret DynamicSourceCtl
	ret.Store(source)
	return &ret
}

func (ds *DynamicSourceCtl) Store(source Source) {
	ds.value.Store(&source)
}

func (ds *DynamicSourceCtl) Next() *Request {
	return (*ds.value.Load()).Next()
}

// Deduplicator() keeps track of the previously run requests to avoid re-running them.
type Deduplicator struct {
	mu     sync.Mutex
	source Source
	mm     map[hash.Sig]*duplicateState
}

type duplicateState struct {
	res    *Result
	queued []*Request // duplicate requests waiting for the result.
}

func Deduplicate(source Source) Source {
	return &Deduplicator{
		source: source,
		mm:     map[hash.Sig]*duplicateState{},
	}
}

func (d *Deduplicator) Next() *Request {
	for {
		req := d.source.Next()
		if req == nil {
			return nil
		}
		hash := req.hash()
		d.mu.Lock()
		entry, ok := d.mm[hash]
		if !ok {
			d.mm[hash] = &duplicateState{}
		} else if entry.res == nil {
			// There's no result yet, put the request to the queue.
			entry.queued = append(entry.queued, req)
		} else {
			// We already know the result.
			req.Done(entry.res.clone())
		}
		d.mu.Unlock()
		if !ok {
			// This is the first time we see such a request.
			req.OnDone(d.onDone)
			return req
		}
	}
}

func (d *Deduplicator) onDone(req *Request, res *Result) bool {
	hash := req.hash()
	clonedRes := res.clone()

	d.mu.Lock()
	entry := d.mm[hash]
	queued := entry.queued
	entry.queued = nil
	entry.res = clonedRes
	d.mu.Unlock()

	// Broadcast the result.
	for _, waitingReq := range queued {
		waitingReq.Done(res.clone())
	}
	return true
}

// DefaultOpts applies opts to all requests in source.
func DefaultOpts(source Source, opts flatrpc.ExecOpts) Source {
	return &defaultOpts{source, opts}
}

type defaultOpts struct {
	source Source
	opts   flatrpc.ExecOpts
}

func (do *defaultOpts) Next() *Request {
	req := do.source.Next()
	if req == nil {
		return nil
	}
	req.ExecOpts.ExecFlags |= do.opts.ExecFlags
	req.ExecOpts.EnvFlags |= do.opts.EnvFlags
	req.ExecOpts.SandboxArg = do.opts.SandboxArg
	return req
}

// RandomQueue holds up to |size| elements.
// Next() evicts a random one.
// On Submit(), if the queue is full, a random element is replaced.
type RandomQueue struct {
	mu      sync.Mutex
	queue   []*Request
	maxSize int
	rnd     *rand.Rand
}

func NewRandomQueue(size int, rnd *rand.Rand) *RandomQueue {
	return &RandomQueue{
		maxSize: size,
		rnd:     rnd,
	}
}

func (rq *RandomQueue) Next() *Request {
	rq.mu.Lock()
	defer rq.mu.Unlock()
	if len(rq.queue) == 0 {
		return nil
	}
	pos := rq.rnd.Intn(len(rq.queue))
	item := rq.queue[pos]

	last := len(rq.queue) - 1
	rq.queue[pos] = rq.queue[last]
	rq.queue[last] = nil
	rq.queue = rq.queue[0 : len(rq.queue)-1]
	return item
}

var errEvictedFromQueue = errors.New("evicted from the random queue")

func (rq *RandomQueue) Submit(req *Request) {
	rq.mu.Lock()
	defer rq.mu.Unlock()
	if len(rq.queue) < rq.maxSize {
		rq.queue = append(rq.queue, req)
	} else {
		pos := rq.rnd.Intn(rq.maxSize + 1)
		if pos < len(rq.queue) {
			rq.queue[pos].Done(&Result{
				Status: ExecFailure,
				Err:    errEvictedFromQueue,
			})
			rq.queue[pos] = req
		}
	}
}

type tee struct {
	queue Executor
	src   Source
}

func Tee(src Source, queue Executor) Source {
	return &tee{src: src, queue: queue}
}

func (t *tee) Next() *Request {
	req := t.src.Next()
	if req == nil {
		return nil
	}
	t.queue.Submit(&Request{
		Prog: req.Prog.Clone(),
	})
	return req
}
