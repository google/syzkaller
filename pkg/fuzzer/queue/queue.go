// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package queue

import (
	"bytes"
	"context"
	"encoding/gob"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/stats"
	"github.com/google/syzkaller/prog"
)

type Request struct {
	Prog     *prog.Prog
	ExecOpts flatrpc.ExecOpts

	// If specified, the resulting signal for call SignalFilterCall
	// will include subset of it even if it's not new.
	SignalFilter     signal.Signal
	SignalFilterCall int

	// Return all signal for these calls instead of new signal.
	ReturnAllSignal []int
	ReturnError     bool
	ReturnOutput    bool

	// This stat will be incremented on request completion.
	Stat *stats.Val

	// Options needed by runtest.
	BinaryFile string // If set, it's executed instead of Prog.

	// Important requests will be retried even from crashed VMs.
	Important bool

	// The callback will be called on request completion in the LIFO order.
	// If it returns false, all further processing will be stopped.
	// It allows wrappers to intercept Done() requests.
	callback DoneCallback

	onceCrashed bool

	mu     sync.Mutex
	result *Result
	done   chan struct{}
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

// Wait() blocks until we have the result.
func (r *Request) Wait(ctx context.Context) *Result {
	r.initChannel()
	select {
	case <-ctx.Done():
		return &Result{Status: ExecFailure}
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
	if r.SignalFilter != nil && !collectSignal {
		return fmt.Errorf("SignalFilter must be used with FlagCollectSignal")
	}
	collectComps := r.ExecOpts.ExecFlags&flatrpc.ExecFlagCollectComps > 0
	collectCover := r.ExecOpts.ExecFlags&flatrpc.ExecFlagCollectCover > 0
	if (collectComps) && (collectSignal || collectCover) {
		return fmt.Errorf("hint collection is mutually exclusive with signal/coverage")
	}
	sandboxes := flatrpc.ExecEnvSandboxNone | flatrpc.ExecEnvSandboxSetuid |
		flatrpc.ExecEnvSandboxNamespace | flatrpc.ExecEnvSandboxAndroid
	if r.BinaryFile == "" && r.ExecOpts.EnvFlags&sandboxes == 0 {
		return fmt.Errorf("no sandboxes set")
	}
	return nil
}

func (r *Request) hash() hash.Sig {
	buf := new(bytes.Buffer)
	if err := gob.NewEncoder(buf).Encode(r.ExecOpts); err != nil {
		panic(err)
	}
	return hash.Hash(r.Prog.Serialize(), buf.Bytes())
}

func (r *Request) initChannel() {
	r.mu.Lock()
	if r.done == nil {
		r.done = make(chan struct{})
	}
	r.mu.Unlock()
}

type Result struct {
	Info   *flatrpc.ProgInfo
	Output []byte
	Status Status
	Err    error // More details in case of ExecFailure.
}

func (r *Result) clone() *Result {
	ret := *r
	ret.Info = ret.Info.Clone()
	return &ret
}

func (r *Result) Stop() bool {
	return r.Status == ExecFailure || r.Status == Crashed
}

type Status int

const (
	Success     Status = iota
	ExecFailure        // For e.g. serialization errors.
	Crashed            // The VM crashed holding the request.
	Restarted          // The VM was restarted holding the request.
)

// Executor describes the interface wanted by the producers of requests.
// After a Request is submitted, it's expected that the consumer will eventually
// take it and report the execution result via Done().
type Executor interface {
	Submit(req *Request)
}

// Source describes the interface wanted by the consumers of requests.
type Source interface {
	Next() (req *Request, stop bool)
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

func (pq *PlainQueue) Next() (*Request, bool) {
	pq.mu.Lock()
	defer pq.mu.Unlock()
	return pq.nextLocked(), false
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

func (o *orderImpl) Next() (*Request, bool) {
	allStop := true
	for _, s := range o.sources {
		req, stop := s.Next()
		if req != nil {
			return req, false
		}
		if !stop {
			allStop = false
		}
	}
	return nil, allStop
}

type callback struct {
	cb func() (*Request, bool)
}

// Callback produces a source that calls the callback to serve every Next() request.
func Callback(cb func() (*Request, bool)) Source {
	return &callback{cb}
}

func (cb *callback) Next() (*Request, bool) {
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

func (a *alternate) Next() (*Request, bool) {
	if a.seq.Add(1)%int64(a.nth) == 0 {
		return nil, false
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

func (do *DynamicOrderer) Next() (*Request, bool) {
	do.mu.Lock()
	defer do.mu.Unlock()
	return do.ops.Pop(), false
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

func (ds *DynamicSourceCtl) Next() (*Request, bool) {
	return (*ds.value.Load()).Next()
}

// Deduplicator() keeps track of the previously run requests to avoid re-running them.
type Deduplicator struct {
	mu     sync.Mutex
	ctx    context.Context
	source Source
	mm     map[hash.Sig]*duplicateState
}

type duplicateState struct {
	res    *Result
	queued []*Request // duplicate requests waiting for the result.
}

func Deduplicate(ctx context.Context, source Source) Source {
	return &Deduplicator{
		ctx:    ctx,
		source: source,
		mm:     map[hash.Sig]*duplicateState{},
	}
}

func (d *Deduplicator) Next() (*Request, bool) {
	for {
		req, stop := d.source.Next()
		if req == nil {
			return req, stop
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
			return req, stop
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

func (do *defaultOpts) Next() (*Request, bool) {
	req, stop := do.source.Next()
	if req == nil {
		return nil, stop
	}
	req.ExecOpts.ExecFlags |= do.opts.ExecFlags
	req.ExecOpts.EnvFlags |= do.opts.EnvFlags
	req.ExecOpts.SandboxArg = do.opts.SandboxArg
	return req, stop
}
