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

	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/stats"
	"github.com/google/syzkaller/prog"
)

type Request struct {
	Prog       *prog.Prog
	NeedSignal SignalType
	NeedCover  bool
	NeedHints  bool
	ExecOpts   *ipc.ExecOpts

	// If specified, the resulting signal for call SignalFilterCall
	// will include subset of it even if it's not new.
	SignalFilter     signal.Signal
	SignalFilterCall int

	ReturnError  bool
	ReturnOutput bool

	// This stat will be incremented on request completion.
	Stat *stats.Val

	// The callback will be called on request completion in the LIFO order.
	// If it returns false, all further processing will be stopped.
	// It allows wrappers to intercept Done() requests.
	callback DoneCallback

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

func (r *Request) hash() hash.Sig {
	buf := new(bytes.Buffer)
	if r.ExecOpts != nil {
		if err := gob.NewEncoder(buf).Encode(r.ExecOpts); err != nil {
			panic(err)
		}
	}
	return hash.Hash(
		[]byte(fmt.Sprint(r.NeedSignal)),
		[]byte(fmt.Sprint(r.NeedCover)),
		[]byte(fmt.Sprint(r.NeedHints)),
		r.Prog.Serialize(),
		buf.Bytes(),
	)
}

func (r *Request) initChannel() {
	r.mu.Lock()
	if r.done == nil {
		r.done = make(chan struct{})
	}
	r.mu.Unlock()
}

type SignalType int

const (
	NoSignal  SignalType = iota // we don't need any signal
	NewSignal                   // we need the newly seen signal
	AllSignal                   // we need all signal
)

type Result struct {
	Info   *ipc.ProgInfo
	Output []byte
	Status Status
	Error  string // More details in case of ExecFailure.
}

func (r *Result) clone() *Result {
	ret := *r
	if ret.Info != nil {
		ret.Info = ret.Info.Clone()
	}
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
	Next() *Request
}

// PlainQueue is a straighforward thread-safe Request queue implementation.
type PlainQueue struct {
	stat  *stats.Val
	mu    sync.Mutex
	queue []*Request
	pos   int
}

func Plain() *PlainQueue {
	return &PlainQueue{}
}

func PlainWithStat(val *stats.Val) *PlainQueue {
	return &PlainQueue{stat: val}
}

func (pq *PlainQueue) Len() int {
	pq.mu.Lock()
	defer pq.mu.Unlock()
	return len(pq.queue) - pq.pos
}

func (pq *PlainQueue) Submit(req *Request) {
	if pq.stat != nil {
		pq.stat.Add(1)
	}
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
	if pq.stat != nil {
		pq.stat.Add(-1)
	}
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

type PriorityQueue struct {
	mu       *sync.Mutex
	ops      *priorityQueueOps[*Request]
	currPrio priority
}

func Priority() *PriorityQueue {
	return &PriorityQueue{
		mu:       &sync.Mutex{},
		ops:      &priorityQueueOps[*Request]{},
		currPrio: priority{0},
	}
}

// AppendQueue() can be used to form nested queues.
// That is, if
// q1 := pq.AppendQueue()
// q2 := pq.AppendQueue()
// All elements added via q2.Submit() will always have a *lower* priority
// than all elements added via q1.Submit().
func (pq *PriorityQueue) AppendQueue() *PriorityQueue {
	pq.mu.Lock()
	defer pq.mu.Unlock()
	pq.currPrio = pq.currPrio.next()
	nextPrio := append(priority{}, pq.currPrio...)
	return &PriorityQueue{
		// We use the same queue, therefore the same mutex.
		mu:       pq.mu,
		ops:      pq.ops,
		currPrio: append(nextPrio, 0),
	}
}

// Each subsequent element added via Submit() will have a lower priority.
func (pq *PriorityQueue) Submit(req *Request) {
	pq.mu.Lock()
	defer pq.mu.Unlock()
	pq.currPrio = pq.currPrio.next()
	pq.ops.Push(req, pq.currPrio)
}

func (pq *PriorityQueue) Next() *Request {
	pq.mu.Lock()
	defer pq.mu.Unlock()
	return pq.ops.Pop()
}

type DynamicSource struct {
	value atomic.Pointer[wrapSource]
}

type wrapSource struct {
	source Source
}

func (ds *DynamicSource) Store(source Source) {
	ds.value.Store(&wrapSource{source})
}

func (ds *DynamicSource) Next() *Request {
	val := ds.value.Load()
	if val == nil || val.source == nil {
		return nil
	}
	return val.source.Next()
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
