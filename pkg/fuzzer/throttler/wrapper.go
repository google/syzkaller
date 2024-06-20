// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// The throttler package implements the functionality to rate limit the repetitive kernel crashes.

package throttler

import (
	"sort"
	"sync"
	"sync/atomic"

	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/stats"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys/targets"
)

type WrapperObject struct {
	base     queue.Source
	syscalls []perSyscall

	disableThreshold float64
	targetCrashRate  float64
	maxDisabled      int
	windowSize       int
	newPolicyExecs   int
	newPolicyCrashes int

	statRiskyExecs     *stats.Val
	statDeniedExecs    *stats.Val
	statImportantExecs *stats.Val
	statThrottledCalls *stats.Val

	mu sync.Mutex

	// Policy is "syscall" -> "execute it no more often than once in N executions".
	policy        map[int]int
	policyExecs   int
	policyCrashes int

	counter    int64 // number of executed programs.
	nextUnsafe int64
}

type perSyscall struct {
	crashed  atomic.Int64
	denied   atomic.Int64
	lastExec int64

	rate weightedAvg
}

func Wrapper(baseSource queue.Source, syscalls []*prog.Syscall) *WrapperObject {
	maxID := 0
	for _, call := range syscalls {
		maxID = max(maxID, call.ID)
	}

	ret := &WrapperObject{
		base: baseSource,

		// Start disabling syscalls after the risk exceeds 3%.
		disableThreshold: 0.03,
		// Disable no more than 10% of syscalls.
		maxDisabled: max(1, len(syscalls)/10),
		// Sample dangerous calls to the 0.1% crash risk.
		targetCrashRate: 0.0005,
		windowSize:      20,
		// Regenerate the policy every 10k requests or every 10 new crashes.
		newPolicyExecs:   10000,
		newPolicyCrashes: 10,

		syscalls: make([]perSyscall, maxID+1),
		statDeniedExecs: stats.Create("denied execs", "Risky calls denied from execution",
			stats.Rate{}, stats.StackedGraph("throttle")),
		statRiskyExecs: stats.Create("risky execs", "Risky calls executed (exploration)",
			stats.Rate{}, stats.StackedGraph("throttle")),
		statImportantExecs: stats.Create("important risky execs", "Risky calls in important execs",
			stats.Rate{}, stats.StackedGraph("throttle")),
	}
	ret.statThrottledCalls = stats.Create("throttled syscalls",
		"The number of syscalls blocked by the current policy",
		stats.Graph("throttled syscalls"),
		func() int {
			ret.mu.Lock()
			defer ret.mu.Unlock()
			return len(ret.policy)
		})
	return ret
}

func (w *WrapperObject) Next() *queue.Request {
	req := w.base.Next()
	if req == nil {
		return nil
	}
	if req.Prog == nil {
		// Ignore binaries executions.
		return req
	}

	w.updatePolicy()

	w.mu.Lock()
	defer w.mu.Unlock()

	w.policyExecs++
	w.counter++

	for _, call := range req.Prog.Calls {
		id := call.Meta.ID
		onceIn := int64(w.policy[id])
		if onceIn == 0 {
			continue
		}

		req.Risky = true
		if req.Important {
			// Don't patch important requests.
			w.statImportantExecs.Add(1)
			continue
		}

		mayRisk := w.nextUnsafe < w.counter

		// Demand that:
		// 1. In general, we execute an unsafe program no more often than once per the window.
		// 2. The individual rate limits are obeyed.

		info := &w.syscalls[id]
		if mayRisk && (info.lastExec == w.counter || w.counter-info.lastExec > onceIn) {
			w.nextUnsafe = max(w.nextUnsafe, w.counter+int64(w.windowSize+1))
			info.lastExec = w.counter
			w.statRiskyExecs.Add(1)
		} else {
			call.Props.Skip = true
			w.syscalls[id].denied.Add(1)
			w.statDeniedExecs.Add(1)
		}
	}
	return req
}

func (w *WrapperObject) updatePolicy() {
	w.mu.Lock()
	update := false
	if w.policyCrashes > w.newPolicyCrashes {
		update = true
		w.policyCrashes = 0
	}
	if w.policyExecs > w.newPolicyExecs {
		update = true
		w.policyExecs = 0
	}
	w.mu.Unlock()
	if update {
		policy := w.generatePolicy()
		w.mu.Lock()
		w.policy = policy
		w.mu.Unlock()
	}
}

func (w *WrapperObject) generatePolicy() map[int]int {
	type record struct {
		id   int
		prob float64
	}
	rates := []record{}
	for id := range w.syscalls {
		info := &w.syscalls[id]
		crashed := float64(info.crashed.Load())
		if crashed < 5 {
			// We consider everything below as still too noisy.
			continue
		}
		// Only consider the syscalls that cause a high enough crash rate.
		prob := info.rate.Get()
		if prob > w.disableThreshold {
			rates = append(rates, record{id, prob})
		}
	}
	sort.Slice(rates, func(i, j int) bool {
		return rates[i].prob > rates[j].prob
	})

	newPolicy := map[int]int{}
	for _, obj := range rates[:min(len(rates), w.maxDisabled)] {
		newPolicy[obj.id] = max(w.windowSize, int(obj.prob/w.targetCrashRate))
	}
	return newPolicy
}

func (w *WrapperObject) recordCalls(calls []*prog.Syscall, crashed bool) {
	if len(calls) == 0 {
		return
	}

	w.mu.Lock()
	policy := w.policy
	if crashed {
		w.policyCrashes++
	}
	w.mu.Unlock()

	onlyDisabled := false
	if crashed {
		// If we crashed and there have been already executed disabled calls,
		// only update the information for them.
		known := 0
		for _, call := range calls {
			if policy[call.ID] > 0 {
				onlyDisabled = true
				known++
			}
		}
	}
	for _, call := range calls {
		if onlyDisabled && policy[call.ID] == 0 {
			continue
		}
		info := &w.syscalls[call.ID]
		if crashed {
			info.rate.Save(1.0)
			info.crashed.Add(1)
		} else {
			info.rate.Save(0)
		}
	}
}

func (w *WrapperObject) InstanceMonitor() InstanceMonitor {
	return &callTracker{
		window: make([][]*prog.Syscall, w.windowSize),
		record: w.recordCalls,
	}
}

type CallInfo struct {
	Crashed   int64
	Denied    int64
	CrashRate float64
	Throttled bool
}

func (w *WrapperObject) Info(call *prog.Syscall) CallInfo {
	w.mu.Lock()
	defer w.mu.Unlock()
	data := &w.syscalls[call.ID]
	return CallInfo{
		Crashed:   data.crashed.Load(),
		Denied:    data.denied.Load(),
		CrashRate: data.rate.Get(),
		Throttled: w.policy[call.ID] > 0,
	}
}

type InstanceMonitor interface {
	// Record() is assumed to get called once an instance starts executing a program.
	Record(req *queue.Request)
	// Shutdown() is expected to be called as soon as possible after the VM has crashed.
	Shutdown(crashed bool)
}

// callTracker is a sliding window of the last executed syscalls.
// Due to delayed crashed, we only consider a program to be unharmful after
// the whole window has passed afterwards.
type callTracker struct {
	mu     sync.Mutex
	pos    int
	window [][]*prog.Syscall
	record func(calls []*prog.Syscall, crashed bool)
}

func (t *callTracker) Record(req *queue.Request) {
	if req.Prog == nil {
		return
	}
	calls := make([]*prog.Syscall, 0, len(req.Prog.Calls))
	for _, info := range req.Prog.Calls {
		if !info.Props.Skip {
			calls = append(calls, info.Meta)
		}
	}
	var prev []*prog.Syscall
	t.mu.Lock()
	prev = t.window[t.pos]
	t.window[t.pos] = calls
	t.pos = (t.pos + 1) % len(t.window)
	t.mu.Unlock()

	t.record(prev, false)
}

func (t *callTracker) Shutdown(crashed bool) {
	if !crashed {
		return
	}
	m := map[*prog.Syscall]struct{}{}
	for _, calls := range t.window {
		for _, call := range calls {
			m[call] = struct{}{}
		}
	}
	var merged []*prog.Syscall
	for call := range m {
		merged = append(merged, call)
	}
	t.record(merged, true)
}

// Until we need to configure it, let it stay const.
const weightedAvgStep = 0.005

type weightedAvg struct {
	mu    sync.Mutex
	total int64
	val   float64
}

func (wa *weightedAvg) Save(val float64) {
	wa.mu.Lock()
	defer wa.mu.Unlock()
	wa.total++
	step := max(weightedAvgStep, 1.0/float64(wa.total))
	wa.val += (val - wa.val) * step
}

func (wa *weightedAvg) Get() float64 {
	wa.mu.Lock()
	defer wa.mu.Unlock()
	return wa.val
}
