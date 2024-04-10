// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/fuzzer"
	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/stats"
	"github.com/google/syzkaller/prog"
)

type RPCServer struct {
	mgr                   RPCManagerView
	cfg                   *mgrconfig.Config
	server                *rpctype.RPCServer
	modules               []host.KernelModule
	port                  int
	targetEnabledSyscalls map[*prog.Syscall]bool
	coverFilter           map[uint32]uint32
	canonicalModules      *cover.Canonicalizer

	mu            sync.Mutex
	runners       sync.Map // Instead of map[string]*Runner.
	checkFeatures *host.Features
	requests      atomic.Pointer[requestDistributor]

	checkFailures int

	statVMRestarts            *stats.Val
	statExchangeCalls         *stats.Val
	statExchangeProgs         *stats.Val
	statExchangeServerLatency *stats.Val
	statExchangeClientLatency *stats.Val
	statCorpusCoverFiltered   *stats.Val
	statReusedSafeInputs      *stats.Val
	statReusedUnsafeInputs    *stats.Val
}

type Runner struct {
	name       string
	started    time.Time
	bootTime   time.Duration
	lastUnsafe time.Time

	machineInfo []byte
	instModules *cover.CanonicalizerInstance

	// The mutex protects newMaxSignal, dropMaxSignal, and requests.
	mu            sync.Mutex
	newMaxSignal  signal.Signal
	dropMaxSignal signal.Signal
	nextRequestID atomic.Int64
	requests      map[int64]*fuzzer.Request
}

type BugFrames struct {
	memoryLeaks []string
	dataRaces   []string
}

// RPCManagerView restricts interface between RPCServer and Manager.
type RPCManagerView interface {
	fuzzerConnect([]host.KernelModule) (BugFrames, map[uint32]uint32, map[uint32]uint32, error)
	machineChecked(features *host.Features, globFiles map[string][]string, enabledSyscalls map[*prog.Syscall]bool)
	getFuzzer() *fuzzer.Fuzzer
	avgBootTime() time.Duration
}

func startRPCServer(mgr *Manager) (*RPCServer, error) {
	serv := &RPCServer{
		mgr: mgr,
		cfg: mgr.cfg,

		statVMRestarts: stats.Create("vm restarts", "Total number of VM starts",
			stats.Rate{}, stats.NoGraph),
		statExchangeCalls: stats.Create("exchange calls", "Number of RPC Exchange calls",
			stats.Rate{}),
		statExchangeProgs: stats.Create("exchange progs", "Test programs exchanged per RPC call",
			stats.Distribution{}),
		statExchangeServerLatency: stats.Create("exchange manager latency",
			"Manager RPC Exchange call latency (us)", stats.Distribution{}),
		statExchangeClientLatency: stats.Create("exchange fuzzer latency",
			"End-to-end fuzzer RPC Exchange call latency (us)", stats.Distribution{}),
		statCorpusCoverFiltered: stats.Create("filtered coverage", "", stats.NoGraph),
		statReusedSafeInputs: stats.Create("reused safe inputs", "Inputs from restarted VMs that were sent to other VMs",
			stats.Rate{}, stats.StackedGraph("reused inputs")),
		statReusedUnsafeInputs: stats.Create("reused unsafe inputs", "Inputs from crashed VMs that were sent to other VMs",
			stats.Rate{}, stats.StackedGraph("reused inputs")),
	}
	s, err := rpctype.NewRPCServer(mgr.cfg.RPC, "Manager", serv, mgr.netCompression)
	if err != nil {
		return nil, err
	}
	log.Logf(0, "serving rpc on tcp://%v", s.Addr())
	serv.port = s.Addr().(*net.TCPAddr).Port
	serv.server = s
	go s.Serve()
	return serv, nil
}

func (serv *RPCServer) Connect(a *rpctype.ConnectArgs, r *rpctype.ConnectRes) error {
	log.Logf(1, "fuzzer %v connected", a.Name)
	serv.statVMRestarts.Add(1)

	serv.mu.Lock()
	if serv.canonicalModules == nil {
		serv.canonicalModules = cover.NewCanonicalizer(a.Modules, serv.cfg.Cover)
		serv.modules = a.Modules
	}
	serv.mu.Unlock()

	bugFrames, coverFilter, execCoverFilter, err := serv.mgr.fuzzerConnect(serv.modules)
	if err != nil {
		return err
	}

	serv.mu.Lock()
	defer serv.mu.Unlock()

	serv.coverFilter = coverFilter

	runner := &Runner{
		name: a.Name,
		// It makes little sense to track the boot time of each individual VM,
		// so let's just use the average value.
		bootTime:    serv.mgr.avgBootTime(),
		started:     time.Now(),
		machineInfo: a.MachineInfo,
		instModules: serv.canonicalModules.NewInstance(a.Modules),
		requests:    make(map[int64]*fuzzer.Request),
	}
	if _, loaded := serv.runners.LoadOrStore(a.Name, runner); loaded {
		return fmt.Errorf("duplicate connection from %s", a.Name)
	}
	r.MemoryLeakFrames = bugFrames.memoryLeaks
	r.DataRaceFrames = bugFrames.dataRaces

	instCoverFilter := runner.instModules.DecanonicalizeFilter(execCoverFilter)
	r.CoverFilterBitmap = createCoverageBitmap(serv.cfg.SysTarget, instCoverFilter)
	r.EnabledCalls = serv.cfg.Syscalls
	r.GitRevision = prog.GitRevision
	r.TargetRevision = serv.cfg.Target.Revision
	r.Features = serv.checkFeatures

	if fuzzer := serv.mgr.getFuzzer(); fuzzer != nil {
		// A Fuzzer object is created after the first Check() call.
		// If there was none, there would be no collected max signal either.
		runner.newMaxSignal = fuzzer.Cover.CopyMaxSignal()
	}
	return nil
}

func (serv *RPCServer) Check(a *rpctype.CheckArgs, r *int) error {
	serv.mu.Lock()
	defer serv.mu.Unlock()

	if serv.checkFeatures != nil {
		return nil // another VM has already made the check
	}
	// Note: need to print disbled syscalls before failing due to an error.
	// This helps to debug "all system calls are disabled".
	if len(serv.cfg.EnabledSyscalls) != 0 && len(a.DisabledCalls[serv.cfg.Sandbox]) != 0 {
		disabled := make(map[string]string)
		for _, dc := range a.DisabledCalls[serv.cfg.Sandbox] {
			disabled[serv.cfg.Target.Syscalls[dc.ID].Name] = dc.Reason
		}
		for _, id := range serv.cfg.Syscalls {
			name := serv.cfg.Target.Syscalls[id].Name
			if reason := disabled[name]; reason != "" {
				log.Logf(0, "disabling %v: %v", name, reason)
			}
		}
	}
	if a.Error != "" {
		log.Logf(0, "machine check failed: %v", a.Error)
		serv.checkFailures++
		if serv.checkFailures == 10 {
			log.Fatalf("machine check failing")
		}
		return fmt.Errorf("machine check failed: %v", a.Error)
	}
	serv.targetEnabledSyscalls = make(map[*prog.Syscall]bool)
	for _, call := range a.EnabledCalls[serv.cfg.Sandbox] {
		serv.targetEnabledSyscalls[serv.cfg.Target.Syscalls[call]] = true
	}
	log.Logf(0, "machine check:")
	log.Logf(0, "%-24v: %v/%v", "syscalls", len(serv.targetEnabledSyscalls), len(serv.cfg.Target.Syscalls))
	for _, feat := range a.Features.Supported() {
		log.Logf(0, "%-24v: %v", feat.Name, feat.Reason)
	}
	serv.mgr.machineChecked(a.Features, a.GlobFiles, serv.targetEnabledSyscalls)
	serv.checkFeatures = a.Features
	return nil
}

func (serv *RPCServer) ExchangeInfo(a *rpctype.ExchangeInfoRequest, r *rpctype.ExchangeInfoReply) error {
	start := time.Now()
	var runner *Runner
	if val, _ := serv.runners.Load(a.Name); val != nil {
		runner = val.(*Runner)
	} else {
		// There might be a parallel shutdownInstance().
		// Ignore the request then.
		return nil
	}

	fuzzer := serv.mgr.getFuzzer()
	if fuzzer == nil {
		// ExchangeInfo calls follow MachineCheck, so the fuzzer must have been initialized.
		panic("exchange info call with nil fuzzer")
	}

	// Lazily initialize the request distributor.
	requests := serv.requests.Load()
	if requests == nil {
		requests = newRequestDistributor(fuzzer, serv.statReusedSafeInputs, serv.statReusedUnsafeInputs)
		serv.requests.CompareAndSwap(nil, requests)
	}

	// First query new inputs and only then post results.
	// It should foster a more even distribution of executions
	// across all VMs.
	for i := 0; i < a.NeedProgs; i++ {
		req := requests.Next(runner)
		r.Requests = append(r.Requests, runner.newRequest(req))
	}
	for _, result := range a.Results {
		req, res := runner.convertResult(result)
		if req == nil {
			continue
		}
		requests.Done(req, res)
	}

	stats.Import(a.StatsDelta)

	runner.mu.Lock()
	// Let's transfer new max signal in portions.

	const transferMaxSignal = 500000
	newSignal := runner.newMaxSignal.Split(transferMaxSignal)
	dropSignal := runner.dropMaxSignal.Split(transferMaxSignal)
	runner.mu.Unlock()

	r.NewMaxSignal = runner.instModules.Decanonicalize(newSignal.ToRaw())
	r.DropMaxSignal = runner.instModules.Decanonicalize(dropSignal.ToRaw())

	log.Logf(2, "exchange with %s: %d done, %d new requests, %d new max signal, %d drop signal",
		a.Name, len(a.Results), len(r.Requests), len(r.NewMaxSignal), len(r.DropMaxSignal))

	serv.statExchangeCalls.Add(1)
	serv.statExchangeProgs.Add(a.NeedProgs)
	serv.statExchangeClientLatency.Add(int(a.Latency.Microseconds()))
	serv.statExchangeServerLatency.Add(int(time.Since(start).Microseconds()))
	return nil
}

func (serv *RPCServer) updateFilteredCover(pcs []uint32) error {
	if len(pcs) == 0 || serv.coverFilter == nil {
		return nil
	}
	// Note: ReportGenerator is already initialized if coverFilter is enabled.
	rg, err := getReportGenerator(serv.cfg, serv.modules)
	if err != nil {
		return err
	}
	filtered := 0
	for _, pc := range pcs {
		if serv.coverFilter[uint32(rg.RestorePC(pc))] != 0 {
			filtered++
		}
	}
	serv.statCorpusCoverFiltered.Add(filtered)
	return nil
}

func (serv *RPCServer) shutdownInstance(name string, crashed bool) []byte {
	var runner *Runner
	if val, _ := serv.runners.LoadAndDelete(name); val != nil {
		runner = val.(*Runner)
	} else {
		return nil
	}

	runner.mu.Lock()
	if runner.requests == nil {
		// We are supposed to invoke this code only once.
		panic("Runner.requests is already nil")
	}
	oldRequests := runner.requests
	runner.requests = nil
	runner.mu.Unlock()

	for _, req := range oldRequests {
		serv.requests.Load().Save(req, !crashed)
	}
	return runner.machineInfo
}

func (serv *RPCServer) distributeSignalDelta(plus, minus signal.Signal) {
	serv.runners.Range(func(key, value any) bool {
		runner := value.(*Runner)
		runner.mu.Lock()
		defer runner.mu.Unlock()
		runner.newMaxSignal.Merge(plus)
		runner.dropMaxSignal.Merge(minus)
		return true
	})
}

func (runner *Runner) convertResult(resp rpctype.ExecutionResult) (*fuzzer.Request, *fuzzer.Result) {
	runner.mu.Lock()
	req, ok := runner.requests[resp.ID]
	if ok {
		delete(runner.requests, resp.ID)
	}
	runner.mu.Unlock()
	if !ok {
		// There may be a concurrent shutdownInstance() call.
		return nil, nil
	}
	info := &resp.Info
	for i := 0; i < len(info.Calls); i++ {
		call := &info.Calls[i]
		call.Cover = runner.instModules.Canonicalize(call.Cover)
		call.Signal = runner.instModules.Canonicalize(call.Signal)
	}
	info.Extra.Cover = runner.instModules.Canonicalize(info.Extra.Cover)
	info.Extra.Signal = runner.instModules.Canonicalize(info.Extra.Signal)
	return req, &fuzzer.Result{Info: info}
}

func (runner *Runner) newRequest(req *fuzzer.Request) rpctype.ExecutionRequest {
	var signalFilter signal.Signal
	if req.SignalFilter != nil {
		newRawSignal := runner.instModules.Decanonicalize(req.SignalFilter.ToRaw())
		// We don't care about specific priorities here.
		signalFilter = signal.FromRaw(newRawSignal, 0)
	}
	id := runner.nextRequestID.Add(1)
	runner.mu.Lock()
	if runner.requests != nil {
		runner.requests[id] = req
	}
	runner.mu.Unlock()
	return rpctype.ExecutionRequest{
		ID:           id,
		ProgData:     req.Prog.Serialize(),
		NeedCover:    req.NeedCover,
		NeedSignal:   req.NeedSignal,
		SignalFilter: signalFilter,
		NeedHints:    req.NeedHints,
	}
}

type requestDistributor struct {
	fuzzer           *fuzzer.Fuzzer
	statReusedSafe   *stats.Val
	statReusedUnsafe *stats.Val
	// These are the inputs that were sent to VMs, but were not executed.
	safeInputs   *queue[fuzzer.Request] // from stopped VMs
	unsafeInputs *queue[fuzzer.Request] // from crashed VMs

	// We don't want to rescue unsafe inputs twice.
	rescuedUnsafe sync.Map
}

func newRequestDistributor(fuzzerObj *fuzzer.Fuzzer, statReusedSafe, statReusedUnsafe *stats.Val) *requestDistributor {
	return &requestDistributor{
		fuzzer:           fuzzerObj,
		safeInputs:       newQueue[fuzzer.Request](1000),
		unsafeInputs:     newQueue[fuzzer.Request](1000),
		statReusedSafe:   statReusedSafe,
		statReusedUnsafe: statReusedUnsafe,
	}
}

func (rd *requestDistributor) Next(runner *Runner) *fuzzer.Request {
	if rd.mayUnsafe(runner) {
		req := rd.unsafeInputs.Fetch()
		if req != nil {
			rd.statReusedUnsafe.Add(1)
			rd.rescuedUnsafe.Store(req, true)
			return req
		}
	}
	// Next() must be as fast as possible, so let's avoid contention.
	req := rd.safeInputs.TryFetch()
	if req != nil {
		rd.statReusedSafe.Add(1)
		return req
	}
	return rd.fuzzer.NextInput()
}

func (rd *requestDistributor) mayUnsafe(runner *Runner) bool {
	if !runner.mu.TryLock() {
		return false
	}
	defer runner.mu.Unlock()
	uptime := time.Since(runner.started)

	// We don't want to risk crashing freshly booted VMs.
	// So let's limit the time wasted on VM re-creation to 10% of the total uptime.
	if (runner.bootTime+uptime).Seconds()*0.1 < runner.bootTime.Seconds() {
		return false
	}

	const unsafeOnceIn = time.Minute
	if time.Since(runner.lastUnsafe) < unsafeOnceIn {
		return false
	}

	runner.lastUnsafe = time.Now()
	return true
}

func (rd *requestDistributor) Save(req *fuzzer.Request, safe bool) {
	_, twice := rd.rescuedUnsafe.LoadAndDelete(req)
	if !req.Important() || twice {
		rd.revoke(req)
		return
	}
	if safe {
		rd.safeInputs.Add(req, rd.revoke)
	} else {
		rd.unsafeInputs.Add(req, rd.revoke)
	}
}

func (rd *requestDistributor) Done(req *fuzzer.Request, res *fuzzer.Result) {
	// No reason to create goroutines here.
	rd.revokeSync(req, res)
}

func (rd *requestDistributor) revoke(req *fuzzer.Request) {
	go rd.revokeSync(req, &fuzzer.Result{Stop: true})
}

func (rd *requestDistributor) revokeSync(req *fuzzer.Request, res *fuzzer.Result) {
	rd.rescuedUnsafe.Delete(req)
	rd.fuzzer.Done(req, res)
}

type queue[T any] struct {
	mu    sync.Mutex
	elems []*T
	start int
	end   int
	full  bool
}

func newQueue[T any](limit int) *queue[T] {
	return &queue[T]{
		elems: make([]*T, limit),
	}
}

func (q *queue[T]) Add(elem *T, revoke func(*T)) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.elems[q.end] != nil {
		revoke(q.elems[q.end])
	}
	q.elems[q.end] = elem
	if q.full {
		q.start = (q.start + 1) % len(q.elems)
	}
	q.end = (q.end + 1) % len(q.elems)
	if q.start == q.end {
		q.full = true
	}
}

func (q *queue[T]) Fetch() *T {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.fetchUnlocked()
}

func (q *queue[T]) TryFetch() *T {
	if !q.mu.TryLock() {
		return nil
	}
	defer q.mu.Unlock()
	return q.fetchUnlocked()
}

func (q *queue[T]) fetchUnlocked() *T {
	ret := q.elems[q.start]
	if ret == nil {
		return nil
	}
	q.elems[q.start] = nil
	q.start = (q.start + 1) % len(q.elems)
	q.full = false
	return ret
}
