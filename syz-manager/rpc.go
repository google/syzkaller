// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/stats"
	"github.com/google/syzkaller/pkg/vminfo"
	"github.com/google/syzkaller/prog"
)

type RPCServer struct {
	mgr     RPCManagerView
	cfg     *mgrconfig.Config
	target  *prog.Target
	server  *rpctype.RPCServer
	checker *vminfo.Checker
	port    int

	infoDone         bool
	checkDone        atomic.Bool
	checkFiles       []string
	checkFilesInfo   []flatrpc.FileInfo
	checkFeatureInfo []flatrpc.FeatureInfo
	checkProgs       []rpctype.ExecutionRequest
	checkResults     []rpctype.ExecutionResult
	needCheckResults int
	checkFailures    int
	enabledFeatures  flatrpc.Feature
	setupFeatures    flatrpc.Feature
	modules          []cover.KernelModule
	canonicalModules *cover.Canonicalizer
	execCoverFilter  map[uint32]uint32
	coverFilter      map[uint32]uint32

	mu      sync.Mutex
	runners sync.Map // Instead of map[string]*Runner.

	statExecs                 *stats.Val
	statExecRetries           *stats.Val
	statExecutorRestarts      *stats.Val
	statExecBufferTooSmall    *stats.Val
	statVMRestarts            *stats.Val
	statExchangeCalls         *stats.Val
	statExchangeProgs         *stats.Val
	statExchangeServerLatency *stats.Val
	statExchangeClientLatency *stats.Val
	statCoverFiltered         *stats.Val
}

type Runner struct {
	name        string
	injectLog   chan<- []byte
	injectStop  chan bool
	stopFuzzing atomic.Bool

	machineInfo []byte
	instModules *cover.CanonicalizerInstance

	// The mutex protects newMaxSignal, dropMaxSignal, and requests.
	mu            sync.Mutex
	newMaxSignal  signal.Signal
	dropMaxSignal signal.Signal
	nextRequestID int64
	requests      map[int64]Request
}

type Request struct {
	req        *queue.Request
	serialized []byte
	try        int
	procID     int
}

type BugFrames struct {
	memoryLeaks []string
	dataRaces   []string
}

// RPCManagerView restricts interface between RPCServer and Manager.
type RPCManagerView interface {
	currentBugFrames() BugFrames
	machineChecked(features flatrpc.Feature, enabledSyscalls map[*prog.Syscall]bool)
	getExecSource() queue.Source
}

func startRPCServer(mgr *Manager) (*RPCServer, error) {
	serv := &RPCServer{
		mgr:       mgr,
		cfg:       mgr.cfg,
		target:    mgr.target,
		checker:   vminfo.New(mgr.cfg),
		statExecs: mgr.statExecs,
		statExecRetries: stats.Create("exec retries",
			"Number of times a test program was restarted because the first run failed",
			stats.Rate{}, stats.Graph("executor")),
		statExecutorRestarts: stats.Create("executor restarts",
			"Number of times executor process was restarted", stats.Rate{}, stats.Graph("executor")),
		statExecBufferTooSmall: stats.Create("buffer too small",
			"Program serialization overflowed exec buffer", stats.NoGraph),
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
		statCoverFiltered: stats.Create("filtered coverage", "", stats.NoGraph),
	}
	s, err := rpctype.NewRPCServer(mgr.cfg.RPC, "Manager", serv)
	if err != nil {
		return nil, err
	}
	serv.checkFiles, serv.checkProgs = serv.checker.StartCheck()
	serv.needCheckResults = len(serv.checkProgs)
	log.Logf(0, "serving rpc on tcp://%v", s.Addr())
	serv.port = s.Addr().(*net.TCPAddr).Port
	serv.server = s
	go s.Serve()
	return serv, nil
}

func (serv *RPCServer) Connect(a *rpctype.ConnectArgs, r *rpctype.ConnectRes) error {
	log.Logf(1, "fuzzer %v connected", a.Name)
	checkRevisions(a, serv.cfg.Target)
	serv.statVMRestarts.Add(1)

	bugFrames := serv.mgr.currentBugFrames()
	r.MemoryLeakFrames = bugFrames.memoryLeaks
	r.DataRaceFrames = bugFrames.dataRaces

	serv.mu.Lock()
	defer serv.mu.Unlock()
	r.ReadFiles = serv.checker.RequiredFiles()
	if serv.checkDone.Load() {
		r.Features = serv.setupFeatures
	} else {
		r.ReadFiles = append(r.ReadFiles, serv.checkFiles...)
		r.ReadGlobs = serv.target.RequiredGlobs()
		r.Features = flatrpc.AllFeatures
	}
	return nil
}

func checkRevisions(a *rpctype.ConnectArgs, target *prog.Target) {
	if target.Arch != a.ExecutorArch {
		log.Fatalf("mismatching target/executor arches: %v vs %v", target.Arch, a.ExecutorArch)
	}
	if prog.GitRevision != a.GitRevision {
		log.Fatalf("mismatching manager/fuzzer git revisions: %v vs %v",
			prog.GitRevision, a.GitRevision)
	}
	if prog.GitRevision != a.ExecutorGitRevision {
		log.Fatalf("mismatching manager/executor git revisions: %v vs %v",
			prog.GitRevision, a.ExecutorGitRevision)
	}
	if target.Revision != a.SyzRevision {
		log.Fatalf("mismatching manager/fuzzer system call descriptions: %v vs %v",
			target.Revision, a.SyzRevision)
	}
	if target.Revision != a.ExecutorSyzRevision {
		log.Fatalf("mismatching manager/executor system call descriptions: %v vs %v",
			target.Revision, a.ExecutorSyzRevision)
	}
}

func (serv *RPCServer) Check(a *rpctype.CheckArgs, r *rpctype.CheckRes) error {
	serv.mu.Lock()
	defer serv.mu.Unlock()

	modules, machineInfo, err := serv.checker.MachineInfo(a.Files)
	if err != nil {
		log.Logf(0, "parsing of machine info failed: %v", err)
		if a.Error == "" {
			a.Error = err.Error()
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

	if !serv.infoDone {
		serv.infoDone = true
		serv.checkFeatureInfo = a.Features
		serv.checkFilesInfo = a.Files
		serv.modules = modules
		serv.target.UpdateGlobs(a.Globs)
		serv.canonicalModules = cover.NewCanonicalizer(modules, serv.cfg.Cover)
		var err error
		serv.execCoverFilter, serv.coverFilter, err = createCoverageFilter(serv.cfg, modules)
		if err != nil {
			log.Fatalf("failed to init coverage filter: %v", err)
		}
	}

	runner := serv.findRunner(a.Name)
	if runner == nil {
		// There may be a parallel shutdownInstance() call that removes the runner.
		return fmt.Errorf("unknown runner %s", a.Name)
	}

	runner.mu.Lock()
	defer runner.mu.Unlock()
	if runner.machineInfo != nil {
		return fmt.Errorf("duplicate connection from %s", a.Name)
	}
	runner.machineInfo = machineInfo
	runner.instModules = serv.canonicalModules.NewInstance(modules)
	instCoverFilter := runner.instModules.DecanonicalizeFilter(serv.execCoverFilter)
	r.CoverFilterBitmap = createCoverageBitmap(serv.cfg.SysTarget, instCoverFilter)
	return nil
}

func (serv *RPCServer) finishCheck() error {
	// Note: need to print disbled syscalls before failing due to an error.
	// This helps to debug "all system calls are disabled".
	enabledCalls, disabledCalls, features, checkErr := serv.checker.FinishCheck(
		serv.checkFilesInfo, serv.checkResults, serv.checkFeatureInfo)
	enabledCalls, transitivelyDisabled := serv.target.TransitivelyEnabledCalls(enabledCalls)
	buf := new(bytes.Buffer)
	if len(serv.cfg.EnabledSyscalls) != 0 || log.V(1) {
		if len(disabledCalls) != 0 {
			var lines []string
			for call, reason := range disabledCalls {
				lines = append(lines, fmt.Sprintf("%-44v: %v\n", call.Name, reason))
			}
			sort.Strings(lines)
			fmt.Fprintf(buf, "disabled the following syscalls:\n%s\n", strings.Join(lines, ""))
		}
		if len(transitivelyDisabled) != 0 {
			var lines []string
			for call, reason := range transitivelyDisabled {
				lines = append(lines, fmt.Sprintf("%-44v: %v\n", call.Name, reason))
			}
			sort.Strings(lines)
			fmt.Fprintf(buf, "transitively disabled the following syscalls"+
				" (missing resource [creating syscalls]):\n%s\n",
				strings.Join(lines, ""))
		}
	}
	hasFileErrors := false
	for _, file := range serv.checkFilesInfo {
		if file.Error == "" {
			continue
		}
		if !hasFileErrors {
			fmt.Fprintf(buf, "failed to read the following files in the VM:\n")
		}
		fmt.Fprintf(buf, "%-44v: %v\n", file.Name, file.Error)
		hasFileErrors = true
	}
	if hasFileErrors {
		fmt.Fprintf(buf, "\n")
	}
	var lines []string
	lines = append(lines, fmt.Sprintf("%-24v: %v/%v\n", "syscalls",
		len(enabledCalls), len(serv.cfg.Target.Syscalls)))
	for feat, info := range features {
		lines = append(lines, fmt.Sprintf("%-24v: %v\n",
			flatrpc.EnumNamesFeature[feat], info.Reason))
	}
	sort.Strings(lines)
	buf.WriteString(strings.Join(lines, ""))
	fmt.Fprintf(buf, "\n")
	log.Logf(0, "machine check:\n%s", buf.Bytes())
	if checkErr != nil {
		return checkErr
	}
	if len(enabledCalls) == 0 {
		return fmt.Errorf("all system calls are disabled")
	}
	serv.enabledFeatures = features.Enabled()
	serv.setupFeatures = features.NeedSetup()
	serv.mgr.machineChecked(serv.enabledFeatures, enabledCalls)
	return nil
}

func (serv *RPCServer) StartExecuting(a *rpctype.ExecutingRequest, r *int) error {
	serv.statExecs.Add(1)
	if a.Try != 0 {
		serv.statExecRetries.Add(1)
	}
	runner := serv.findRunner(a.Name)
	if runner == nil {
		return nil
	}
	runner.mu.Lock()
	req, ok := runner.requests[a.ID]
	if !ok {
		runner.mu.Unlock()
		return nil
	}
	// RPC handlers are invoked in separate goroutines, so start executing notifications
	// can outrun each other and completion notification.
	if req.try < a.Try {
		req.try = a.Try
		req.procID = a.ProcID
	}
	runner.requests[a.ID] = req
	runner.mu.Unlock()
	runner.logProgram(a.ProcID, req.serialized)
	return nil
}

func (serv *RPCServer) ExchangeInfo(a *rpctype.ExchangeInfoRequest, r *rpctype.ExchangeInfoReply) error {
	start := time.Now()
	runner := serv.findRunner(a.Name)
	if runner == nil {
		return nil
	}

	if !serv.checkDone.Load() {
		serv.mu.Lock()
		if !serv.checkDone.Load() {
			serv.checkResults = append(serv.checkResults, a.Results...)
			if len(serv.checkResults) < serv.needCheckResults {
				numRequests := min(len(serv.checkProgs), a.NeedProgs)
				r.Requests = serv.checkProgs[:numRequests]
				serv.checkProgs = serv.checkProgs[numRequests:]
			} else {
				if err := serv.finishCheck(); err != nil {
					log.Fatalf("check failed: %v", err)
				}
				serv.checkProgs = nil
				serv.checkResults = nil
				serv.checkFiles = nil
				serv.checkFilesInfo = nil
				serv.checkFeatureInfo = nil
				serv.checkDone.Store(true)
			}
		}
		serv.mu.Unlock()
		return nil
	}

	source := serv.mgr.getExecSource()
	if source == nil {
		// ExchangeInfo calls follow MachineCheck, so the fuzzer must have been initialized.
		panic("exchange info call with nil fuzzer")
	}

	// First query new inputs and only then post results.
	// It should foster a more even distribution of executions
	// across all VMs.
	for len(r.Requests) < a.NeedProgs {
		inp := source.Next()
		if req, ok := serv.newRequest(runner, inp); ok {
			r.Requests = append(r.Requests, req)
		} else {
			// It's bad if we systematically fail to serialize programs,
			// but so far we don't have a better handling than counting this.
			// This error is observed a lot on the seeded syz_mount_image calls.
			serv.statExecBufferTooSmall.Add(1)
			inp.Done(&queue.Result{Status: queue.ExecFailure})
		}
	}

	for _, result := range a.Results {
		serv.doneRequest(runner, result)
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

func (serv *RPCServer) findRunner(name string) *Runner {
	if val, _ := serv.runners.Load(name); val != nil {
		runner := val.(*Runner)
		if runner.stopFuzzing.Load() {
			return nil
		}
		return runner
	}
	// There might be a parallel shutdownInstance().
	// Ignore requests then.
	return nil
}

func (serv *RPCServer) createInstance(name string, maxSignal signal.Signal, injectLog chan<- []byte) {
	runner := &Runner{
		name:         name,
		requests:     make(map[int64]Request),
		newMaxSignal: maxSignal,
		injectLog:    injectLog,
		injectStop:   make(chan bool),
	}
	if _, loaded := serv.runners.LoadOrStore(name, runner); loaded {
		panic(fmt.Sprintf("duplicate instance %s", name))
	}
}

// stopInstance prevents further request exchange requests.
// To make RPCServer fully forget an instance, shutdownInstance() must be called.
func (serv *RPCServer) stopFuzzing(name string) {
	runner := serv.findRunner(name)
	if runner == nil {
		return
	}
	runner.stopFuzzing.Store(true)
}

func (serv *RPCServer) shutdownInstance(name string, crashed bool) []byte {
	runnerPtr, _ := serv.runners.LoadAndDelete(name)
	runner := runnerPtr.(*Runner)
	runner.mu.Lock()
	if runner.requests == nil {
		// We are supposed to invoke this code only once.
		panic("Runner.requests is already nil")
	}
	oldRequests := runner.requests
	runner.requests = nil
	runner.mu.Unlock()

	close(runner.injectStop)

	serv.mu.Lock()
	defer serv.mu.Unlock()
	if !serv.checkDone.Load() {
		log.Fatalf("VM is exited while checking is not done")
	}
	for _, req := range oldRequests {
		if crashed && req.try >= 0 {
			req.req.Done(&queue.Result{Status: queue.Crashed})
		} else {
			req.req.Done(&queue.Result{Status: queue.Restarted})
		}
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

func (serv *RPCServer) updateCoverFilter(newCover []uint32) {
	if len(newCover) == 0 || serv.coverFilter == nil {
		return
	}
	rg, _ := getReportGenerator(serv.cfg, serv.modules)
	if rg == nil {
		return
	}
	filtered := 0
	for _, pc := range newCover {
		if serv.coverFilter[uint32(rg.RestorePC(pc))] != 0 {
			filtered++
		}
	}
	serv.statCoverFiltered.Add(filtered)
}

func (serv *RPCServer) doneRequest(runner *Runner, resp rpctype.ExecutionResult) {
	info := &resp.Info
	if info.Freshness == 0 {
		serv.statExecutorRestarts.Add(1)
	}
	runner.mu.Lock()
	req, ok := runner.requests[resp.ID]
	if ok {
		delete(runner.requests, resp.ID)
	}
	runner.mu.Unlock()
	if !ok {
		// There may be a concurrent shutdownInstance() call.
		return
	}
	// RPC handlers are invoked in separate goroutines, so log the program here
	// if completion notification outrun start executing notification.
	if req.try < resp.Try {
		runner.logProgram(resp.ProcID, req.serialized)
	}
	if !serv.cfg.Cover {
		addFallbackSignal(req.req.Prog, info)
	}
	for i := 0; i < len(info.Calls); i++ {
		call := &info.Calls[i]
		call.Cover = runner.instModules.Canonicalize(call.Cover)
		call.Signal = runner.instModules.Canonicalize(call.Signal)
	}
	info.Extra.Cover = runner.instModules.Canonicalize(info.Extra.Cover)
	info.Extra.Signal = runner.instModules.Canonicalize(info.Extra.Signal)
	req.req.Done(&queue.Result{Info: info})
}

func (serv *RPCServer) newRequest(runner *Runner, req *queue.Request) (rpctype.ExecutionRequest, bool) {
	progData, err := req.Prog.SerializeForExec()
	if err != nil {
		return rpctype.ExecutionRequest{}, false
	}

	// logProgram() may race with Done(), so let's serialize the program right now.
	serialized := req.Prog.Serialize()

	var signalFilter signal.Signal
	if req.SignalFilter != nil {
		newRawSignal := runner.instModules.Decanonicalize(req.SignalFilter.ToRaw())
		// We don't care about specific priorities here.
		signalFilter = signal.FromRaw(newRawSignal, 0)
	}
	runner.mu.Lock()
	runner.nextRequestID++
	id := runner.nextRequestID
	if runner.requests != nil {
		runner.requests[id] = Request{
			req:        req,
			try:        -1,
			serialized: serialized,
		}
	}
	runner.mu.Unlock()
	return rpctype.ExecutionRequest{
		ID:               id,
		ProgData:         progData,
		ExecOpts:         serv.createExecOpts(req),
		NewSignal:        req.NeedSignal == queue.NewSignal,
		SignalFilter:     signalFilter,
		SignalFilterCall: req.SignalFilterCall,
		ResetState:       serv.cfg.Experimental.ResetAccState,
	}, true
}

func (serv *RPCServer) createExecOpts(req *queue.Request) ipc.ExecOpts {
	env := ipc.FeaturesToFlags(serv.enabledFeatures, nil)
	if *flagDebug {
		env |= ipc.FlagDebug
	}
	if serv.cfg.Cover {
		env |= ipc.FlagSignal
	}
	sandbox, err := ipc.SandboxToFlags(serv.cfg.Sandbox)
	if err != nil {
		panic(fmt.Sprintf("failed to parse sandbox: %v", err))
	}
	env |= sandbox

	exec := ipc.FlagThreaded
	if !serv.cfg.RawCover {
		exec |= ipc.FlagDedupCover
	}
	if serv.cfg.HasCovFilter() {
		exec |= ipc.FlagEnableCoverageFilter
	}
	if serv.cfg.Cover {
		if req.NeedSignal != queue.NoSignal {
			exec |= ipc.FlagCollectSignal
		}
		if req.NeedCover {
			exec |= ipc.FlagCollectCover
		}
		if req.NeedHints {
			exec |= ipc.FlagCollectComps
		}
	}
	return ipc.ExecOpts{
		EnvFlags:   env,
		ExecFlags:  exec,
		SandboxArg: serv.cfg.SandboxArg,
	}
}

func (runner *Runner) logProgram(procID int, serialized []byte) {
	buf := new(bytes.Buffer)
	fmt.Fprintf(buf, "executing program %v:\n%s\n", procID, serialized)
	select {
	case runner.injectLog <- buf.Bytes():
	case <-runner.injectStop:
	}
}

// addFallbackSignal computes simple fallback signal in cases we don't have real coverage signal.
// We use syscall number or-ed with returned errno value as signal.
// At least this gives us all combinations of syscall+errno.
func addFallbackSignal(p *prog.Prog, info *ipc.ProgInfo) {
	callInfos := make([]prog.CallInfo, len(info.Calls))
	for i, inf := range info.Calls {
		if inf.Flags&ipc.CallExecuted != 0 {
			callInfos[i].Flags |= prog.CallExecuted
		}
		if inf.Flags&ipc.CallFinished != 0 {
			callInfos[i].Flags |= prog.CallFinished
		}
		if inf.Flags&ipc.CallBlocked != 0 {
			callInfos[i].Flags |= prog.CallBlocked
		}
		callInfos[i].Errno = inf.Errno
	}
	p.FallbackSignal(callInfos)
	for i, inf := range callInfos {
		info.Calls[i].Signal = inf.Signal
	}
}
