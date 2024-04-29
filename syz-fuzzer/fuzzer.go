// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/ipc/ipcconfig"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/sys/targets"
)

type FuzzerTool struct {
	name     string
	executor string
	gate     *ipc.Gate
	manager  *rpctype.RPCClient
	// TODO: repair triagedCandidates logic, it's broken now.
	triagedCandidates uint32
	timeouts          targets.Timeouts

	noExecRequests atomic.Uint64
	noExecDuration atomic.Uint64

	requests  chan rpctype.ExecutionRequest
	results   chan executionResult
	signalMu  sync.RWMutex
	maxSignal signal.Signal
}

// executionResult offloads some computations from the proc loop
// to the communication thread.
type executionResult struct {
	rpctype.ExecutionRequest
	procID int
	try    int
	info   *ipc.ProgInfo
}

// Gate size controls how deep in the log the last executed by every proc
// program may be. The intent is to make sure that, given the output log,
// we always understand what was happening.
// Judging by the logs collected on syzbot, 32 should be a reasonable figure.
// It coincides with prog.MaxPids.
const gateSize = prog.MaxPids

// TODO: split into smaller methods.
// nolint: funlen, gocyclo
func main() {
	debug.SetGCPercent(50)

	var (
		flagName           = flag.String("name", "test", "unique name for manager")
		flagOS             = flag.String("os", runtime.GOOS, "target OS")
		flagArch           = flag.String("arch", runtime.GOARCH, "target arch")
		flagManager        = flag.String("manager", "", "manager rpc address")
		flagProcs          = flag.Int("procs", 1, "number of parallel test processes")
		flagTest           = flag.Bool("test", false, "enable image testing mode")      // used by syz-ci
		flagRunTest        = flag.Bool("runtest", false, "enable program testing mode") // used by pkg/runtest
		flagPprofPort      = flag.Int("pprof_port", 0, "HTTP port for the pprof endpoint (disabled if 0)")
		flagNetCompression = flag.Bool("net_compression", false, "use network compression for RPC calls")

		// Experimental flags.
		flagResetAccState = flag.Bool("reset_acc_state", false, "restarts executor before most executions")
	)
	defer tool.Init()()
	log.Logf(0, "fuzzer started")

	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		log.SyzFatalf("%v", err)
	}

	config, execOpts, err := ipcconfig.Default(target)
	if err != nil {
		log.SyzFatalf("failed to create default ipc config: %v", err)
	}
	timeouts := config.Timeouts
	sandbox := ipc.FlagsToSandbox(execOpts.EnvFlags)
	executor := config.Executor
	shutdown := make(chan struct{})
	osutil.HandleInterrupts(shutdown)
	go func() {
		// Handles graceful preemption on GCE.
		<-shutdown
		log.Logf(0, "SYZ-FUZZER: PREEMPTED")
		os.Exit(1)
	}()

	if *flagPprofPort != 0 {
		setupPprofHandler(*flagPprofPort)
	}

	checkArgs := &checkArgs{
		target:         target,
		sandbox:        sandbox,
		ipcConfig:      config,
		ipcExecOpts:    execOpts,
		gitRevision:    prog.GitRevision,
		targetRevision: target.Revision,
	}
	if *flagTest {
		testImage(*flagManager, checkArgs)
		return
	}

	log.Logf(0, "dialing manager at %v", *flagManager)
	manager, err := rpctype.NewRPCClient(*flagManager, timeouts.Scale, false, *flagNetCompression)
	if err != nil {
		log.SyzFatalf("failed to create an RPC client: %v ", err)
	}

	log.Logf(1, "connecting to manager...")
	a := &rpctype.ConnectArgs{
		Name:        *flagName,
		GitRevision: prog.GitRevision,
		SyzRevision: target.Revision,
	}
	a.ExecutorArch, a.ExecutorSyzRevision, a.ExecutorGitRevision, err = executorVersion(executor)
	if err != nil {
		log.SyzFatalf("failed to run executor version: %v ", err)
	}
	r := &rpctype.ConnectRes{}
	if err := manager.Call("Manager.Connect", a, r); err != nil {
		log.SyzFatalf("failed to call Manager.Connect(): %v ", err)
	}
	featureFlags, err := csource.ParseFeaturesFlags("none", "none", true)
	if err != nil {
		log.SyzFatalf("%v", err)
	}
	var checkReq *rpctype.CheckArgs
	if r.Features == nil {
		checkArgs.enabledCalls = r.EnabledCalls
		checkArgs.allSandboxes = r.AllSandboxes
		checkArgs.featureFlags = featureFlags
		checkReq, err = checkMachine(checkArgs)
		if err != nil {
			if checkReq == nil {
				checkReq = new(rpctype.CheckArgs)
			}
			checkReq.Error = err.Error()
		}
		r.Features = checkReq.Features
	} else {
		if err = host.Setup(target, r.Features, featureFlags, executor); err != nil {
			log.SyzFatalf("%v", err)
		}
		checkReq = new(rpctype.CheckArgs)
	}

	for _, feat := range r.Features.Supported() {
		log.Logf(0, "%v: %v", feat.Name, feat.Reason)
	}

	inputsCount := *flagProcs * 2
	fuzzerTool := &FuzzerTool{
		name:     *flagName,
		manager:  manager,
		timeouts: timeouts,

		requests: make(chan rpctype.ExecutionRequest, inputsCount),
		results:  make(chan executionResult, inputsCount),
	}
	gateCb := fuzzerTool.useBugFrames(r.Features, r.MemoryLeakFrames, r.DataRaceFrames)
	fuzzerTool.gate = ipc.NewGate(gateSize, gateCb)

	log.Logf(0, "starting %v executor processes", *flagProcs)
	for pid := 0; pid < *flagProcs; pid++ {
		startProc(fuzzerTool, pid, config, *flagResetAccState)
	}

	checkReq.Name = *flagName
	checkReq.Files = host.ReadFiles(r.ReadFiles)
	checkReq.Globs = make(map[string][]string)
	for _, glob := range r.ReadGlobs {
		files, err := filepath.Glob(filepath.FromSlash(glob))
		if err != nil && checkReq.Error == "" {
			checkReq.Error = fmt.Sprintf("failed to read glob %q: %v", glob, err)
		}
		checkReq.Globs[glob] = files
	}
	checkRes := new(rpctype.CheckRes)
	if err := manager.Call("Manager.Check", checkReq, checkRes); err != nil {
		log.SyzFatalf("Manager.Check call failed: %v", err)
	}
	if checkReq.Error != "" {
		log.SyzFatalf("%v", checkReq.Error)
	}

	if *flagRunTest {
		runTest(target, manager, *flagName, executor)
		return
	}
	if checkRes.CoverFilterBitmap != nil {
		if err := osutil.WriteFile("syz-cover-bitmap", checkRes.CoverFilterBitmap); err != nil {
			log.SyzFatalf("failed to write syz-cover-bitmap: %v", err)
		}
	}
	// Query enough inputs at the beginning.
	fuzzerTool.exchangeDataCall(inputsCount, nil, 0)
	go fuzzerTool.exchangeDataWorker()
	fuzzerTool.exchangeDataWorker()
}

// Returns gateCallback for leak checking if enabled.
func (tool *FuzzerTool) useBugFrames(featues *host.Features, leakFrames, raceFrames []string) func() {
	var gateCallback func()

	if featues[host.FeatureLeak].Enabled {
		gateCallback = func() { tool.gateCallback(leakFrames) }
	}

	if featues[host.FeatureKCSAN].Enabled && len(raceFrames) != 0 {
		tool.filterDataRaceFrames(raceFrames)
	}

	return gateCallback
}

func (tool *FuzzerTool) gateCallback(leakFrames []string) {
	// Leak checking is very slow so we don't do it while triaging the corpus
	// (otherwise it takes infinity). When we have presumably triaged the corpus
	// (triagedCandidates == 1), we run leak checking bug ignore the result
	// to flush any previous leaks. After that (triagedCandidates == 2)
	// we do actual leak checking and report leaks.
	triagedCandidates := atomic.LoadUint32(&tool.triagedCandidates)
	if triagedCandidates == 0 {
		return
	}
	args := append([]string{"leak"}, leakFrames...)
	timeout := tool.timeouts.NoOutput * 9 / 10
	output, err := osutil.RunCmd(timeout, "", tool.executor, args...)
	if err != nil && triagedCandidates == 2 {
		// If we exit right away, dying executors will dump lots of garbage to console.
		os.Stdout.Write(output)
		fmt.Printf("BUG: leak checking failed\n")
		time.Sleep(time.Hour)
		os.Exit(1)
	}
	if triagedCandidates == 1 {
		atomic.StoreUint32(&tool.triagedCandidates, 2)
	}
}

func (tool *FuzzerTool) filterDataRaceFrames(frames []string) {
	args := append([]string{"setup_kcsan_filterlist"}, frames...)
	timeout := time.Minute * tool.timeouts.Scale
	output, err := osutil.RunCmd(timeout, "", tool.executor, args...)
	if err != nil {
		log.SyzFatalf("failed to set KCSAN filterlist: %v", err)
	}
	log.Logf(0, "%s", output)
}

func (tool *FuzzerTool) startExecutingCall(progID int64, pid, try int) {
	tool.manager.AsyncCall("Manager.StartExecuting", &rpctype.ExecutingRequest{
		Name:   tool.name,
		ID:     progID,
		ProcID: pid,
		Try:    try,
	})
}

func (tool *FuzzerTool) exchangeDataCall(needProgs int, results []rpctype.ExecutionResult,
	latency time.Duration) time.Duration {
	a := &rpctype.ExchangeInfoRequest{
		Name:       tool.name,
		NeedProgs:  needProgs,
		Results:    results,
		StatsDelta: tool.grabStats(),
		Latency:    latency,
	}
	r := &rpctype.ExchangeInfoReply{}
	start := osutil.MonotonicNano()
	if err := tool.manager.Call("Manager.ExchangeInfo", a, r); err != nil {
		log.SyzFatalf("Manager.ExchangeInfo call failed: %v", err)
	}
	latency = osutil.MonotonicNano() - start
	if needProgs != len(r.Requests) {
		log.SyzFatalf("manager returned wrong number of requests: %v/%v", needProgs, len(r.Requests))
	}
	tool.updateMaxSignal(r.NewMaxSignal, r.DropMaxSignal)
	for _, req := range r.Requests {
		tool.requests <- req
	}
	return latency
}

func (tool *FuzzerTool) exchangeDataWorker() {
	var latency time.Duration
	for result := range tool.results {
		results := []rpctype.ExecutionResult{tool.convertExecutionResult(result)}
		// Grab other finished calls, just in case there are any.
	loop:
		for {
			select {
			case res := <-tool.results:
				results = append(results, tool.convertExecutionResult(res))
			default:
				break loop
			}
		}
		// Replenish exactly the finished requests.
		latency = tool.exchangeDataCall(len(results), results, latency)
	}
}

func (tool *FuzzerTool) convertExecutionResult(res executionResult) rpctype.ExecutionResult {
	ret := rpctype.ExecutionResult{
		ID:     res.ID,
		ProcID: res.procID,
		Try:    res.try,
	}
	if res.info != nil {
		if res.NewSignal {
			tool.diffMaxSignal(res.info, res.SignalFilter, res.SignalFilterCall)
		}
		ret.Info = *res.info
	}
	return ret
}

func (tool *FuzzerTool) grabStats() map[string]uint64 {
	return map[string]uint64{
		"no exec requests": tool.noExecRequests.Swap(0),
		"no exec duration": tool.noExecDuration.Swap(0),
	}
}

func (tool *FuzzerTool) diffMaxSignal(info *ipc.ProgInfo, mask signal.Signal, maskCall int) {
	tool.signalMu.RLock()
	defer tool.signalMu.RUnlock()
	diffMaxSignal(info, tool.maxSignal, mask, maskCall)
}

func diffMaxSignal(info *ipc.ProgInfo, max, mask signal.Signal, maskCall int) {
	info.Extra.Signal = diffCallSignal(info.Extra.Signal, max, mask, -1, maskCall)
	for i := 0; i < len(info.Calls); i++ {
		info.Calls[i].Signal = diffCallSignal(info.Calls[i].Signal, max, mask, i, maskCall)
	}
}

func diffCallSignal(raw []uint32, max, mask signal.Signal, call, maskCall int) []uint32 {
	if mask != nil && call == maskCall {
		return signal.FilterRaw(raw, max, mask)
	}
	return max.DiffFromRaw(raw)
}

func (tool *FuzzerTool) updateMaxSignal(add, drop []uint32) {
	tool.signalMu.Lock()
	defer tool.signalMu.Unlock()
	tool.maxSignal.Subtract(signal.FromRaw(drop, 0))
	tool.maxSignal.Merge(signal.FromRaw(add, 0))
}

func setupPprofHandler(port int) {
	// Necessary for pprof handlers.
	go func() {
		err := http.ListenAndServe(fmt.Sprintf("0.0.0.0:%v", port), nil)
		if err != nil {
			log.SyzFatalf("failed to setup a server: %v", err)
		}
	}()
}
