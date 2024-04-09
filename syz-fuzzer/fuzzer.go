// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
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
	name              string
	outputType        OutputType
	config            *ipc.Config
	procs             []*Proc
	gate              *ipc.Gate
	manager           *rpctype.RPCClient
	target            *prog.Target
	triagedCandidates uint32
	timeouts          targets.Timeouts

	logMu sync.Mutex

	bufferTooSmall atomic.Uint64
	noExecRequests atomic.Uint64
	noExecDuration atomic.Uint64
	resetAccState  bool

	inputs    chan executionRequest
	results   chan executionResult
	signalMu  sync.RWMutex
	maxSignal signal.Signal
}

// executionResult offloads some computations from the proc loop
// to the communication thread.
type executionResult struct {
	rpctype.ExecutionRequest
	info *ipc.ProgInfo
}

// executionRequest offloads prog deseralization to another thread.
type executionRequest struct {
	rpctype.ExecutionRequest
	prog *prog.Prog
}

type OutputType int

const (
	OutputNone OutputType = iota
	OutputStdout
	OutputDmesg
	OutputFile
)

func createIPCConfig(features *host.Features, config *ipc.Config) {
	if features[host.FeatureExtraCoverage].Enabled {
		config.Flags |= ipc.FlagExtraCover
	}
	if features[host.FeatureDelayKcovMmap].Enabled {
		config.Flags |= ipc.FlagDelayKcovMmap
	}
	if features[host.FeatureNetInjection].Enabled {
		config.Flags |= ipc.FlagEnableTun
	}
	if features[host.FeatureNetDevices].Enabled {
		config.Flags |= ipc.FlagEnableNetDev
	}
	config.Flags |= ipc.FlagEnableNetReset
	config.Flags |= ipc.FlagEnableCgroups
	config.Flags |= ipc.FlagEnableCloseFds
	if features[host.FeatureDevlinkPCI].Enabled {
		config.Flags |= ipc.FlagEnableDevlinkPCI
	}
	if features[host.FeatureNicVF].Enabled {
		config.Flags |= ipc.FlagEnableNicVF
	}
	if features[host.FeatureVhciInjection].Enabled {
		config.Flags |= ipc.FlagEnableVhciInjection
	}
	if features[host.FeatureWifiEmulation].Enabled {
		config.Flags |= ipc.FlagEnableWifi
	}
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
		flagOutput         = flag.String("output", "stdout", "write programs to none/stdout/dmesg/file")
		flagTest           = flag.Bool("test", false, "enable image testing mode")      // used by syz-ci
		flagRunTest        = flag.Bool("runtest", false, "enable program testing mode") // used by pkg/runtest
		flagRawCover       = flag.Bool("raw_cover", false, "fetch raw coverage")
		flagPprofPort      = flag.Int("pprof_port", 0, "HTTP port for the pprof endpoint (disabled if 0)")
		flagNetCompression = flag.Bool("net_compression", false, "use network compression for RPC calls")

		// Experimental flags.
		flagResetAccState = flag.Bool("reset_acc_state", false, "restarts executor before most executions")
	)
	defer tool.Init()()
	outputType := parseOutputType(*flagOutput)
	log.Logf(0, "fuzzer started")

	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		log.SyzFatalf("%v", err)
	}

	config, execOpts, err := ipcconfig.Default(target)
	if err != nil {
		log.SyzFatalf("failed to create default ipc config: %v", err)
	}
	if *flagRawCover {
		execOpts.Flags &^= ipc.FlagDedupCover
	}
	timeouts := config.Timeouts
	sandbox := ipc.FlagsToSandbox(config.Flags)
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

	machineInfo, modules := collectMachineInfos(target)

	log.Logf(0, "dialing manager at %v", *flagManager)
	manager, err := rpctype.NewRPCClient(*flagManager, timeouts.Scale, *flagNetCompression)
	if err != nil {
		log.SyzFatalf("failed to create an RPC client: %v ", err)
	}

	log.Logf(1, "connecting to manager...")
	a := &rpctype.ConnectArgs{
		Name:        *flagName,
		MachineInfo: machineInfo,
		Modules:     modules,
	}
	r := &rpctype.ConnectRes{}
	if err := manager.Call("Manager.Connect", a, r); err != nil {
		log.SyzFatalf("failed to call Manager.Connect(): %v ", err)
	}
	featureFlags, err := csource.ParseFeaturesFlags("none", "none", true)
	if err != nil {
		log.SyzFatalf("%v", err)
	}
	if r.CoverFilterBitmap != nil {
		if err := osutil.WriteFile("syz-cover-bitmap", r.CoverFilterBitmap); err != nil {
			log.SyzFatalf("failed to write syz-cover-bitmap: %v", err)
		}
	}
	if r.Features == nil {
		checkArgs.gitRevision = r.GitRevision
		checkArgs.targetRevision = r.TargetRevision
		checkArgs.enabledCalls = r.EnabledCalls
		checkArgs.allSandboxes = r.AllSandboxes
		checkArgs.featureFlags = featureFlags
		checkResult, err := checkMachine(checkArgs)
		if err != nil {
			if checkResult == nil {
				checkResult = new(rpctype.CheckArgs)
			}
			checkResult.Error = err.Error()
		}
		checkResult.Name = *flagName
		if err := manager.Call("Manager.Check", checkResult, nil); err != nil {
			log.SyzFatalf("Manager.Check call failed: %v", err)
		}
		if checkResult.Error != "" {
			log.SyzFatalf("%v", checkResult.Error)
		}
		r.Features = checkResult.Features
	} else {
		if err = host.Setup(target, r.Features, featureFlags, config.Executor); err != nil {
			log.SyzFatalf("%v", err)
		}
	}
	for _, feat := range r.Features.Supported() {
		log.Logf(0, "%v: %v", feat.Name, feat.Reason)
	}
	createIPCConfig(r.Features, config)

	if *flagRunTest {
		runTest(target, manager, *flagName, config.Executor)
		return
	}
	inputsCount := *flagProcs * 2
	fuzzerTool := &FuzzerTool{
		name:          *flagName,
		outputType:    outputType,
		manager:       manager,
		target:        target,
		timeouts:      timeouts,
		config:        config,
		resetAccState: *flagResetAccState,

		inputs:  make(chan executionRequest, inputsCount),
		results: make(chan executionResult, inputsCount),
	}
	fuzzerTool.gate = ipc.NewGate(gateSize,
		fuzzerTool.useBugFrames(r, *flagProcs))
	if r.CoverFilterBitmap != nil {
		execOpts.Flags |= ipc.FlagEnableCoverageFilter
	}
	// Query enough inputs at the beginning.
	fuzzerTool.exchangeDataCall(inputsCount, nil, 0)
	log.Logf(0, "starting %v executor processes", *flagProcs)
	for pid := 0; pid < *flagProcs; pid++ {
		proc, err := newProc(fuzzerTool, execOpts, pid)
		if err != nil {
			log.SyzFatalf("failed to create proc: %v", err)
		}
		fuzzerTool.procs = append(fuzzerTool.procs, proc)
		go proc.loop()
	}
	go fuzzerTool.exchangeDataWorker()
	fuzzerTool.exchangeDataWorker()
}

func collectMachineInfos(target *prog.Target) ([]byte, []host.KernelModule) {
	machineInfo, err := host.CollectMachineInfo()
	if err != nil {
		log.SyzFatalf("failed to collect machine information: %v", err)
	}
	modules, err := host.CollectModulesInfo()
	if err != nil {
		log.SyzFatalf("failed to collect modules info: %v", err)
	}
	return machineInfo, modules
}

// Returns gateCallback for leak checking if enabled.
func (tool *FuzzerTool) useBugFrames(r *rpctype.ConnectRes, flagProcs int) func() {
	var gateCallback func()

	if r.Features[host.FeatureLeak].Enabled {
		gateCallback = func() { tool.gateCallback(r.MemoryLeakFrames) }
	}

	if r.Features[host.FeatureKCSAN].Enabled && len(r.DataRaceFrames) != 0 {
		tool.filterDataRaceFrames(r.DataRaceFrames)
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
	output, err := osutil.RunCmd(timeout, "", tool.config.Executor, args...)
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
	output, err := osutil.RunCmd(timeout, "", tool.config.Executor, args...)
	if err != nil {
		log.SyzFatalf("failed to set KCSAN filterlist: %v", err)
	}
	log.Logf(0, "%s", output)
}

func (tool *FuzzerTool) exchangeDataCall(needProgs int, results []executionResult,
	latency time.Duration) time.Duration {
	a := &rpctype.ExchangeInfoRequest{
		Name:       tool.name,
		NeedProgs:  needProgs,
		StatsDelta: tool.grabStats(),
		Latency:    latency,
	}
	for _, result := range results {
		a.Results = append(a.Results, tool.convertExecutionResult(result))
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
		p := tool.deserializeInput(req.ProgData)
		if p == nil {
			log.SyzFatalf("failed to deserialize input: %s", req.ProgData)
		}
		tool.inputs <- executionRequest{
			ExecutionRequest: req,
			prog:             p,
		}
	}
	return latency
}

func (tool *FuzzerTool) exchangeDataWorker() {
	var latency time.Duration
	for result := range tool.results {
		results := []executionResult{
			result,
		}
		// Grab other finished calls, just in case there are any.
	loop:
		for {
			select {
			case res := <-tool.results:
				results = append(results, res)
			default:
				break loop
			}
		}
		// Replenish exactly the finished requests.
		latency = tool.exchangeDataCall(len(results), results, latency)
	}
}

func (tool *FuzzerTool) convertExecutionResult(res executionResult) rpctype.ExecutionResult {
	ret := rpctype.ExecutionResult{ID: res.ID}
	if res.info != nil {
		if res.NeedSignal == rpctype.NewSignal {
			tool.diffMaxSignal(res.info)
		}
		if res.SignalFilter != nil {
			// TODO: we can filter without maps if req.SignalFilter is sorted.
			filterProgInfo(res.info, res.SignalFilter)
		}
		ret.Info = *res.info
	}
	return ret
}

func (tool *FuzzerTool) grabStats() map[string]uint64 {
	stats := map[string]uint64{}
	for _, proc := range tool.procs {
		stats["exec total"] += atomic.SwapUint64(&proc.env.StatExecs, 0)
		stats["executor restarts"] += atomic.SwapUint64(&proc.env.StatRestarts, 0)
	}
	stats["buffer too small"] = tool.bufferTooSmall.Swap(0)
	stats["no exec requests"] = tool.noExecRequests.Swap(0)
	stats["no exec duration"] = tool.noExecDuration.Swap(0)
	return stats
}

func (tool *FuzzerTool) deserializeInput(inp []byte) *prog.Prog {
	p, err := tool.target.Deserialize(inp, prog.NonStrict)
	if err != nil {
		log.SyzFatalf("failed to deserialize prog: %v\n%s", err, inp)
	}
	if len(p.Calls) > prog.MaxCalls {
		return nil
	}
	return p
}

// The linter is too aggressive.
// nolint: dupl
func filterProgInfo(info *ipc.ProgInfo, mask signal.Signal) {
	info.Extra.Signal = mask.FilterRaw(info.Extra.Signal)
	for i := 0; i < len(info.Calls); i++ {
		info.Calls[i].Signal = mask.FilterRaw(info.Calls[i].Signal)
	}
}

// The linter is too aggressive.
// nolint: dupl
func diffProgInfo(info *ipc.ProgInfo, base signal.Signal) {
	info.Extra.Signal = base.DiffFromRaw(info.Extra.Signal)
	for i := 0; i < len(info.Calls); i++ {
		info.Calls[i].Signal = base.DiffFromRaw(info.Calls[i].Signal)
	}
}

func (tool *FuzzerTool) diffMaxSignal(info *ipc.ProgInfo) {
	tool.signalMu.RLock()
	defer tool.signalMu.RUnlock()

	diffProgInfo(info, tool.maxSignal)
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

func parseOutputType(str string) OutputType {
	switch str {
	case "none":
		return OutputNone
	case "stdout":
		return OutputStdout
	case "dmesg":
		return OutputDmesg
	case "file":
		return OutputFile
	default:
		log.SyzFatalf("-output flag must be one of none/stdout/dmesg/file")
		return OutputNone
	}
}
