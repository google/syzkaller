// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/fuzzer"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/ipc/ipcconfig"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/sys/targets"
)

type FuzzerTool struct {
	name              string
	outputType        OutputType
	config            *ipc.Config
	fuzzer            *fuzzer.Fuzzer
	procs             []*Proc
	gate              *ipc.Gate
	manager           *rpctype.RPCClient
	target            *prog.Target
	triagedCandidates uint32
	timeouts          targets.Timeouts

	checkResult *rpctype.CheckArgs
	logMu       sync.Mutex

	bufferTooSmall uint64
	resetAccState  bool
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
		flagName      = flag.String("name", "test", "unique name for manager")
		flagOS        = flag.String("os", runtime.GOOS, "target OS")
		flagArch      = flag.String("arch", runtime.GOARCH, "target arch")
		flagManager   = flag.String("manager", "", "manager rpc address")
		flagProcs     = flag.Int("procs", 1, "number of parallel test processes")
		flagOutput    = flag.String("output", "stdout", "write programs to none/stdout/dmesg/file")
		flagTest      = flag.Bool("test", false, "enable image testing mode")      // used by syz-ci
		flagRunTest   = flag.Bool("runtest", false, "enable program testing mode") // used by pkg/runtest
		flagRawCover  = flag.Bool("raw_cover", false, "fetch raw coverage")
		flagPprofPort = flag.Int("pprof_port", 0, "HTTP port for the pprof endpoint (disabled if 0)")

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
	manager, err := rpctype.NewRPCClient(*flagManager, timeouts.Scale)
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
	if r.CheckResult == nil {
		checkArgs.gitRevision = r.GitRevision
		checkArgs.targetRevision = r.TargetRevision
		checkArgs.enabledCalls = r.EnabledCalls
		checkArgs.allSandboxes = r.AllSandboxes
		checkArgs.featureFlags = featureFlags
		r.CheckResult, err = checkMachine(checkArgs)
		if err != nil {
			if r.CheckResult == nil {
				r.CheckResult = new(rpctype.CheckArgs)
			}
			r.CheckResult.Error = err.Error()
		}
		r.CheckResult.Name = *flagName
		if err := manager.Call("Manager.Check", r.CheckResult, nil); err != nil {
			log.SyzFatalf("Manager.Check call failed: %v", err)
		}
		if r.CheckResult.Error != "" {
			log.SyzFatalf("%v", r.CheckResult.Error)
		}
	} else {
		target.UpdateGlobs(r.CheckResult.GlobFiles)
		if err = host.Setup(target, r.CheckResult.Features, featureFlags, config.Executor); err != nil {
			log.SyzFatalf("%v", err)
		}
	}
	log.Logf(0, "syscalls: %v", len(r.CheckResult.EnabledCalls[sandbox]))
	for _, feat := range r.CheckResult.Features.Supported() {
		log.Logf(0, "%v: %v", feat.Name, feat.Reason)
	}
	createIPCConfig(r.CheckResult.Features, config)

	if *flagRunTest {
		runTest(target, manager, *flagName, config.Executor)
		return
	}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	calls := make(map[*prog.Syscall]bool)
	for _, id := range r.CheckResult.EnabledCalls[sandbox] {
		calls[target.Syscalls[id]] = true
	}
	fuzzerObj := fuzzer.NewFuzzer(context.Background(), &fuzzer.Config{
		Coverage:       config.Flags&ipc.FlagSignal > 0,
		FaultInjection: r.CheckResult.Features[host.FeatureFault].Enabled,
		Comparisons:    r.CheckResult.Features[host.FeatureComparisons].Enabled,
		Collide:        execOpts.Flags&ipc.FlagThreaded > 0,
		EnabledCalls:   calls,
		NoMutateCalls:  r.NoMutateCalls,
		LeakChecking:   r.CheckResult.Features[host.FeatureLeak].Enabled,
		FetchRawCover:  *flagRawCover,
		MinCandidates:  uint(*flagProcs * 2),
		NewInputs:      make(chan rpctype.Input),
	}, rnd, target)

	fuzzerTool := &FuzzerTool{
		fuzzer:        fuzzerObj,
		name:          *flagName,
		outputType:    outputType,
		manager:       manager,
		target:        target,
		timeouts:      timeouts,
		config:        config,
		checkResult:   r.CheckResult,
		resetAccState: *flagResetAccState,
	}
	fuzzerObj.Config.Logf = func(level int, msg string, args ...interface{}) {
		// Log 0 messages are most important: send them directly to syz-manager.
		if level == 0 {
			fuzzerTool.Logf(level, msg, args...)
		}
		// Dump log level 0 and 1 messages into syz-fuzzer output.
		if level <= 1 {
			fuzzerTool.logMu.Lock()
			defer fuzzerTool.logMu.Unlock()
			log.Logf(0, "fuzzer: "+msg, args...)
		}
	}
	fuzzerTool.gate = ipc.NewGate(gateSize,
		fuzzerTool.useBugFrames(r, *flagProcs))
	for needCandidates, more := true, true; more; needCandidates = false {
		more = fuzzerTool.poll(needCandidates, nil)
		// This loop lead to "no output" in qemu emulation, tell manager we are not dead.
		stat := fuzzerObj.Corpus.Stat()
		log.Logf(0, "fetching corpus: %v, signal %v/%v (executing program)",
			stat.Progs, stat.Signal, stat.MaxSignal)
	}
	if r.CoverFilterBitmap != nil {
		execOpts.Flags |= ipc.FlagEnableCoverageFilter
	}

	log.Logf(0, "starting %v fuzzer processes", *flagProcs)
	for pid := 0; pid < *flagProcs; pid++ {
		proc, err := newProc(fuzzerTool, execOpts, pid)
		if err != nil {
			log.SyzFatalf("failed to create proc: %v", err)
		}
		fuzzerTool.procs = append(fuzzerTool.procs, proc)
		go proc.loop()
	}
	// Start send input workers.
	for i := 0; i < *flagProcs*2; i++ {
		go fuzzerTool.sendInputsWorker()
	}
	fuzzerTool.pollLoop()
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

	if r.CheckResult.Features[host.FeatureLeak].Enabled {
		gateCallback = func() { tool.gateCallback(r.MemoryLeakFrames) }
	}

	if r.CheckResult.Features[host.FeatureKCSAN].Enabled && len(r.DataRaceFrames) != 0 {
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

func (tool *FuzzerTool) pollLoop() {
	var execTotal uint64
	var lastPoll time.Time
	var lastPrint time.Time
	ticker := time.NewTicker(3 * time.Second * tool.timeouts.Scale).C
	for {
		needCandidates := false
		select {
		case <-ticker:
		case <-tool.fuzzer.NeedCandidates:
			needCandidates = true
		}
		if tool.outputType != OutputStdout && time.Since(lastPrint) > 10*time.Second*tool.timeouts.Scale {
			// Keep-alive for manager.
			log.Logf(0, "alive, executed %v", execTotal)
			lastPrint = time.Now()
		}
		needCandidates = tool.fuzzer.NeedCandidatesNow()
		if needCandidates || time.Since(lastPoll) > 10*time.Second*tool.timeouts.Scale {
			more := tool.poll(needCandidates, tool.grabStats())
			if !more {
				lastPoll = time.Now()
			}
		}
	}
}

func (tool *FuzzerTool) poll(needCandidates bool, stats map[string]uint64) bool {
	fuzzer := tool.fuzzer
	a := &rpctype.PollArgs{
		Name:           tool.name,
		NeedCandidates: needCandidates,
		MaxSignal:      fuzzer.Corpus.GrabNewSignal().Serialize(),
		Stats:          stats,
	}
	r := &rpctype.PollRes{}
	if err := tool.manager.Call("Manager.Poll", a, r); err != nil {
		log.SyzFatalf("Manager.Poll call failed: %v", err)
	}
	maxSignal := r.MaxSignal.Deserialize()
	log.Logf(1, "poll: candidates=%v inputs=%v signal=%v",
		len(r.Candidates), len(r.NewInputs), maxSignal.Len())
	fuzzer.Corpus.AddMaxSignal(maxSignal)
	for _, inp := range r.NewInputs {
		tool.inputFromOtherFuzzer(inp)
	}
	tool.addCandidates(r.Candidates)
	if needCandidates && len(r.Candidates) == 0 && atomic.LoadUint32(&tool.triagedCandidates) == 0 {
		atomic.StoreUint32(&tool.triagedCandidates, 1)
	}
	return len(r.NewInputs) != 0 || len(r.Candidates) != 0 || maxSignal.Len() != 0
}

func (tool *FuzzerTool) sendInputsWorker() {
	for inp := range tool.fuzzer.Config.NewInputs {
		a := &rpctype.NewInputArgs{
			Name:  tool.name,
			Input: inp,
		}
		if err := tool.manager.Call("Manager.NewInput", a, nil); err != nil {
			log.SyzFatalf("Manager.NewInput call failed: %v", err)
		}
	}
}

func (tool *FuzzerTool) grabStats() map[string]uint64 {
	stats := tool.fuzzer.GrabStats()
	for _, proc := range tool.procs {
		stats["exec total"] += atomic.SwapUint64(&proc.env.StatExecs, 0)
		stats["executor restarts"] += atomic.SwapUint64(&proc.env.StatRestarts, 0)
	}
	stats["buffer too small"] = atomic.SwapUint64(&tool.bufferTooSmall, 0)
	return stats
}

func (tool *FuzzerTool) addCandidates(candidates []rpctype.Candidate) {
	var inputs []fuzzer.Candidate
	for _, candidate := range candidates {
		p := tool.deserializeInput(candidate.Prog)
		if p == nil {
			continue
		}
		inputs = append(inputs, fuzzer.Candidate{
			Prog:      p,
			Smashed:   candidate.Smashed,
			Minimized: candidate.Minimized,
		})
	}
	if len(inputs) > 0 {
		tool.fuzzer.AddCandidates(inputs)
	}
}

func (tool *FuzzerTool) inputFromOtherFuzzer(inp rpctype.Input) {
	p := tool.deserializeInput(inp.Prog)
	if p == nil {
		return
	}
	tool.fuzzer.Corpus.Save(p,
		inp.Signal.Deserialize(),
		hash.Hash(inp.Prog))
}

func (tool *FuzzerTool) deserializeInput(inp []byte) *prog.Prog {
	p, err := tool.target.Deserialize(inp, prog.NonStrict)
	if err != nil {
		log.SyzFatalf("failed to deserialize prog: %v\n%s", err, inp)
	}
	tool.checkDisabledCalls(p)
	if len(p.Calls) > prog.MaxCalls {
		return nil
	}
	return p
}

func (tool *FuzzerTool) checkDisabledCalls(p *prog.Prog) {
	ct := tool.fuzzer.ChoiceTable()
	for _, call := range p.Calls {
		if !ct.Enabled(call.Meta.ID) {
			fmt.Printf("executing disabled syscall %v [%v]\n", call.Meta.Name, call.Meta.ID)
			sandbox := ipc.FlagsToSandbox(tool.config.Flags)
			fmt.Printf("check result for sandbox=%v:\n", sandbox)
			for _, id := range tool.checkResult.EnabledCalls[sandbox] {
				meta := tool.target.Syscalls[id]
				fmt.Printf("  %v [%v]\n", meta.Name, meta.ID)
			}
			fmt.Printf("choice table:\n")
			for i, meta := range tool.target.Syscalls {
				fmt.Printf("  #%v: %v [%v]: enabled=%v\n", i, meta.Name, meta.ID, ct.Enabled(meta.ID))
			}
			panic("disabled syscall")
		}
	}
}

// nolint: unused
// It's only needed for debugging.
func (tool *FuzzerTool) Logf(level int, msg string, args ...interface{}) {
	go func() {
		a := &rpctype.LogMessageReq{
			Level:   level,
			Name:    tool.name,
			Message: fmt.Sprintf(msg, args...),
		}
		if err := tool.manager.Call("Manager.LogMessage", a, nil); err != nil {
			log.SyzFatalf("Manager.LogMessage call failed: %v", err)
		}
	}()
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
