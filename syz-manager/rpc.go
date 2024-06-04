// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/cover/backend"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/stats"
	"github.com/google/syzkaller/pkg/vminfo"
	"github.com/google/syzkaller/prog"
)

type RPCServer struct {
	mgr     RPCManagerView
	cfg     *mgrconfig.Config
	target  *prog.Target
	checker *vminfo.Checker
	port    int

	infoOnce         sync.Once
	checkDone        atomic.Bool
	checkFailures    int
	baseSource       *queue.DynamicSourceCtl
	enabledFeatures  flatrpc.Feature
	setupFeatures    flatrpc.Feature
	modules          []cover.KernelModule
	canonicalModules *cover.Canonicalizer
	execCoverFilter  []uint64            // includes both coverage and comparison PCs
	coverFilter      map[uint64]struct{} // includes only coverage PCs

	mu         sync.Mutex
	runners    map[string]*Runner
	execSource queue.Source
	checkLeaks bool

	statNumFuzzing         *stats.Val
	statExecs              *stats.Val
	statExecRetries        *stats.Val
	statExecutorRestarts   *stats.Val
	statExecBufferTooSmall *stats.Val
	statVMRestarts         *stats.Val
	statNoExecRequests     *stats.Val
	statNoExecDuration     *stats.Val
	statCoverFiltered      *stats.Val
}

type Runner struct {
	stopped       bool
	finished      chan bool
	injectExec    chan<- bool
	conn          *flatrpc.Conn
	machineInfo   []byte
	canonicalizer *cover.CanonicalizerInstance
	nextRequestID int64
	requests      map[int64]*queue.Request
	executing     map[int64]bool
	lastExec      *LastExecuting
	rnd           *rand.Rand
}

type BugFrames struct {
	memoryLeaks []string
	dataRaces   []string
}

// RPCManagerView restricts interface between RPCServer and Manager.
type RPCManagerView interface {
	currentBugFrames() BugFrames
	maxSignal() signal.Signal
	machineChecked(features flatrpc.Feature, enabledSyscalls map[*prog.Syscall]bool,
		opts flatrpc.ExecOpts) queue.Source
}

func startRPCServer(mgr *Manager) (*RPCServer, error) {
	checker := vminfo.New(mgr.cfg)
	baseSource := queue.DynamicSource(checker)
	serv := &RPCServer{
		mgr:        mgr,
		cfg:        mgr.cfg,
		target:     mgr.target,
		runners:    make(map[string]*Runner),
		checker:    checker,
		baseSource: baseSource,
		execSource: queue.Retry(baseSource),
		statExecs:  mgr.statExecs,
		statNumFuzzing: stats.Create("fuzzing VMs", "Number of VMs that are currently fuzzing",
			stats.Console),
		statExecRetries: stats.Create("exec retries",
			"Number of times a test program was restarted because the first run failed",
			stats.Rate{}, stats.Graph("executor")),
		statExecutorRestarts: stats.Create("executor restarts",
			"Number of times executor process was restarted", stats.Rate{}, stats.Graph("executor")),
		statExecBufferTooSmall: stats.Create("buffer too small",
			"Program serialization overflowed exec buffer", stats.NoGraph),
		statVMRestarts: stats.Create("vm restarts", "Total number of VM starts",
			stats.Rate{}, stats.NoGraph),
		statNoExecRequests: stats.Create("no exec requests",
			"Number of times fuzzer was stalled with no exec requests", stats.Rate{}),
		statNoExecDuration: stats.Create("no exec duration",
			"Total duration fuzzer was stalled with no exec requests (ns/sec)", stats.Rate{}),
		statCoverFiltered: stats.Create("filtered coverage", "", stats.NoGraph),
	}
	s, err := flatrpc.ListenAndServe(mgr.cfg.RPC, serv.handleConn)
	if err != nil {
		return nil, err
	}
	baseSource.Store(serv.checker)

	log.Logf(0, "serving rpc on tcp://%v", s.Addr)
	serv.port = s.Addr.Port
	return serv, nil
}

func (serv *RPCServer) handleConn(conn *flatrpc.Conn) {
	name, machineInfo, canonicalizer, err := serv.handshake(conn)
	if err != nil {
		log.Logf(1, "%v", err)
		return
	}

	if serv.cfg.VMLess {
		// There is no VM loop, so minic what it would do.
		serv.createInstance(name, nil)
		defer func() {
			serv.stopFuzzing(name)
			serv.shutdownInstance(name, false)
		}()
	}

	serv.mu.Lock()
	runner := serv.runners[name]
	if runner == nil || runner.stopped {
		serv.mu.Unlock()
		log.Logf(2, "VM %v shut down before connect", name)
		return
	}
	runner.conn = conn
	runner.machineInfo = machineInfo
	runner.canonicalizer = canonicalizer
	checkLeaks := serv.checkLeaks
	serv.mu.Unlock()
	defer close(runner.finished)

	if checkLeaks {
		if err := runner.sendStartLeakChecks(); err != nil {
			log.Logf(2, "%v", err)
			return
		}
	}

	err = serv.connectionLoop(runner)
	log.Logf(2, "runner %v: %v", name, err)
}

func (serv *RPCServer) handshake(conn *flatrpc.Conn) (string, []byte, *cover.CanonicalizerInstance, error) {
	connectReqRaw, err := flatrpc.Recv[flatrpc.ConnectRequestRaw](conn)
	if err != nil {
		return "", nil, nil, err
	}
	connectReq := connectReqRaw.UnPack()
	log.Logf(1, "fuzzer %v connected", connectReq.Name)
	if !serv.cfg.VMLess {
		checkRevisions(connectReq, serv.cfg.Target)
	}
	serv.statVMRestarts.Add(1)

	bugFrames := serv.mgr.currentBugFrames()
	connectReply := &flatrpc.ConnectReply{
		Debug:      *flagDebug,
		Procs:      int32(serv.cfg.Procs),
		Slowdown:   int32(serv.cfg.Timeouts.Slowdown),
		LeakFrames: bugFrames.memoryLeaks,
		RaceFrames: bugFrames.dataRaces,
	}
	connectReply.Files = serv.checker.RequiredFiles()
	if serv.checkDone.Load() {
		connectReply.Features = serv.setupFeatures
	} else {
		connectReply.Files = append(connectReply.Files, serv.checker.CheckFiles()...)
		connectReply.Globs = serv.target.RequiredGlobs()
		connectReply.Features = flatrpc.AllFeatures
	}
	if err := flatrpc.Send(conn, connectReply); err != nil {
		return "", nil, nil, err
	}

	infoReqRaw, err := flatrpc.Recv[flatrpc.InfoRequestRaw](conn)
	if err != nil {
		return "", nil, nil, err
	}
	infoReq := infoReqRaw.UnPack()
	modules, machineInfo, err := serv.checker.MachineInfo(infoReq.Files)
	if err != nil {
		log.Logf(0, "parsing of machine info failed: %v", err)
		if infoReq.Error == "" {
			infoReq.Error = err.Error()
		}
	}
	if infoReq.Error != "" {
		log.Logf(0, "machine check failed: %v", infoReq.Error)
		serv.checkFailures++
		if serv.checkFailures == 10 {
			log.Fatalf("machine check failing")
		}
		return "", nil, nil, errors.New("machine check failed")
	}

	serv.infoOnce.Do(func() {
		serv.modules = modules
		serv.canonicalModules = cover.NewCanonicalizer(modules, serv.cfg.Cover)
		var err error
		serv.execCoverFilter, serv.coverFilter, err = createCoverageFilter(serv.cfg, modules)
		if err != nil {
			log.Fatalf("failed to init coverage filter: %v", err)
		}
		globs := make(map[string][]string)
		for _, glob := range infoReq.Globs {
			globs[glob.Name] = glob.Files
		}
		serv.target.UpdateGlobs(globs)
		// Flatbuffers don't do deep copy of byte slices,
		// so clone manually since we pass it a goroutine.
		for _, file := range infoReq.Files {
			file.Data = slices.Clone(file.Data)
		}
		// Now execute check programs.
		go func() {
			if err := serv.runCheck(infoReq.Files, infoReq.Features); err != nil {
				log.Fatalf("check failed: %v", err)
			}
		}()
	})

	canonicalizer := serv.canonicalModules.NewInstance(modules)
	instCoverFilter := canonicalizer.Decanonicalize(serv.execCoverFilter)
	infoReply := &flatrpc.InfoReply{
		CoverFilter: createCoverageBitmap(serv.cfg, instCoverFilter),
	}
	if err := flatrpc.Send(conn, infoReply); err != nil {
		return "", nil, nil, err
	}
	return connectReq.Name, machineInfo, canonicalizer, nil
}

func (serv *RPCServer) connectionLoop(runner *Runner) error {
	if serv.cfg.Cover {
		maxSignal := serv.mgr.maxSignal().ToRaw()
		for len(maxSignal) != 0 {
			// Split coverage into batches to not grow the connection serialization
			// buffer too much (we don't want to grow it larger than what will be needed
			// to send programs).
			n := min(len(maxSignal), 50000)
			if err := runner.sendSignalUpdate(maxSignal[:n], nil); err != nil {
				return err
			}
			maxSignal = maxSignal[n:]
		}
	}

	serv.statNumFuzzing.Add(1)
	defer serv.statNumFuzzing.Add(-1)
	for {
		for len(runner.requests)-len(runner.executing) < 2*serv.cfg.Procs {
			req := serv.execSource.Next()
			if req == nil {
				break
			}
			if err := serv.sendRequest(runner, req); err != nil {
				return err
			}
		}
		if len(runner.requests) == 0 {
			// The runner has not requests at all, so don't wait to receive anything from it.
			// This is only possible during the initial checking.
			time.Sleep(10 * time.Millisecond)
			continue
		}
		raw, err := flatrpc.Recv[flatrpc.ExecutorMessageRaw](runner.conn)
		if err != nil {
			return err
		}
		unpacked := raw.UnPack()
		if unpacked.Msg == nil || unpacked.Msg.Value == nil {
			return errors.New("received no message")
		}
		switch msg := raw.UnPack().Msg.Value.(type) {
		case *flatrpc.ExecutingMessage:
			err = serv.handleExecutingMessage(runner, msg)
		case *flatrpc.ExecResult:
			err = serv.handleExecResult(runner, msg)
		default:
			return fmt.Errorf("received unknown message type %T", msg)
		}
		if err != nil {
			return err
		}
	}
}

func (serv *RPCServer) sendRequest(runner *Runner, req *queue.Request) error {
	if err := validateRequest(req); err != nil {
		panic(err)
	}
	progData, err := req.Prog.SerializeForExec()
	if err != nil {
		// It's bad if we systematically fail to serialize programs,
		// but so far we don't have a better handling than counting this.
		// This error is observed a lot on the seeded syz_mount_image calls.
		serv.statExecBufferTooSmall.Add(1)
		req.Done(&queue.Result{Status: queue.ExecFailure})
		return nil
	}
	runner.nextRequestID++
	id := runner.nextRequestID
	var flags flatrpc.RequestFlag
	if req.ReturnOutput {
		flags |= flatrpc.RequestFlagReturnOutput
	}
	if req.ReturnError {
		flags |= flatrpc.RequestFlagReturnError
	}
	allSignal := make([]int32, len(req.ReturnAllSignal))
	for i, call := range req.ReturnAllSignal {
		allSignal[i] = int32(call)
	}
	// Do not let too much state accumulate.
	const restartIn = 600
	resetFlags := flatrpc.ExecFlagCollectSignal | flatrpc.ExecFlagCollectCover | flatrpc.ExecFlagCollectComps
	if serv.cfg.Experimental.ResetAccState || req.ExecOpts.ExecFlags&resetFlags != 0 && runner.rnd.Intn(restartIn) == 0 {
		flags |= flatrpc.RequestFlagResetState
	}
	signalFilter := runner.canonicalizer.Decanonicalize(req.SignalFilter.ToRaw())
	msg := &flatrpc.HostMessage{
		Msg: &flatrpc.HostMessages{
			Type: flatrpc.HostMessagesRawExecRequest,
			Value: &flatrpc.ExecRequest{
				Id:               id,
				ProgData:         progData,
				Flags:            flags,
				ExecOpts:         &req.ExecOpts,
				SignalFilter:     signalFilter,
				SignalFilterCall: int32(req.SignalFilterCall),
				AllSignal:        allSignal,
			},
		},
	}
	runner.requests[id] = req
	return flatrpc.Send(runner.conn, msg)
}

func (serv *RPCServer) handleExecutingMessage(runner *Runner, msg *flatrpc.ExecutingMessage) error {
	req := runner.requests[msg.Id]
	if req == nil {
		return fmt.Errorf("can't find executing request %v", msg.Id)
	}
	proc := int(msg.ProcId)
	if proc < 0 || proc >= serv.cfg.Procs {
		return fmt.Errorf("got bad proc id %v", proc)
	}
	serv.statExecs.Add(1)
	if msg.Try == 0 {
		if msg.WaitDuration != 0 {
			serv.statNoExecRequests.Add(1)
			// Cap wait duration to 1 second to avoid extreme peaks on the graph
			// which make it impossible to see real data (the rest becomes a flat line).
			serv.statNoExecDuration.Add(int(min(msg.WaitDuration, 1e9)))
		}
	} else {
		serv.statExecRetries.Add(1)
	}
	runner.lastExec.Note(proc, req.Prog.Serialize(), osutil.MonotonicNano())
	select {
	case runner.injectExec <- true:
	default:
	}
	runner.executing[msg.Id] = true
	return nil
}

func (serv *RPCServer) handleExecResult(runner *Runner, msg *flatrpc.ExecResult) error {
	req := runner.requests[msg.Id]
	if req == nil {
		return fmt.Errorf("can't find executed request %v", msg.Id)
	}
	delete(runner.requests, msg.Id)
	delete(runner.executing, msg.Id)
	if msg.Info != nil {
		if msg.Info.Freshness == 0 {
			serv.statExecutorRestarts.Add(1)
		}
		if !serv.cfg.Cover && req.ExecOpts.ExecFlags&flatrpc.ExecFlagCollectSignal != 0 {
			// Coverage collection is disabled, but signal was requested => use a substitute signal.
			addFallbackSignal(req.Prog, msg.Info)
		}
		for i := 0; i < len(msg.Info.Calls); i++ {
			call := msg.Info.Calls[i]
			call.Cover = runner.canonicalizer.Canonicalize(call.Cover)
			call.Signal = runner.canonicalizer.Canonicalize(call.Signal)
		}
		if msg.Info.Extra != nil {
			msg.Info.Extra.Cover = runner.canonicalizer.Canonicalize(msg.Info.Extra.Cover)
			msg.Info.Extra.Signal = runner.canonicalizer.Canonicalize(msg.Info.Extra.Signal)
		}
	}
	status := queue.Success
	var resErr error
	if msg.Error != "" {
		status = queue.ExecFailure
		resErr = errors.New(msg.Error)
	}
	req.Done(&queue.Result{
		Status: status,
		Info:   msg.Info,
		Output: slices.Clone(msg.Output),
		Err:    resErr,
	})
	return nil
}

func checkRevisions(a *flatrpc.ConnectRequest, target *prog.Target) {
	if target.Arch != a.Arch {
		log.Fatalf("mismatching target/executor arches: %v vs %v", target.Arch, a.Arch)
	}
	if prog.GitRevision != a.GitRevision {
		log.Fatalf("mismatching manager/fuzzer git revisions: %v vs %v",
			prog.GitRevision, a.GitRevision)
	}
	if target.Revision != a.SyzRevision {
		log.Fatalf("mismatching manager/fuzzer system call descriptions: %v vs %v",
			target.Revision, a.SyzRevision)
	}
}

func (serv *RPCServer) runCheck(checkFilesInfo []*flatrpc.FileInfo, checkFeatureInfo []*flatrpc.FeatureInfo) error {
	enabledCalls, disabledCalls, features, checkErr := serv.checker.Run(checkFilesInfo, checkFeatureInfo)
	enabledCalls, transitivelyDisabled := serv.target.TransitivelyEnabledCalls(enabledCalls)
	// Note: need to print disbled syscalls before failing due to an error.
	// This helps to debug "all system calls are disabled".
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
	for _, file := range checkFilesInfo {
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
	newSource := serv.mgr.machineChecked(serv.enabledFeatures, enabledCalls, serv.execOpts())
	serv.baseSource.Store(newSource)
	serv.checkDone.Store(true)
	return nil
}

func validateRequest(req *queue.Request) error {
	err := req.Validate()
	if err != nil {
		return err
	}
	if req.BinaryFile != "" {
		// Currnetly it should only be done in tools/syz-runtest.
		return fmt.Errorf("binary file execution is not supported")
	}
	return nil
}

func (serv *RPCServer) createInstance(name string, injectExec chan<- bool) {
	runner := &Runner{
		injectExec: injectExec,
		finished:   make(chan bool),
		requests:   make(map[int64]*queue.Request),
		executing:  make(map[int64]bool),
		lastExec:   MakeLastExecuting(serv.cfg.Procs, 6),
		rnd:        rand.New(rand.NewSource(time.Now().UnixNano())),
	}
	serv.mu.Lock()
	if serv.runners[name] != nil {
		panic(fmt.Sprintf("duplicate instance %s", name))
	}
	serv.runners[name] = runner
	serv.mu.Unlock()
}

// stopInstance prevents further request exchange requests.
// To make RPCServer fully forget an instance, shutdownInstance() must be called.
func (serv *RPCServer) stopFuzzing(name string) {
	serv.mu.Lock()
	runner := serv.runners[name]
	runner.stopped = true
	conn := runner.conn
	serv.mu.Unlock()
	if conn != nil {
		conn.Close()
	}
}

func (serv *RPCServer) shutdownInstance(name string, crashed bool) ([]ExecRecord, []byte) {
	serv.mu.Lock()
	runner := serv.runners[name]
	delete(serv.runners, name)
	serv.mu.Unlock()
	if runner.conn != nil {
		// Wait for the connection goroutine to finish and stop touching data.
		// If conn is nil before we removed the runner, then it won't touch anything.
		<-runner.finished
	}
	for id, req := range runner.requests {
		status := queue.Restarted
		if crashed && runner.executing[id] {
			status = queue.Crashed
		}
		req.Done(&queue.Result{Status: status})
	}
	return runner.lastExec.Collect(), runner.machineInfo
}

func (serv *RPCServer) distributeSignalDelta(plus, minus signal.Signal) {
	plusRaw := plus.ToRaw()
	minusRaw := minus.ToRaw()
	serv.foreachRunnerAsync(func(runner *Runner) {
		runner.sendSignalUpdate(plusRaw, minusRaw)
	})
}

func (runner *Runner) sendSignalUpdate(plus, minus []uint64) error {
	msg := &flatrpc.HostMessage{
		Msg: &flatrpc.HostMessages{
			Type: flatrpc.HostMessagesRawSignalUpdate,
			Value: &flatrpc.SignalUpdate{
				NewMax:  runner.canonicalizer.Decanonicalize(plus),
				DropMax: runner.canonicalizer.Decanonicalize(minus),
			},
		},
	}
	return flatrpc.Send(runner.conn, msg)
}

func (serv *RPCServer) startLeakChecking() {
	serv.foreachRunnerAsync(func(runner *Runner) {
		runner.sendStartLeakChecks()
	})
}

func (runner *Runner) sendStartLeakChecks() error {
	msg := &flatrpc.HostMessage{
		Msg: &flatrpc.HostMessages{
			Type:  flatrpc.HostMessagesRawStartLeakChecks,
			Value: &flatrpc.StartLeakChecks{},
		},
	}
	return flatrpc.Send(runner.conn, msg)
}

// foreachRunnerAsync runs callback fn for each connected runner asynchronously.
// If a VM has hanged w/o reading out the socket, we want to avoid blocking
// important goroutines on the send operations.
func (serv *RPCServer) foreachRunnerAsync(fn func(runner *Runner)) {
	serv.mu.Lock()
	defer serv.mu.Unlock()
	for _, runner := range serv.runners {
		if runner.conn != nil {
			go fn(runner)
		}
	}
}

func (serv *RPCServer) updateCoverFilter(newCover []uint64) {
	if len(newCover) == 0 || serv.coverFilter == nil {
		return
	}
	filtered := 0
	for _, pc := range newCover {
		pc = backend.PreviousInstructionPC(serv.cfg.SysTarget, serv.cfg.Type, pc)
		if _, ok := serv.coverFilter[pc]; ok {
			filtered++
		}
	}
	serv.statCoverFiltered.Add(filtered)
}

func (serv *RPCServer) execOpts() flatrpc.ExecOpts {
	env := ipc.FeaturesToFlags(serv.enabledFeatures, nil)
	if *flagDebug {
		env |= flatrpc.ExecEnvDebug
	}
	if serv.cfg.Cover {
		env |= flatrpc.ExecEnvSignal
	}
	sandbox, err := ipc.SandboxToFlags(serv.cfg.Sandbox)
	if err != nil {
		panic(fmt.Sprintf("failed to parse sandbox: %v", err))
	}
	env |= sandbox

	exec := flatrpc.ExecFlagThreaded
	if !serv.cfg.RawCover {
		exec |= flatrpc.ExecFlagDedupCover
	}
	if serv.cfg.HasCovFilter() {
		exec |= flatrpc.ExecFlagCoverFilter
	}
	return flatrpc.ExecOpts{
		EnvFlags:   env,
		ExecFlags:  exec,
		SandboxArg: serv.cfg.SandboxArg,
	}
}

// addFallbackSignal computes simple fallback signal in cases we don't have real coverage signal.
// We use syscall number or-ed with returned errno value as signal.
// At least this gives us all combinations of syscall+errno.
func addFallbackSignal(p *prog.Prog, info *flatrpc.ProgInfo) {
	callInfos := make([]prog.CallInfo, len(info.Calls))
	for i, inf := range info.Calls {
		if inf.Flags&flatrpc.CallFlagExecuted != 0 {
			callInfos[i].Flags |= prog.CallExecuted
		}
		if inf.Flags&flatrpc.CallFlagFinished != 0 {
			callInfos[i].Flags |= prog.CallFinished
		}
		if inf.Flags&flatrpc.CallFlagBlocked != 0 {
			callInfos[i].Flags |= prog.CallBlocked
		}
		callInfos[i].Errno = int(inf.Error)
	}
	p.FallbackSignal(callInfos)
	for i, inf := range callInfos {
		info.Calls[i].Signal = inf.Signal
	}
}
