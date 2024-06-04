// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package rpcserver

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"math/rand"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/stats"
	"github.com/google/syzkaller/pkg/vminfo"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

type Config struct {
	vminfo.Config
	RPC               string
	VMLess            bool
	PrintMachineCheck bool
	Procs             int
	Slowdown          int
}

type Manager interface {
	MaxSignal() signal.Signal
	BugFrames() (leaks []string, races []string)
	MachineChecked(features flatrpc.Feature, syscalls map[*prog.Syscall]bool) queue.Source
	CoverageFilter(modules []*cover.KernelModule) []uint64
}

type Server struct {
	Port           int
	StatExecs      *stats.Val
	StatNumFuzzing *stats.Val

	cfg      *Config
	mgr      Manager
	serv     *flatrpc.Serv
	target   *prog.Target
	timeouts targets.Timeouts
	checker  *vminfo.Checker

	infoOnce         sync.Once
	checkDone        atomic.Bool
	checkFailures    int
	baseSource       *queue.DynamicSourceCtl
	enabledFeatures  flatrpc.Feature
	setupFeatures    flatrpc.Feature
	modules          []*cover.KernelModule
	canonicalModules *cover.Canonicalizer
	coverFilter      []uint64

	mu            sync.Mutex
	runners       map[string]*Runner
	info          map[string]VMState
	execSource    queue.Source
	triagedCorpus atomic.Bool

	statExecRetries        *stats.Val
	statExecutorRestarts   *stats.Val
	statExecBufferTooSmall *stats.Val
	statVMRestarts         *stats.Val
	statNoExecRequests     *stats.Val
	statNoExecDuration     *stats.Val
}

type Runner struct {
	stopped       bool
	finished      chan bool
	injectExec    chan<- bool
	infoc         chan chan []byte
	conn          *flatrpc.Conn
	machineInfo   []byte
	canonicalizer *cover.CanonicalizerInstance
	nextRequestID int64
	requests      map[int64]*queue.Request
	executing     map[int64]bool
	lastExec      *LastExecuting
	rnd           *rand.Rand
}

func New(cfg *mgrconfig.Config, mgr Manager, debug bool) (*Server, error) {
	sandbox, err := flatrpc.SandboxToFlags(cfg.Sandbox)
	if err != nil {
		return nil, err
	}
	return newImpl(&Config{
		Config: vminfo.Config{
			Target:     cfg.Target,
			Features:   flatrpc.AllFeatures,
			Syscalls:   cfg.Syscalls,
			Debug:      debug,
			Cover:      cfg.Cover,
			Sandbox:    sandbox,
			SandboxArg: cfg.SandboxArg,
		},
		RPC:               cfg.RPC,
		VMLess:            cfg.VMLess,
		PrintMachineCheck: true,
		Procs:             cfg.Procs,
		Slowdown:          cfg.Timeouts.Slowdown,
	}, mgr)
}

func newImpl(cfg *Config, mgr Manager) (*Server, error) {
	cfg.Procs = min(cfg.Procs, prog.MaxPids)
	checker := vminfo.New(&cfg.Config)
	baseSource := queue.DynamicSource(checker)
	serv := &Server{
		cfg:        cfg,
		mgr:        mgr,
		target:     cfg.Target,
		timeouts:   targets.Get(cfg.Target.OS, cfg.Target.Arch).Timeouts(cfg.Slowdown),
		runners:    make(map[string]*Runner),
		info:       make(map[string]VMState),
		checker:    checker,
		baseSource: baseSource,
		execSource: queue.Retry(baseSource),

		StatExecs: stats.Create("exec total", "Total test program executions",
			stats.Console, stats.Rate{}, stats.Prometheus("syz_exec_total")),
		StatNumFuzzing: stats.Create("fuzzing VMs", "Number of VMs that are currently fuzzing",
			stats.Console, stats.Link("/vms")),
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
	}
	s, err := flatrpc.ListenAndServe(cfg.RPC, serv.handleConn)
	if err != nil {
		return nil, err
	}
	serv.serv = s
	serv.Port = s.Addr.Port
	return serv, nil
}

func (serv *Server) Close() error {
	return serv.serv.Close()
}

type VMState struct {
	State     int
	Timestamp time.Time
}

const (
	StateOffline = iota
	StateBooting
	StateFuzzing
	StateStopping
)

func (serv *Server) VMState() map[string]VMState {
	serv.mu.Lock()
	defer serv.mu.Unlock()
	return maps.Clone(serv.info)
}

func (serv *Server) MachineInfo(name string) []byte {
	serv.mu.Lock()
	runner := serv.runners[name]
	if runner != nil && (runner.conn == nil || runner.stopped) {
		runner = nil
	}
	serv.mu.Unlock()
	if runner == nil {
		return []byte("VM is not alive")
	}
	return runner.machineInfo
}

func (serv *Server) RunnerStatus(name string) []byte {
	serv.mu.Lock()
	runner := serv.runners[name]
	if runner != nil && (runner.conn == nil || runner.stopped) {
		runner = nil
	}
	serv.mu.Unlock()
	if runner == nil {
		return []byte("VM is not alive")
	}
	resc := make(chan []byte, 1)
	timeout := time.After(time.Minute)
	select {
	case runner.infoc <- resc:
	case <-timeout:
		return []byte("VM loop is not responding")
	}
	select {
	case res := <-resc:
		return res
	case <-timeout:
		return []byte("VM is not responding")
	}
}

func (serv *Server) handleConn(conn *flatrpc.Conn) {
	name, machineInfo, canonicalizer, err := serv.handshake(conn)
	if err != nil {
		log.Logf(1, "%v", err)
		return
	}

	if serv.cfg.VMLess {
		// There is no VM loop, so minic what it would do.
		serv.CreateInstance(name, nil)
		defer func() {
			serv.StopFuzzing(name)
			serv.ShutdownInstance(name, true)
		}()
	}

	serv.mu.Lock()
	runner := serv.runners[name]
	if runner == nil || runner.stopped {
		serv.mu.Unlock()
		log.Logf(2, "VM %v shut down before connect", name)
		return
	}
	serv.info[name] = VMState{StateFuzzing, time.Now()}
	runner.conn = conn
	runner.machineInfo = machineInfo
	runner.canonicalizer = canonicalizer
	serv.mu.Unlock()
	defer close(runner.finished)

	if serv.triagedCorpus.Load() {
		if err := runner.sendStartLeakChecks(); err != nil {
			log.Logf(2, "%v", err)
			return
		}
	}

	err = serv.connectionLoop(runner)
	log.Logf(2, "runner %v: %v", name, err)
}

func (serv *Server) handshake(conn *flatrpc.Conn) (string, []byte, *cover.CanonicalizerInstance, error) {
	connectReq, err := flatrpc.Recv[*flatrpc.ConnectRequestRaw](conn)
	if err != nil {
		return "", nil, nil, err
	}
	log.Logf(1, "runner %v connected", connectReq.Name)
	if !serv.cfg.VMLess {
		checkRevisions(connectReq, serv.cfg.Target)
	}
	serv.statVMRestarts.Add(1)

	leaks, races := serv.mgr.BugFrames()
	connectReply := &flatrpc.ConnectReply{
		Debug:            serv.cfg.Debug,
		Cover:            serv.cfg.Cover,
		Procs:            int32(serv.cfg.Procs),
		Slowdown:         int32(serv.timeouts.Slowdown),
		SyscallTimeoutMs: int32(serv.timeouts.Syscall / time.Millisecond),
		ProgramTimeoutMs: int32(serv.timeouts.Program / time.Millisecond),
		LeakFrames:       leaks,
		RaceFrames:       races,
	}
	connectReply.Files = serv.checker.RequiredFiles()
	if serv.checkDone.Load() {
		connectReply.Features = serv.setupFeatures
	} else {
		connectReply.Files = append(connectReply.Files, serv.checker.CheckFiles()...)
		connectReply.Globs = serv.target.RequiredGlobs()
		connectReply.Features = serv.cfg.Features
	}
	if err := flatrpc.Send(conn, connectReply); err != nil {
		return "", nil, nil, err
	}

	infoReq, err := flatrpc.Recv[*flatrpc.InfoRequestRaw](conn)
	if err != nil {
		return "", nil, nil, err
	}
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
		serv.coverFilter = serv.mgr.CoverageFilter(modules)
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
	infoReply := &flatrpc.InfoReply{
		CoverFilter: canonicalizer.Decanonicalize(serv.coverFilter),
	}
	if err := flatrpc.Send(conn, infoReply); err != nil {
		return "", nil, nil, err
	}
	return connectReq.Name, machineInfo, canonicalizer, nil
}

func (serv *Server) connectionLoop(runner *Runner) error {
	if serv.cfg.Cover {
		maxSignal := serv.mgr.MaxSignal().ToRaw()
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

	serv.StatNumFuzzing.Add(1)
	defer serv.StatNumFuzzing.Add(-1)
	var infoc chan []byte
	defer func() {
		if infoc != nil {
			infoc <- []byte("VM has crashed")
		}
	}()
	for {
		if infoc == nil {
			select {
			case infoc = <-runner.infoc:
				msg := &flatrpc.HostMessage{
					Msg: &flatrpc.HostMessages{
						Type:  flatrpc.HostMessagesRawStateRequest,
						Value: &flatrpc.StateRequest{},
					},
				}
				if err := flatrpc.Send(runner.conn, msg); err != nil {
					return err
				}
			default:
			}
		}
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
			time.Sleep(10 * time.Millisecond)
			continue
		}
		raw, err := flatrpc.Recv[*flatrpc.ExecutorMessageRaw](runner.conn)
		if err != nil {
			return err
		}
		if raw.Msg == nil || raw.Msg.Value == nil {
			return errors.New("received no message")
		}
		switch msg := raw.Msg.Value.(type) {
		case *flatrpc.ExecutingMessage:
			err = serv.handleExecutingMessage(runner, msg)
		case *flatrpc.ExecResult:
			err = serv.handleExecResult(runner, msg)
		case *flatrpc.StateResult:
			if infoc != nil {
				buf := new(bytes.Buffer)
				fmt.Fprintf(buf, "pending requests on the VM:")
				for id := range runner.requests {
					fmt.Fprintf(buf, " %v", id)
				}
				fmt.Fprintf(buf, "\n\n")
				infoc <- append(buf.Bytes(), msg.Data...)
				infoc = nil
			}
		default:
			return fmt.Errorf("received unknown message type %T", msg)
		}
		if err != nil {
			return err
		}
	}
}

func (serv *Server) sendRequest(runner *Runner, req *queue.Request) error {
	if err := req.Validate(); err != nil {
		panic(err)
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
	opts := req.ExecOpts
	if req.ExecOpts.ExecFlags&resetFlags != 0 && runner.rnd.Intn(restartIn) == 0 {
		opts.EnvFlags |= flatrpc.ExecEnvResetState
	}
	if serv.cfg.Debug {
		opts.EnvFlags |= flatrpc.ExecEnvDebug
	}
	var data []byte
	if req.BinaryFile == "" {
		progData, err := req.Prog.SerializeForExec()
		if err != nil {
			// It's bad if we systematically fail to serialize programs,
			// but so far we don't have a better handling than counting this.
			// This error is observed a lot on the seeded syz_mount_image calls.
			serv.statExecBufferTooSmall.Add(1)
			req.Done(&queue.Result{Status: queue.ExecFailure})
			return nil
		}
		data = progData
	} else {
		flags |= flatrpc.RequestFlagIsBinary
		fileData, err := os.ReadFile(req.BinaryFile)
		if err != nil {
			req.Done(&queue.Result{
				Status: queue.ExecFailure,
				Err:    err,
			})
			return nil
		}
		data = fileData
	}
	msg := &flatrpc.HostMessage{
		Msg: &flatrpc.HostMessages{
			Type: flatrpc.HostMessagesRawExecRequest,
			Value: &flatrpc.ExecRequest{
				Id:        id,
				ProgData:  data,
				Flags:     flags,
				ExecOpts:  &opts,
				AllSignal: allSignal,
			},
		},
	}
	runner.requests[id] = req
	return flatrpc.Send(runner.conn, msg)
}

func (serv *Server) handleExecutingMessage(runner *Runner, msg *flatrpc.ExecutingMessage) error {
	req := runner.requests[msg.Id]
	if req == nil {
		return fmt.Errorf("can't find executing request %v", msg.Id)
	}
	proc := int(msg.ProcId)
	if proc < 0 || proc >= serv.cfg.Procs {
		return fmt.Errorf("got bad proc id %v", proc)
	}
	serv.StatExecs.Add(1)
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
	runner.lastExec.Note(int(msg.Id), proc, req.Prog.Serialize(), osutil.MonotonicNano())
	select {
	case runner.injectExec <- true:
	default:
	}
	runner.executing[msg.Id] = true
	return nil
}

func (serv *Server) handleExecResult(runner *Runner, msg *flatrpc.ExecResult) error {
	req := runner.requests[msg.Id]
	if req == nil {
		return fmt.Errorf("can't find executed request %v", msg.Id)
	}
	delete(runner.requests, msg.Id)
	delete(runner.executing, msg.Id)
	if msg.Info != nil {
		for len(msg.Info.Calls) < len(req.Prog.Calls) {
			msg.Info.Calls = append(msg.Info.Calls, &flatrpc.CallInfo{
				Error: 999,
			})
		}
		msg.Info.Calls = msg.Info.Calls[:len(req.Prog.Calls)]
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
		if len(msg.Info.ExtraRaw) != 0 {
			msg.Info.Extra = msg.Info.ExtraRaw[0]
			for _, info := range msg.Info.ExtraRaw[1:] {
				// All processing in the fuzzer later will convert signal/cover to maps and dedup,
				// so there is little point in deduping here.
				msg.Info.Extra.Cover = append(msg.Info.Extra.Cover, info.Cover...)
				msg.Info.Extra.Signal = append(msg.Info.Extra.Signal, info.Signal...)
			}
			msg.Info.Extra.Cover = runner.canonicalizer.Canonicalize(msg.Info.Extra.Cover)
			msg.Info.Extra.Signal = runner.canonicalizer.Canonicalize(msg.Info.Extra.Signal)
			msg.Info.ExtraRaw = nil
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
		log.Fatalf("mismatching manager/executor arches: %v vs %v", target.Arch, a.Arch)
	}
	if prog.GitRevision != a.GitRevision {
		log.Fatalf("mismatching manager/executor git revisions: %v vs %v",
			prog.GitRevision, a.GitRevision)
	}
	if target.Revision != a.SyzRevision {
		log.Fatalf("mismatching manager/executor system call descriptions: %v vs %v",
			target.Revision, a.SyzRevision)
	}
}

func (serv *Server) runCheck(checkFilesInfo []*flatrpc.FileInfo, checkFeatureInfo []*flatrpc.FeatureInfo) error {
	enabledCalls, disabledCalls, features, checkErr := serv.checker.Run(checkFilesInfo, checkFeatureInfo)
	enabledCalls, transitivelyDisabled := serv.target.TransitivelyEnabledCalls(enabledCalls)
	// Note: need to print disbled syscalls before failing due to an error.
	// This helps to debug "all system calls are disabled".
	if serv.cfg.PrintMachineCheck {
		serv.printMachineCheck(checkFilesInfo, enabledCalls, disabledCalls, transitivelyDisabled, features)
	}
	if checkErr != nil {
		return checkErr
	}
	serv.enabledFeatures = features.Enabled()
	serv.setupFeatures = features.NeedSetup()
	newSource := serv.mgr.MachineChecked(serv.enabledFeatures, enabledCalls)
	serv.baseSource.Store(newSource)
	serv.checkDone.Store(true)
	return nil
}

func (serv *Server) printMachineCheck(checkFilesInfo []*flatrpc.FileInfo, enabledCalls map[*prog.Syscall]bool,
	disabledCalls, transitivelyDisabled map[*prog.Syscall]string, features vminfo.Features) {
	buf := new(bytes.Buffer)
	if len(serv.cfg.Syscalls) != 0 || log.V(1) {
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
}

func (serv *Server) CreateInstance(name string, injectExec chan<- bool) {
	runner := &Runner{
		injectExec: injectExec,
		infoc:      make(chan chan []byte),
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
	serv.info[name] = VMState{StateBooting, time.Now()}
	serv.mu.Unlock()
}

// stopInstance prevents further request exchange requests.
// To make RPCServer fully forget an instance, shutdownInstance() must be called.
func (serv *Server) StopFuzzing(name string) {
	serv.mu.Lock()
	runner := serv.runners[name]
	runner.stopped = true
	conn := runner.conn
	serv.info[name] = VMState{StateStopping, time.Now()}
	serv.mu.Unlock()
	if conn != nil {
		conn.Close()
	}
}

func (serv *Server) ShutdownInstance(name string, crashed bool) ([]ExecRecord, []byte) {
	serv.mu.Lock()
	runner := serv.runners[name]
	delete(serv.runners, name)
	serv.info[name] = VMState{StateOffline, time.Now()}
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

func (serv *Server) DistributeSignalDelta(plus, minus signal.Signal) {
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

func (serv *Server) TriagedCorpus() {
	serv.triagedCorpus.Store(true)
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
func (serv *Server) foreachRunnerAsync(fn func(runner *Runner)) {
	serv.mu.Lock()
	defer serv.mu.Unlock()
	for _, runner := range serv.runners {
		if runner.conn != nil {
			go fn(runner)
		}
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
