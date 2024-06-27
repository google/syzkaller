// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package rpcserver

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"math/rand"
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
	setupFeatures    flatrpc.Feature
	canonicalModules *cover.Canonicalizer
	coverFilter      []uint64

	mu             sync.Mutex
	runners        map[string]*Runner
	info           map[string]VMState
	execSource     queue.Source
	triagedCorpus  atomic.Bool
	statVMRestarts *stats.Val
	*runnerStats
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
		statVMRestarts: stats.Create("vm restarts", "Total number of VM starts",
			stats.Rate{}, stats.NoGraph),
		runnerStats: &runnerStats{
			statExecRetries: stats.Create("exec retries",
				"Number of times a test program was restarted because the first run failed",
				stats.Rate{}, stats.Graph("executor")),
			statExecutorRestarts: stats.Create("executor restarts",
				"Number of times executor process was restarted", stats.Rate{}, stats.Graph("executor")),
			statExecBufferTooSmall: stats.Create("buffer too small",
				"Program serialization overflowed exec buffer", stats.NoGraph),
			statNoExecRequests: stats.Create("no exec requests",
				"Number of times fuzzer was stalled with no exec requests", stats.Rate{}),
			statNoExecDuration: stats.Create("no exec duration",
				"Total duration fuzzer was stalled with no exec requests (ns/sec)", stats.Rate{}),
		},
	}
	serv.runnerStats.statExecs = serv.StatExecs
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
	return runner.queryStatus()
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
			if err := runner.sendSignalUpdate(maxSignal[:n]); err != nil {
				return err
			}
			maxSignal = maxSignal[n:]
		}
	}

	serv.StatNumFuzzing.Add(1)
	defer serv.StatNumFuzzing.Add(-1)

	return runner.connectionLoop()
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
	enabledFeatures := features.Enabled()
	serv.setupFeatures = features.NeedSetup()
	newSource := serv.mgr.MachineChecked(enabledFeatures, enabledCalls)
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
		source:     serv.baseSource,
		cover:      serv.cfg.Cover,
		debug:      serv.cfg.Debug,
		injectExec: injectExec,
		infoc:      make(chan chan []byte),
		finished:   make(chan bool),
		requests:   make(map[int64]*queue.Request),
		executing:  make(map[int64]bool),
		lastExec:   MakeLastExecuting(serv.cfg.Procs, 6),
		rnd:        rand.New(rand.NewSource(time.Now().UnixNano())),
		stats:      serv.runnerStats,
		procs:      serv.cfg.Procs,
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
	return runner.shutdown(crashed)
}

func (serv *Server) DistributeSignalDelta(plus signal.Signal) {
	plusRaw := plus.ToRaw()
	serv.foreachRunnerAsync(func(runner *Runner) {
		runner.sendSignalUpdate(plusRaw)
	})
}

func (serv *Server) TriagedCorpus() {
	serv.triagedCorpus.Store(true)
	serv.foreachRunnerAsync(func(runner *Runner) {
		runner.sendStartLeakChecks()
	})
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
