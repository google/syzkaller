// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package rpcserver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/cover/backend"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/stat"
	"github.com/google/syzkaller/pkg/vminfo"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/vm/dispatcher"
)

type Config struct {
	vminfo.Config
	VMArch string
	VMType string
	RPC    string
	VMLess bool
	// Hash adjacent PCs to form fuzzing feedback signal (otherwise just use coverage PCs as signal).
	UseCoverEdges bool
	// Filter signal/comparisons against target kernel text/data ranges.
	// Disabled for gVisor/Starnix which are not Linux.
	FilterSignal      bool
	PrintMachineCheck bool
	// Abort early on syz-executor not replying to requests and print extra debugging information.
	DebugTimeouts bool
	Procs         int
	Slowdown      int
	pcBase        uint64
	localModules  []*vminfo.KernelModule
}

//go:generate ../../tools/mockery.sh --name Manager --output ./mocks
type Manager interface {
	MaxSignal() signal.Signal
	BugFrames() (leaks []string, races []string)
	MachineChecked(features flatrpc.Feature, syscalls map[*prog.Syscall]bool) queue.Source
	CoverageFilter(modules []*vminfo.KernelModule) []uint64
}

type Server interface {
	Listen() error
	Close() error
	Port() int
	TriagedCorpus()
	CreateInstance(id int, injectExec chan<- bool, updInfo dispatcher.UpdateInfo) chan error
	ShutdownInstance(id int, crashed bool, extraExecs ...report.ExecutorInfo) ([]ExecRecord, []byte)
	StopFuzzing(id int)
	DistributeSignalDelta(plus signal.Signal)
}

type server struct {
	cfg       *Config
	mgr       Manager
	serv      *flatrpc.Serv
	target    *prog.Target
	sysTarget *targets.Target
	timeouts  targets.Timeouts
	checker   *vminfo.Checker

	infoOnce         sync.Once
	checkDone        atomic.Bool
	checkFailures    int
	baseSource       *queue.DynamicSourceCtl
	setupFeatures    flatrpc.Feature
	canonicalModules *cover.Canonicalizer
	coverFilter      []uint64

	mu             sync.Mutex
	runners        map[int]*Runner
	execSource     *queue.Distributor
	triagedCorpus  atomic.Bool
	statVMRestarts *stat.Val
	*runnerStats
}

func New(cfg *mgrconfig.Config, mgr Manager, debug bool) (Server, error) {
	var pcBase uint64
	if cfg.KernelObj != "" {
		var err error
		pcBase, err = cover.GetPCBase(cfg)
		if err != nil {
			return nil, err
		}
	}
	sandbox, err := flatrpc.SandboxToFlags(cfg.Sandbox)
	if err != nil {
		return nil, err
	}
	features := flatrpc.AllFeatures
	if !cfg.Experimental.RemoteCover {
		features &= ^flatrpc.FeatureExtraCoverage
	}
	return newImpl(context.Background(), &Config{
		Config: vminfo.Config{
			Target:     cfg.Target,
			VMType:     cfg.Type,
			Features:   features,
			Syscalls:   cfg.Syscalls,
			Debug:      debug,
			Cover:      cfg.Cover,
			Sandbox:    sandbox,
			SandboxArg: cfg.SandboxArg,
		},
		VMArch: cfg.TargetVMArch,
		RPC:    cfg.RPC,
		VMLess: cfg.VMLess,
		// gVisor coverage is not a trace, so producing edges won't work.
		UseCoverEdges: cfg.Experimental.CoverEdges && cfg.Type != targets.GVisor,
		// gVisor/Starnix are not Linux, so filtering against Linux ranges won't work.
		FilterSignal:      cfg.Type != targets.GVisor && cfg.Type != targets.Starnix,
		PrintMachineCheck: true,
		Procs:             cfg.Procs,
		Slowdown:          cfg.Timeouts.Slowdown,
		pcBase:            pcBase,
		localModules:      cfg.LocalModules,
	}, mgr), nil
}

func newImpl(ctx context.Context, cfg *Config, mgr Manager) *server {
	// Note that we use VMArch, rather than Arch. We need the kernel address ranges and bitness.
	sysTarget := targets.Get(cfg.Target.OS, cfg.VMArch)
	cfg.Procs = min(cfg.Procs, prog.MaxPids)
	checker := vminfo.New(ctx, &cfg.Config)
	baseSource := queue.DynamicSource(checker)
	return &server{
		cfg:        cfg,
		mgr:        mgr,
		target:     cfg.Target,
		sysTarget:  sysTarget,
		timeouts:   sysTarget.Timeouts(cfg.Slowdown),
		runners:    make(map[int]*Runner),
		checker:    checker,
		baseSource: baseSource,
		execSource: queue.Distribute(queue.Retry(baseSource)),

		statVMRestarts: stat.New("vm restarts", "Total number of VM starts",
			stat.Rate{}, stat.NoGraph),
		runnerStats: &runnerStats{
			statExecRetries: stat.New("exec retries",
				"Number of times a test program was restarted because the first run failed",
				stat.Rate{}, stat.Graph("executor")),
			statExecutorRestarts: stat.New("executor restarts",
				"Number of times executor process was restarted", stat.Rate{}, stat.Graph("executor")),
			statExecBufferTooSmall: queue.StatExecBufferTooSmall,
			statExecs:              queue.StatExecs,
			statNoExecRequests:     queue.StatNoExecRequests,
			statNoExecDuration:     queue.StatNoExecDuration,
		},
	}
}

func (serv *server) Close() error {
	return serv.serv.Close()
}

func (serv *server) Listen() error {
	s, err := flatrpc.ListenAndServe(serv.cfg.RPC, serv.handleConn)
	if err != nil {
		return err
	}
	serv.serv = s
	return nil
}

func (serv *server) Port() int {
	return serv.serv.Addr.Port
}

func (serv *server) handleConn(conn *flatrpc.Conn) {
	connectReq, err := flatrpc.Recv[*flatrpc.ConnectRequestRaw](conn)
	if err != nil {
		log.Logf(1, "%s", err)
		return
	}
	id := int(connectReq.Id)
	log.Logf(1, "runner %v connected", id)

	if serv.cfg.VMLess {
		// There is no VM loop, so minic what it would do.
		serv.CreateInstance(id, nil, nil)
		defer func() {
			serv.StopFuzzing(id)
			serv.ShutdownInstance(id, true)
		}()
	} else if err := checkRevisions(connectReq, serv.cfg.Target); err != nil {
		log.Fatal(err)
	}
	serv.statVMRestarts.Add(1)

	serv.mu.Lock()
	runner := serv.runners[id]
	serv.mu.Unlock()
	if runner == nil {
		log.Logf(2, "unknown VM %v tries to connect", id)
		return
	}

	err = serv.handleRunnerConn(runner, conn)
	log.Logf(2, "runner %v: %v", id, err)
	runner.resultCh <- err
}

func (serv *server) handleRunnerConn(runner *Runner, conn *flatrpc.Conn) error {
	opts := &handshakeConfig{
		VMLess:   serv.cfg.VMLess,
		Files:    serv.checker.RequiredFiles(),
		Timeouts: serv.timeouts,
		Callback: serv.handleMachineInfo,
	}
	opts.LeakFrames, opts.RaceFrames = serv.mgr.BugFrames()
	if serv.checkDone.Load() {
		opts.Features = serv.setupFeatures
	} else {
		opts.Files = append(opts.Files, serv.checker.CheckFiles()...)
		opts.Globs = serv.target.RequiredGlobs()
		opts.Features = serv.cfg.Features
	}

	err := runner.Handshake(conn, opts)
	if err != nil {
		log.Logf(1, "%v", err)
		return err
	}

	if serv.triagedCorpus.Load() {
		if err := runner.SendCorpusTriaged(); err != nil {
			log.Logf(2, "%v", err)
			return err
		}
	}

	return serv.connectionLoop(runner)
}

func (serv *server) handleMachineInfo(infoReq *flatrpc.InfoRequestRawT) (handshakeResult, error) {
	modules, machineInfo, err := serv.checker.MachineInfo(infoReq.Files)
	if err != nil {
		log.Logf(0, "parsing of machine info failed: %v", err)
		if infoReq.Error == "" {
			infoReq.Error = err.Error()
		}
	}
	modules = backend.FixModules(serv.cfg.localModules, modules, serv.cfg.pcBase)
	if infoReq.Error != "" {
		log.Logf(0, "machine check failed: %v", infoReq.Error)
		serv.checkFailures++
		if serv.checkFailures == 10 {
			log.Fatalf("machine check failing")
		}
		return handshakeResult{}, errors.New("machine check failed")
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
	return handshakeResult{
		CovFilter:     canonicalizer.Decanonicalize(serv.coverFilter),
		MachineInfo:   machineInfo,
		Canonicalizer: canonicalizer,
	}, nil
}

func (serv *server) connectionLoop(runner *Runner) error {
	if serv.cfg.Cover {
		maxSignal := serv.mgr.MaxSignal().ToRaw()
		for len(maxSignal) != 0 {
			// Split coverage into batches to not grow the connection serialization
			// buffer too much (we don't want to grow it larger than what will be needed
			// to send programs).
			n := min(len(maxSignal), 50000)
			if err := runner.SendSignalUpdate(maxSignal[:n]); err != nil {
				return err
			}
			maxSignal = maxSignal[n:]
		}
	}

	queue.StatNumFuzzing.Add(1)
	defer queue.StatNumFuzzing.Add(-1)

	return runner.ConnectionLoop()
}

func checkRevisions(a *flatrpc.ConnectRequest, target *prog.Target) error {
	if target.Arch != a.Arch {
		return fmt.Errorf("mismatching manager/executor arches: %v vs %v", target.Arch, a.Arch)
	}
	if prog.GitRevision != a.GitRevision {
		return fmt.Errorf("mismatching manager/executor git revisions: %v vs %v",
			prog.GitRevision, a.GitRevision)
	}
	if target.Revision != a.SyzRevision {
		return fmt.Errorf("mismatching manager/executor system call descriptions: %v vs %v",
			target.Revision, a.SyzRevision)
	}
	return nil
}

func (serv *server) runCheck(checkFilesInfo []*flatrpc.FileInfo, checkFeatureInfo []*flatrpc.FeatureInfo) error {
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

func (serv *server) printMachineCheck(checkFilesInfo []*flatrpc.FileInfo, enabledCalls map[*prog.Syscall]bool,
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

func (serv *server) CreateInstance(id int, injectExec chan<- bool, updInfo dispatcher.UpdateInfo) chan error {
	runner := &Runner{
		id:            id,
		source:        serv.execSource,
		cover:         serv.cfg.Cover,
		coverEdges:    serv.cfg.UseCoverEdges,
		filterSignal:  serv.cfg.FilterSignal,
		debug:         serv.cfg.Debug,
		debugTimeouts: serv.cfg.DebugTimeouts,
		sysTarget:     serv.sysTarget,
		injectExec:    injectExec,
		infoc:         make(chan chan []byte),
		requests:      make(map[int64]*queue.Request),
		executing:     make(map[int64]bool),
		lastExec:      MakeLastExecuting(serv.cfg.Procs, 6),
		stats:         serv.runnerStats,
		procs:         serv.cfg.Procs,
		updInfo:       updInfo,
		resultCh:      make(chan error, 1),
	}
	serv.mu.Lock()
	defer serv.mu.Unlock()
	if serv.runners[id] != nil {
		panic(fmt.Sprintf("duplicate instance %v", id))
	}
	serv.runners[id] = runner
	return runner.resultCh
}

// stopInstance prevents further request exchange requests.
// To make RPCServer fully forget an instance, shutdownInstance() must be called.
func (serv *server) StopFuzzing(id int) {
	serv.mu.Lock()
	runner := serv.runners[id]
	serv.mu.Unlock()
	if runner.updInfo != nil {
		runner.updInfo(func(info *dispatcher.Info) {
			info.Status = "fuzzing is stopped"
		})
	}
	runner.Stop()
}

func (serv *server) ShutdownInstance(id int, crashed bool, extraExecs ...report.ExecutorInfo) ([]ExecRecord, []byte) {
	serv.mu.Lock()
	runner := serv.runners[id]
	delete(serv.runners, id)
	serv.mu.Unlock()
	return runner.Shutdown(crashed, extraExecs...), runner.MachineInfo()
}

func (serv *server) DistributeSignalDelta(plus signal.Signal) {
	plusRaw := plus.ToRaw()
	serv.foreachRunnerAsync(func(runner *Runner) {
		runner.SendSignalUpdate(plusRaw)
	})
}

func (serv *server) TriagedCorpus() {
	serv.triagedCorpus.Store(true)
	serv.foreachRunnerAsync(func(runner *Runner) {
		runner.SendCorpusTriaged()
	})
}

// foreachRunnerAsync runs callback fn for each connected runner asynchronously.
// If a VM has hanged w/o reading out the socket, we want to avoid blocking
// important goroutines on the send operations.
func (serv *server) foreachRunnerAsync(fn func(runner *Runner)) {
	serv.mu.Lock()
	defer serv.mu.Unlock()
	for _, runner := range serv.runners {
		if runner.Alive() {
			go fn(runner)
		}
	}
}
