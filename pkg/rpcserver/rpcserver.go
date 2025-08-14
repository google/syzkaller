// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package rpcserver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net/url"
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
	"golang.org/x/sync/errgroup"
)

type Config struct {
	vminfo.Config
	Stats

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
	DebugTimeouts   bool
	Procs           int
	Slowdown        int
	ProcRestartFreq int
	pcBase          uint64
	localModules    []*vminfo.KernelModule

	// RPCServer closes the channel once the machine check has begun. Used for fault injection during testing.
	machineCheckStarted chan struct{}
}

type RemoteConfig struct {
	*mgrconfig.Config
	Manager Manager
	Stats   Stats
	Debug   bool
}

type Manager interface {
	MaxSignal() signal.Signal
	BugFrames() (leaks []string, races []string)
	MachineChecked(features flatrpc.Feature, syscalls map[*prog.Syscall]bool) (queue.Source, error)
	CoverageFilter(modules []*vminfo.KernelModule) ([]uint64, error)
}

type Server interface {
	Listen() error
	Close() error
	Port() int
	TriagedCorpus()
	Serve(context.Context) error
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
	onHandshake      chan *handshakeResult
	baseSource       *queue.DynamicSourceCtl
	setupFeatures    flatrpc.Feature
	canonicalModules *cover.Canonicalizer
	coverFilter      []uint64

	mu            sync.Mutex
	runners       map[int]*Runner
	execSource    *queue.Distributor
	triagedCorpus atomic.Bool

	Stats
	*runnerStats
}

type Stats struct {
	StatExecs      *stat.Val
	StatNumFuzzing *stat.Val
	StatVMRestarts *stat.Val
	StatModules    *stat.Val
}

func NewStats() Stats {
	return NewNamedStats("")
}

func NewNamedStats(name string) Stats {
	suffix, linkSuffix := "", ""
	if name != "" {
		suffix = " [" + name + "]"
		linkSuffix = "?pool=" + url.QueryEscape(name)
	}
	return Stats{
		StatExecs: stat.New("exec total"+suffix, "Total test program executions",
			stat.Console, stat.Rate{}, stat.Prometheus("syz_exec_total"+name),
		),
		StatNumFuzzing: stat.New("fuzzing VMs"+suffix,
			"Number of VMs that are currently fuzzing", stat.Graph("fuzzing VMs"),
			stat.Link("/vms"+linkSuffix),
		),
		StatVMRestarts: stat.New("vm restarts"+suffix, "Total number of VM starts",
			stat.Rate{}, stat.NoGraph),
		StatModules: stat.New("modules"+suffix, "Number of loaded kernel modules",
			stat.NoGraph, stat.Link("/modules"+linkSuffix)),
	}
}

func New(cfg *RemoteConfig) (Server, error) {
	var pcBase uint64
	if cfg.KernelObj != "" {
		var err error
		pcBase, err = cover.GetPCBase(cfg.Config)
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
	return newImpl(&Config{
		Config: vminfo.Config{
			Target:     cfg.Target,
			VMType:     cfg.Type,
			Features:   features,
			Syscalls:   cfg.Syscalls,
			Debug:      cfg.Debug,
			Cover:      cfg.Cover,
			Sandbox:    sandbox,
			SandboxArg: cfg.SandboxArg,
		},
		Stats:  cfg.Stats,
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
		ProcRestartFreq:   cfg.Experimental.ProcRestartFreq,
		pcBase:            pcBase,
		localModules:      cfg.LocalModules,
	}, cfg.Manager), nil
}

func newImpl(cfg *Config, mgr Manager) *server {
	// Note that we use VMArch, rather than Arch. We need the kernel address ranges and bitness.
	sysTarget := targets.Get(cfg.Target.OS, cfg.VMArch)
	cfg.Procs = min(cfg.Procs, prog.MaxPids)
	checker := vminfo.New(&cfg.Config)
	baseSource := queue.DynamicSource(checker)
	return &server{
		cfg:         cfg,
		mgr:         mgr,
		target:      cfg.Target,
		sysTarget:   sysTarget,
		timeouts:    sysTarget.Timeouts(cfg.Slowdown),
		runners:     make(map[int]*Runner),
		checker:     checker,
		baseSource:  baseSource,
		execSource:  queue.Distribute(queue.Retry(baseSource)),
		onHandshake: make(chan *handshakeResult, 1),

		Stats: cfg.Stats,
		runnerStats: &runnerStats{
			statExecRetries: stat.New("exec retries",
				"Number of times a test program was restarted because the first run failed",
				stat.Rate{}, stat.Graph("executor")),
			statExecutorRestarts: stat.New("executor restarts",
				"Number of times executor process was restarted", stat.Rate{}, stat.Graph("executor")),
			statExecBufferTooSmall: queue.StatExecBufferTooSmall,
			statExecs:              cfg.Stats.StatExecs,
			statNoExecRequests:     queue.StatNoExecRequests,
			statNoExecDuration:     queue.StatNoExecDuration,
		},
	}
}

func (serv *server) Close() error {
	return serv.serv.Close()
}

func (serv *server) Listen() error {
	s, err := flatrpc.Listen(serv.cfg.RPC)
	if err != nil {
		return err
	}
	serv.serv = s
	return nil
}

// Used for errors incompatible with further RPCServer operation.
var errFatal = errors.New("aborting RPC server")

func (serv *server) Serve(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		return serv.serv.Serve(ctx, func(ctx context.Context, conn *flatrpc.Conn) error {
			err := serv.handleConn(ctx, conn)
			if err != nil && !errors.Is(err, errFatal) {
				log.Logf(2, "%v", err)
				return nil
			}
			return err
		})
	})
	g.Go(func() error {
		var info *handshakeResult
		select {
		case <-ctx.Done():
			return nil
		case info = <-serv.onHandshake:
		}
		// We run the machine check specifically from the top level context,
		// not from the per-connection one.
		return serv.runCheck(ctx, info)
	})
	return g.Wait()
}

func (serv *server) Port() int {
	return serv.serv.Addr.Port
}

// Must be simple enough to not require adding dependencies to the executor.
func authHash(value uint64) uint64 {
	prime1 := uint64(73856093)
	prime2 := uint64(83492791)
	hashValue := (value * prime1) ^ prime2

	return hashValue
}

func (serv *server) handleConn(ctx context.Context, conn *flatrpc.Conn) error {
	// Use a random cookie, because we do not want the fuzzer to accidentally guess it and DDoS multiple managers.
	helloCookie := rand.Uint64()
	expectCookie := authHash(helloCookie)
	connectHello := &flatrpc.ConnectHello{
		Cookie: helloCookie,
	}

	if err := flatrpc.Send(conn, connectHello); err != nil {
		// The other side is not an executor.
		return fmt.Errorf("failed to establish connection with a remote runner")
	}

	connectReq, err := flatrpc.Recv[*flatrpc.ConnectRequestRaw](conn)
	if err != nil {
		return err
	}
	id := int(connectReq.Id)

	if connectReq.Cookie != expectCookie {
		return fmt.Errorf("client failed to respond with a valid cookie: %v (expected %v)", connectReq.Cookie, expectCookie)
	}

	// From now on, assume that the client is well-behaving.
	log.Logf(1, "runner %v connected", id)

	if serv.cfg.VMLess {
		// There is no VM loop, so mimic what it would do.
		serv.CreateInstance(id, nil, nil)
		defer func() {
			serv.StopFuzzing(id)
			serv.ShutdownInstance(id, true)
		}()
	} else if err := checkRevisions(connectReq, serv.cfg.Target); err != nil {
		return err
	}
	serv.StatVMRestarts.Add(1)

	serv.mu.Lock()
	runner := serv.runners[id]
	serv.mu.Unlock()
	if runner == nil {
		return fmt.Errorf("unknown VM %v tries to connect", id)
	}

	err = serv.handleRunnerConn(ctx, runner, conn)
	log.Logf(2, "runner %v: %v", id, err)

	runner.resultCh <- err
	return nil
}

const defaultProcRestartFreq = 600

func (serv *server) handleRunnerConn(ctx context.Context, runner *Runner, conn *flatrpc.Conn) error {
	opts := &handshakeConfig{
		VMLess:          serv.cfg.VMLess,
		Files:           serv.checker.RequiredFiles(),
		Timeouts:        serv.timeouts,
		Callback:        serv.handleMachineInfo,
		ProcRestartFreq: defaultProcRestartFreq,
	}
	if serv.cfg.ProcRestartFreq != 0 {
		opts.ProcRestartFreq = serv.cfg.ProcRestartFreq
	}
	opts.LeakFrames, opts.RaceFrames = serv.mgr.BugFrames()
	if serv.checkDone.Load() {
		opts.Features = serv.setupFeatures
	} else {
		opts.Files = append(opts.Files, serv.checker.CheckFiles()...)
		opts.Features = serv.cfg.Features
	}

	info, err := runner.Handshake(conn, opts)
	if err != nil {
		log.Logf(1, "%v", err)
		return err
	}

	select {
	case serv.onHandshake <- &info:
	default:
	}

	if serv.triagedCorpus.Load() {
		if err := runner.SendCorpusTriaged(); err != nil {
			return err
		}
	}
	return serv.connectionLoop(ctx, runner)
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
			return handshakeResult{}, fmt.Errorf("%w: machine check failed too many times", errFatal)
		}
		return handshakeResult{}, errors.New("machine check failed")
	}
	var retErr error
	serv.infoOnce.Do(func() {
		serv.StatModules.Add(len(modules))
		serv.canonicalModules = cover.NewCanonicalizer(modules, serv.cfg.Cover)
		var err error
		serv.coverFilter, err = serv.mgr.CoverageFilter(modules)
		if err != nil {
			retErr = fmt.Errorf("%w: %w", errFatal, err)
			return
		}
	})
	if retErr != nil {
		return handshakeResult{}, retErr
	}
	// Flatbuffers don't do deep copy of byte slices,
	// so clone manually since we may later pass it a goroutine.
	for _, file := range infoReq.Files {
		file.Data = slices.Clone(file.Data)
	}
	canonicalizer := serv.canonicalModules.NewInstance(modules)
	return handshakeResult{
		CovFilter:     canonicalizer.Decanonicalize(serv.coverFilter),
		MachineInfo:   machineInfo,
		Canonicalizer: canonicalizer,
		Files:         infoReq.Files,
		Features:      infoReq.Features,
	}, nil
}

func (serv *server) connectionLoop(baseCtx context.Context, runner *Runner) error {
	// To "cancel" the runner's loop we need to call runner.Stop().
	// At the same time, we don't want to leak the goroutine that monitors it,
	// so we derive a new context and cancel it on function exit.
	ctx, cancel := context.WithCancel(baseCtx)
	defer cancel()
	go func() {
		<-ctx.Done()
		runner.Stop()
	}()

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

	serv.StatNumFuzzing.Add(1)
	defer serv.StatNumFuzzing.Add(-1)

	return runner.ConnectionLoop()
}

func checkRevisions(a *flatrpc.ConnectRequest, target *prog.Target) error {
	if target.Arch != a.Arch {
		return fmt.Errorf("%w: mismatching manager/executor arches: %v vs %v (full request: `%#v`)",
			errFatal, target.Arch, a.Arch, a)
	}
	if prog.GitRevision != a.GitRevision {
		return fmt.Errorf("%w: mismatching manager/executor git revisions: %v vs %v",
			errFatal, prog.GitRevision, a.GitRevision)
	}
	if target.Revision != a.SyzRevision {
		return fmt.Errorf("%w: mismatching manager/executor system call descriptions: %v vs %v",
			errFatal, target.Revision, a.SyzRevision)
	}
	return nil
}

func (serv *server) runCheck(ctx context.Context, info *handshakeResult) error {
	if serv.cfg.machineCheckStarted != nil {
		close(serv.cfg.machineCheckStarted)
	}
	enabledCalls, disabledCalls, features, checkErr := serv.checker.Run(ctx, info.Files, info.Features)
	if checkErr == vminfo.ErrAborted {
		return nil
	}

	enabledCalls, transitivelyDisabled := serv.target.TransitivelyEnabledCalls(enabledCalls)
	// Note: need to print disbled syscalls before failing due to an error.
	// This helps to debug "all system calls are disabled".
	if serv.cfg.PrintMachineCheck {
		serv.printMachineCheck(info.Files, enabledCalls, disabledCalls, transitivelyDisabled, features)
	}
	if checkErr != nil {
		return checkErr
	}
	enabledFeatures := features.Enabled()
	serv.setupFeatures = features.NeedSetup()
	newSource, err := serv.mgr.MachineChecked(enabledFeatures, enabledCalls)
	if err != nil {
		return err
	}
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
		hanged:        make(map[int64]bool),
		// Executor may report proc IDs that are larger than serv.cfg.Procs.
		lastExec: MakeLastExecuting(prog.MaxPids, 6),
		stats:    serv.runnerStats,
		procs:    serv.cfg.Procs,
		updInfo:  updInfo,
		resultCh: make(chan error, 1),
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
