// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/asset"
	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/gce"
	"github.com/google/syzkaller/pkg/ifaceprobe"
	"github.com/google/syzkaller/pkg/image"
	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/kfuzztest"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/manager"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	crash_pkg "github.com/google/syzkaller/pkg/report/crash"
	"github.com/google/syzkaller/pkg/repro"
	"github.com/google/syzkaller/pkg/rpcserver"
	"github.com/google/syzkaller/pkg/runtest"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/stat"
	"github.com/google/syzkaller/pkg/vminfo"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/vm"
	"github.com/google/syzkaller/vm/dispatcher"
)

var (
	flagConfig = flag.String("config", "", "configuration file")
	flagDebug  = flag.Bool("debug", false, "dump all VM output to console")
	flagBench  = flag.String("bench", "", "write execution statistics into this file periodically")
	flagMode   = flag.String("mode", ModeFuzzing.Name, modesDescription())
	flagTests  = flag.String("tests", "", "prefix to match test file names (for -mode run-tests)")
)

type Manager struct {
	cfg             *mgrconfig.Config
	mode            *Mode
	vmPool          *vm.Pool
	pool            *vm.Dispatcher
	target          *prog.Target
	sysTarget       *targets.Target
	reporter        *report.Reporter
	crashStore      *manager.CrashStore
	serv            rpcserver.Server
	http            *manager.HTTPServer
	servStats       rpcserver.Stats
	corpus          *corpus.Corpus
	corpusDB        *db.DB
	corpusDBMu      sync.Mutex // for concurrent operations on corpusDB
	corpusPreload   chan []fuzzer.Candidate
	firstConnect    atomic.Int64 // unix time, or 0 if not connected
	crashTypes      map[string]bool
	enabledFeatures flatrpc.Feature
	checkDone       atomic.Bool
	reportGenerator *manager.ReportGeneratorWrapper
	fresh           bool
	coverFilters    manager.CoverageFilters

	dash *dashapi.Dashboard
	// This is specifically separated from dash, so that we can keep dash = nil when
	// cfg.DashboardOnlyRepro is set, so that we don't accidentially use dash for anything.
	dashRepro *dashapi.Dashboard

	mu             sync.Mutex
	fuzzer         atomic.Pointer[fuzzer.Fuzzer]
	snapshotSource *queue.Distributor
	phase          int

	disabledHashes   map[string]struct{}
	newRepros        [][]byte
	lastMinCorpus    int
	memoryLeakFrames map[string]bool
	dataRaceFrames   map[string]bool
	saturatedCalls   map[string]bool

	externalReproQueue chan *manager.Crash
	crashes            chan *manager.Crash

	benchMu   sync.Mutex
	benchFile *os.File

	assetStorage *asset.Storage
	fsckChecker  image.FsckChecker

	reproLoop *manager.ReproLoop

	Stats
}

type Mode struct {
	Name                  string
	Description           string
	UseDashboard          bool // the mode connects to dashboard/hub
	LoadCorpus            bool // the mode needs to load the corpus
	ExitAfterMachineCheck bool // exit with 0 status when machine check is done
	// Exit with non-zero status and save the report to workdir/report.json if any kernel crash happens.
	FailOnCrashes bool
	CheckConfig   func(cfg *mgrconfig.Config) error
}

var (
	ModeFuzzing = &Mode{
		Name:         "fuzzing",
		Description:  `the default continuous fuzzing mode`,
		UseDashboard: true,
		LoadCorpus:   true,
	}
	ModeSmokeTest = &Mode{
		Name: "smoke-test",
		Description: `run smoke test for syzkaller+kernel
	The test consists of booting VMs and running some simple test programs
	to ensure that fuzzing can proceed in general. After completing the test
	the process exits and the exit status indicates success/failure.
	If the kernel oopses during testing, the report is saved to workdir/report.json.`,
		ExitAfterMachineCheck: true,
		FailOnCrashes:         true,
	}
	ModeCorpusTriage = &Mode{
		Name: "corpus-triage",
		Description: `triage corpus and exit
	This is useful mostly for benchmarking with testbed.`,
		LoadCorpus: true,
	}
	ModeCorpusRun = &Mode{
		Name:        "corpus-run",
		Description: `continuously run the corpus programs`,
		LoadCorpus:  true,
	}
	ModeRunTests = &Mode{
		Name: "run-tests",
		Description: `run unit tests
	Run sys/os/test/* tests in various modes and print results.`,
	}
	ModeIfaceProbe = &Mode{
		Name: "iface-probe",
		Description: `run dynamic part of kernel interface auto-extraction
	When the probe is finished, manager writes the result to workdir/interfaces.json file and exits.`,
		CheckConfig: func(cfg *mgrconfig.Config) error {
			if cfg.Snapshot {
				return fmt.Errorf("snapshot mode is not supported")
			}
			if cfg.Sandbox != "none" {
				return fmt.Errorf("sandbox \"%v\" is not supported (only \"none\")", cfg.Sandbox)
			}
			if !cfg.Cover {
				return fmt.Errorf("coverage is required")
			}
			return nil
		},
	}

	modes = []*Mode{
		ModeFuzzing,
		ModeSmokeTest,
		ModeCorpusTriage,
		ModeCorpusRun,
		ModeRunTests,
		ModeIfaceProbe,
	}
)

func modesDescription() string {
	desc := "mode of operation, one of:\n"
	for _, mode := range modes {
		desc += fmt.Sprintf(" - %v: %v\n", mode.Name, mode.Description)
	}
	return desc
}

const (
	// Just started, nothing done yet.
	phaseInit = iota
	// Corpus is loaded and machine is checked.
	phaseLoadedCorpus
	// Triaged all inputs from corpus.
	// This is when we start querying hub and minimizing persistent corpus.
	phaseTriagedCorpus
	// Done the first request to hub.
	phaseQueriedHub
	// Triaged all new inputs from hub.
	// This is when we start reproducing crashes.
	phaseTriagedHub
)

func main() {
	flag.Parse()
	if !prog.GitRevisionKnown() {
		log.Fatalf("bad syz-manager build: build with make, run bin/syz-manager")
	}
	log.EnableLogCaching(1000, 1<<20)
	cfg, err := mgrconfig.LoadFile(*flagConfig)
	if err != nil {
		log.Fatalf("%v", err)
	}
	if cfg.DashboardAddr != "" {
		// This lets better distinguish logs of individual syz-manager instances.
		log.SetName(cfg.Name)
	}
	var mode *Mode
	for _, m := range modes {
		if *flagMode == m.Name {
			mode = m
			break
		}
	}
	if mode == nil {
		flag.PrintDefaults()
		log.Fatalf("unknown mode: %v", *flagMode)
	}
	if mode.CheckConfig != nil {
		if err := mode.CheckConfig(cfg); err != nil {
			log.Fatalf("%v mode: %v", mode.Name, err)
		}
	}
	if !mode.UseDashboard {
		cfg.DashboardClient = ""
		cfg.HubClient = ""
	}
	if cfg.Experimental.EnableKFuzzTest {
		vmLinuxPath := path.Join(cfg.KernelObj, cfg.SysTarget.KernelObject)
		log.Log(0, "enabling KFuzzTest targets")
		_, err := kfuzztest.ActivateKFuzzTargets(cfg.Target, vmLinuxPath)
		if err != nil {
			log.Fatalf("failed to enable KFuzzTest targets: %v", err)
		}
	}
	RunManager(mode, cfg)
}

func RunManager(mode *Mode, cfg *mgrconfig.Config) {
	var vmPool *vm.Pool
	if !cfg.VMLess {
		var err error
		vmPool, err = vm.Create(cfg, *flagDebug)
		if err != nil {
			log.Fatalf("%v", err)
		}
		defer vmPool.Close()
	}

	osutil.MkdirAll(cfg.Workdir)

	reporter, err := report.NewReporter(cfg)
	if err != nil {
		log.Fatalf("%v", err)
	}

	mgr := &Manager{
		cfg:                cfg,
		mode:               mode,
		vmPool:             vmPool,
		corpusPreload:      make(chan []fuzzer.Candidate),
		target:             cfg.Target,
		sysTarget:          cfg.SysTarget,
		reporter:           reporter,
		crashStore:         manager.NewCrashStore(cfg),
		crashTypes:         make(map[string]bool),
		disabledHashes:     make(map[string]struct{}),
		memoryLeakFrames:   make(map[string]bool),
		dataRaceFrames:     make(map[string]bool),
		fresh:              true,
		externalReproQueue: make(chan *manager.Crash, 10),
		crashes:            make(chan *manager.Crash, 10),
		saturatedCalls:     make(map[string]bool),
		reportGenerator:    manager.ReportGeneratorCache(cfg),
	}
	if *flagDebug {
		mgr.cfg.Procs = 1
	}
	mgr.http = &manager.HTTPServer{
		// Note that if cfg.HTTP == "", we don't start the server.
		Cfg:        cfg,
		StartTime:  time.Now(),
		CrashStore: mgr.crashStore,
	}

	mgr.initStats()
	if mgr.mode.LoadCorpus {
		go mgr.preloadCorpus()
	} else {
		close(mgr.corpusPreload)
	}

	// Create RPC server for fuzzers.
	mgr.servStats = rpcserver.NewStats()
	rpcCfg := &rpcserver.RemoteConfig{
		Config:  mgr.cfg,
		Manager: mgr,
		Stats:   mgr.servStats,
		Debug:   *flagDebug,
	}
	mgr.serv, err = rpcserver.New(rpcCfg)
	if err != nil {
		log.Fatalf("failed to create rpc server: %v", err)
	}
	if err := mgr.serv.Listen(); err != nil {
		log.Fatalf("failed to start rpc server: %v", err)
	}
	ctx := vm.ShutdownCtx()
	go func() {
		err := mgr.serv.Serve(ctx)
		if err != nil {
			log.Fatalf("%s", err)
		}
	}()
	log.Logf(0, "serving rpc on tcp://%v", mgr.serv.Port())

	if cfg.DashboardAddr != "" {
		opts := []dashapi.DashboardOpts{}
		if cfg.DashboardUserAgent != "" {
			opts = append(opts, dashapi.UserAgent(cfg.DashboardUserAgent))
		}
		dash, err := dashapi.New(cfg.DashboardClient, cfg.DashboardAddr, cfg.DashboardKey, opts...)
		if err != nil {
			log.Fatalf("failed to create dashapi connection: %v", err)
		}
		mgr.dashRepro = dash
		if !cfg.DashboardOnlyRepro {
			mgr.dash = dash
		}
	}

	if !cfg.AssetStorage.IsEmpty() {
		mgr.assetStorage, err = asset.StorageFromConfig(cfg.AssetStorage, mgr.dash)
		if err != nil {
			log.Fatalf("failed to init asset storage: %v", err)
		}
	}

	if *flagBench != "" {
		mgr.initBench()
	}

	go mgr.heartbeatLoop()
	if mgr.mode != ModeSmokeTest {
		osutil.HandleInterrupts(vm.Shutdown)
	}
	if mgr.vmPool == nil {
		log.Logf(0, "no VMs started (type=none)")
		log.Logf(0, "you are supposed to start syz-executor manually as:")
		log.Logf(0, "syz-executor runner local manager.ip %v", mgr.serv.Port())
		<-vm.Shutdown
		return
	}
	mgr.pool = vm.NewDispatcher(mgr.vmPool, mgr.fuzzerInstance)
	mgr.http.Pool = mgr.pool
	reproVMs := max(0, mgr.vmPool.Count()-mgr.cfg.FuzzingVMs)
	mgr.reproLoop = manager.NewReproLoop(mgr, reproVMs, mgr.cfg.DashboardOnlyRepro)
	mgr.http.ReproLoop = mgr.reproLoop
	mgr.http.TogglePause = mgr.pool.TogglePause

	if mgr.cfg.HTTP != "" {
		go func() {
			err := mgr.http.Serve(ctx)
			if err != nil {
				log.Fatalf("failed to serve HTTP: %v", err)
			}
		}()
	}
	go mgr.trackUsedFiles()
	go mgr.processFuzzingResults(ctx)
	mgr.pool.Loop(ctx)
}

// Exit successfully in special operation modes.
func (mgr *Manager) exit(reason string) {
	log.Logf(0, "%v finished, shutting down...", reason)
	mgr.writeBench()
	close(vm.Shutdown)
	time.Sleep(10 * time.Second)
	os.Exit(0)
}

func (mgr *Manager) heartbeatLoop() {
	lastTime := time.Now()
	for now := range time.NewTicker(10 * time.Second).C {
		diff := int(now.Sub(lastTime))
		lastTime = now
		if mgr.firstConnect.Load() == 0 {
			continue
		}
		mgr.statFuzzingTime.Add(diff * mgr.servStats.StatNumFuzzing.Val())
		buf := new(bytes.Buffer)
		for _, stat := range stat.Collect(stat.Console) {
			fmt.Fprintf(buf, "%v=%v ", stat.Name, stat.Value)
		}
		log.Logf(0, "%s", buf.String())
	}
}

func (mgr *Manager) initBench() {
	f, err := os.OpenFile(*flagBench, os.O_WRONLY|os.O_CREATE|os.O_EXCL, osutil.DefaultFilePerm)
	if err != nil {
		log.Fatalf("failed to open bench file: %v", err)
	}
	mgr.benchFile = f
	go func() {
		for range time.NewTicker(time.Minute).C {
			mgr.writeBench()
		}
	}()
}

func (mgr *Manager) writeBench() {
	if mgr.benchFile == nil {
		return
	}
	mgr.benchMu.Lock()
	defer mgr.benchMu.Unlock()
	vals := make(map[string]int)
	for _, stat := range stat.Collect(stat.All) {
		vals[stat.Name] = stat.V
	}
	data, err := json.MarshalIndent(vals, "", "  ")
	if err != nil {
		log.Fatalf("failed to serialize bench data")
	}
	if _, err := mgr.benchFile.Write(append(data, '\n')); err != nil {
		log.Fatalf("failed to write bench data")
	}
}

func (mgr *Manager) processFuzzingResults(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case crash := <-mgr.crashes:
			needRepro := mgr.saveCrash(crash)
			if mgr.cfg.Reproduce && needRepro {
				mgr.reproLoop.Enqueue(crash)
			}
		case err := <-mgr.pool.BootErrors:
			crash := mgr.convertBootError(err)
			if crash != nil {
				mgr.saveCrash(crash)
			}
		case crash := <-mgr.externalReproQueue:
			if mgr.NeedRepro(crash) {
				mgr.reproLoop.Enqueue(crash)
			}
		}
	}
}

func (mgr *Manager) convertBootError(err error) *manager.Crash {
	var bootErr vm.BootErrorer
	if errors.As(err, &bootErr) {
		title, output := bootErr.BootError()
		rep := mgr.reporter.Parse(output)
		if rep != nil && rep.Type == crash_pkg.UnexpectedReboot {
			// Avoid detecting any boot crash as "unexpected kernel reboot".
			rep = mgr.reporter.ParseFrom(output, rep.SkipPos)
		}
		if rep == nil {
			rep = &report.Report{
				Title:  title,
				Output: output,
			}
		}
		return &manager.Crash{
			Report: rep,
		}
	}
	return nil
}

func reportReproError(err error) {
	shutdown := false
	select {
	case <-vm.Shutdown:
		shutdown = true
	default:
	}

	if errors.Is(err, repro.ErrEmptyCrashLog) {
		// The kernel could have crashed before we executed any programs.
		log.Logf(0, "repro failed: %v", err)
		return
	} else if errors.Is(err, repro.ErrNoVMs) || errors.Is(err, context.Canceled) {
		// This error is to be expected if we're shutting down.
		if shutdown {
			return
		}
	}
	// Report everything else as errors.
	log.Errorf("repro failed: %v", err)
}

func (mgr *Manager) RunRepro(ctx context.Context, crash *manager.Crash) *manager.ReproResult {
	res, stats, err := repro.Run(ctx, crash.Output, repro.Environment{
		Config:   mgr.cfg,
		Features: mgr.enabledFeatures,
		Reporter: mgr.reporter,
		Pool:     mgr.pool,
	})
	ret := &manager.ReproResult{
		Crash: crash,
		Repro: res,
		Stats: stats,
		Err:   err,
	}
	if err == nil && res != nil && mgr.cfg.StraceBin != "" {
		const straceAttempts = 2
		for i := 1; i <= straceAttempts; i++ {
			strace := repro.RunStrace(res, mgr.cfg, mgr.reporter, mgr.pool)
			sameBug := strace.IsSameBug(res)
			log.Logf(0, "strace run attempt %d/%d for '%s': same bug %v, error %v",
				i, straceAttempts, res.Report.Title, sameBug, strace.Error)
			// We only want to save strace output if it resulted in the same bug.
			// Otherwise, it will be hard to reproduce on syzbot and will confuse users.
			if sameBug {
				ret.Strace = strace
				break
			}
		}
	}

	mgr.processRepro(ret)

	return ret
}

func (mgr *Manager) processRepro(res *manager.ReproResult) {
	if res.Err != nil {
		reportReproError(res.Err)
	}
	if res.Repro == nil {
		if res.Crash.Title == "" {
			log.Logf(1, "repro '%v' not from dashboard, so not reporting the failure",
				res.Crash.FullTitle())
		} else {
			log.Logf(1, "report repro failure of '%v'", res.Crash.Title)
			mgr.saveFailedRepro(res.Crash.Report, res.Stats)
		}
	} else {
		mgr.saveRepro(res)
	}
}

func (mgr *Manager) preloadCorpus() {
	info, err := manager.LoadSeeds(mgr.cfg, false)
	if err != nil {
		log.Fatalf("failed to load corpus: %v", err)
	}
	mgr.fresh = info.Fresh
	mgr.corpusDB = info.CorpusDB
	mgr.corpusPreload <- info.Candidates
}

func (mgr *Manager) loadCorpus(enabledSyscalls map[*prog.Syscall]bool) []fuzzer.Candidate {
	ret := manager.FilterCandidates(<-mgr.corpusPreload, enabledSyscalls, true)
	if mgr.cfg.PreserveCorpus {
		for _, hash := range ret.ModifiedHashes {
			// This program contains a disabled syscall.
			// We won't execute it, but remember its hash so
			// it is not deleted during minimization.
			mgr.disabledHashes[hash] = struct{}{}
		}
	}
	// Let's favorize smaller programs, otherwise the poorly minimized ones may overshadow the rest.
	sort.SliceStable(ret.Candidates, func(i, j int) bool {
		return len(ret.Candidates[i].Prog.Calls) < len(ret.Candidates[j].Prog.Calls)
	})
	reminimized := ret.ReminimizeSubset()
	resmashed := ret.ResmashSubset()
	log.Logf(0, "%-24v: %v (%v seeds), %d to be reminimized, %d to be resmashed",
		"corpus", len(ret.Candidates), ret.SeedCount, reminimized, resmashed)
	return ret.Candidates
}

func (mgr *Manager) fuzzerInstance(ctx context.Context, inst *vm.Instance, updInfo dispatcher.UpdateInfo) {
	mgr.mu.Lock()
	serv := mgr.serv
	mgr.mu.Unlock()
	if serv == nil {
		// We're in the process of switching off the RPCServer.
		return
	}
	injectExec := make(chan bool, 10)
	serv.CreateInstance(inst.Index(), injectExec, updInfo)

	reps, vmInfo, err := mgr.runInstanceInner(ctx, inst,
		vm.WithExitCondition(vm.ExitTimeout),
		vm.WithInjectExecuting(injectExec),
		vm.WithEarlyFinishCb(func() {
			// Depending on the crash type and kernel config, fuzzing may continue
			// running for several seconds even after kernel has printed a crash report.
			// This litters the log, and we want to prevent it.
			serv.StopFuzzing(inst.Index())
		}))
	var extraExecs []report.ExecutorInfo
	var rep *report.Report
	if len(reps) != 0 {
		rep = reps[0]
	}
	if rep != nil && rep.Executor != nil {
		extraExecs = []report.ExecutorInfo{*rep.Executor}
	}
	var memoryDump string
	if mgr.cfg.MemoryDump && rep != nil {
		memoryDump = mgr.extractMemoryDump(inst, rep)
	}
	lastExec, machineInfo := serv.ShutdownInstance(inst.Index(), rep != nil, extraExecs...)
	if rep != nil {
		rpcserver.PrependExecuting(rep, lastExec)
		if len(vmInfo) != 0 {
			machineInfo = append(append(vmInfo, '\n'), machineInfo...)
		}
		rep.MachineInfo = machineInfo
	}
	if err == nil && rep != nil {
		mgr.crashes <- &manager.Crash{
			InstanceIndex: inst.Index(),
			Report:        rep,
			TailReports:   reps[1:],
			MemoryDump:    memoryDump,
		}
	}
	if err != nil {
		log.Logf(1, "VM %v: failed with error: %v", inst.Index(), err)
	}
}

func (mgr *Manager) runInstanceInner(ctx context.Context, inst *vm.Instance, opts ...func(*vm.RunOptions),
) ([]*report.Report, []byte, error) {
	fwdAddr, err := inst.Forward(mgr.serv.Port())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to setup port forwarding: %w", err)
	}

	// If ExecutorBin is provided, it means that syz-executor is already in the image,
	// so no need to copy it.
	executorBin := mgr.sysTarget.ExecutorBin
	if executorBin == "" {
		executorBin, err = inst.Copy(mgr.cfg.ExecutorBin)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to copy binary: %w", err)
		}
	}

	// Run the fuzzer binary.
	start := time.Now()

	host, port, err := net.SplitHostPort(fwdAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse manager's address")
	}
	cmd := fmt.Sprintf("%v runner %v %v %v", executorBin, inst.Index(), host, port)
	ctxTimeout, cancel := context.WithTimeout(ctx, mgr.cfg.Timeouts.VMRunningTime)
	defer cancel()
	_, reps, err := inst.Run(ctxTimeout, mgr.reporter, cmd, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to run fuzzer: %w", err)
	}
	if len(reps) == 0 {
		// This is the only "OK" outcome.
		log.Logf(0, "VM %v: running for %v, restarting", inst.Index(), time.Since(start))
		return nil, nil, nil
	}
	vmInfo, err := inst.Info()
	if err != nil {
		vmInfo = []byte(fmt.Sprintf("error getting VM info: %v\n", err))
	}
	return reps, vmInfo, nil
}

func (mgr *Manager) emailCrash(crash *manager.Crash) {
	if len(mgr.cfg.EmailAddrs) == 0 {
		return
	}
	args := []string{"-s", "syzkaller: " + crash.Title}
	args = append(args, mgr.cfg.EmailAddrs...)
	log.Logf(0, "sending email to %v", mgr.cfg.EmailAddrs)

	cmd := exec.Command("mailx", args...)
	cmd.Stdin = bytes.NewReader(crash.Report.Report)
	if _, err := osutil.Run(10*time.Minute, cmd); err != nil {
		log.Logf(0, "failed to send email: %v", err)
	}
}

func (mgr *Manager) saveCrash(crash *manager.Crash) bool {
	if crash.MemoryDump != "" {
		defer os.Remove(crash.MemoryDump)
	}
	if err := mgr.reporter.Symbolize(crash.Report); err != nil {
		log.Errorf("failed to symbolize report: %v", err)
	}
	if crash.Type == crash_pkg.MemoryLeak {
		mgr.mu.Lock()
		mgr.memoryLeakFrames[crash.Frame] = true
		mgr.mu.Unlock()
	}
	if crash.Type == crash_pkg.KCSANDataRace {
		mgr.mu.Lock()
		mgr.dataRaceFrames[crash.Frame] = true
		mgr.mu.Unlock()
	}
	flags := ""
	if crash.Corrupted {
		flags += " [corrupted]"
	}
	if crash.Suppressed {
		flags += " [suppressed]"
	}
	log.Logf(0, "VM %v: crash: %v%v", crash.InstanceIndex, crash.Report.Title, flags)
	for i, report := range crash.TailReports {
		log.Logf(0, "VM %v: crash(tail%d): %v%v", crash.InstanceIndex, i, report.Title, flags)
	}

	if mgr.mode.FailOnCrashes {
		path := filepath.Join(mgr.cfg.Workdir, "report.json")
		if err := osutil.WriteJSON(path, crash.Report); err != nil {
			log.Fatal(err)
		}
		log.Fatalf("kernel crashed in smoke testing mode, exiting")
	}

	if crash.Suppressed {
		// Collect all of them into a single bucket so that it's possible to control and assess them,
		// e.g. if there are some spikes in suppressed reports.
		crash.Title = "suppressed report"
		mgr.statSuppressed.Add(1)
	}

	mgr.statCrashes.Add(1)
	mgr.mu.Lock()
	if !mgr.crashTypes[crash.Title] {
		mgr.crashTypes[crash.Title] = true
		mgr.statCrashTypes.Add(1)
	}
	mgr.mu.Unlock()

	if mgr.dash != nil {
		if crash.Type == crash_pkg.MemoryLeak {
			return true
		}
		dc := &dashapi.Crash{
			BuildID:     mgr.cfg.Tag,
			Title:       crash.Title,
			AltTitles:   crash.AltTitles,
			Corrupted:   crash.Corrupted,
			Suppressed:  crash.Suppressed,
			Recipients:  crash.Recipients.ToDash(),
			Log:         crash.Output,
			Report:      report.SplitReportBytes(crash.Report.Report)[0],
			MachineInfo: crash.MachineInfo,
		}
		setGuiltyFiles(dc, crash.Report)
		resp, err := mgr.dash.ReportCrash(dc)
		if err != nil {
			log.Logf(0, "failed to report crash to dashboard: %v", err)
		}
		// Don't store the crash locally even if we failed to upload it.
		// There is 0 chance that one will ever look in the crashes/ folder of those instances.
		return mgr.cfg.Reproduce && resp.NeedRepro
	}
	first, err := mgr.crashStore.SaveCrash(crash)
	if err != nil {
		log.Logf(0, "failed to save the crash: %v", err)
		return false
	}
	if first {
		go mgr.emailCrash(crash)
	}
	return mgr.NeedRepro(crash)
}

func (mgr *Manager) needLocalRepro(crash *manager.Crash) bool {
	if !mgr.cfg.Reproduce || crash.Corrupted || crash.Suppressed {
		return false
	}
	if mgr.crashStore.HasRepro(crash.Title) {
		return false
	}
	return mgr.crashStore.MoreReproAttempts(crash.Title)
}

func (mgr *Manager) NeedRepro(crash *manager.Crash) bool {
	if !mgr.cfg.Reproduce {
		return false
	}
	if crash.FromHub || crash.FromDashboard {
		return true
	}
	mgr.mu.Lock()
	phase, features := mgr.phase, mgr.enabledFeatures
	mgr.mu.Unlock()
	if phase < phaseLoadedCorpus || (features&flatrpc.FeatureLeak != 0 &&
		crash.Type != crash_pkg.MemoryLeak) {
		// Leak checking is very slow, don't bother reproducing other crashes on leak instance.
		return false
	}
	if mgr.dashRepro == nil {
		return mgr.needLocalRepro(crash)
	}
	cid := &dashapi.CrashID{
		BuildID:    mgr.cfg.Tag,
		Title:      crash.Title,
		Corrupted:  crash.Corrupted,
		Suppressed: crash.Suppressed,
		// When cfg.DashboardOnlyRepro is enabled, we don't sent any reports to dashboard.
		// We also don't send leak reports w/o reproducers to dashboard, so they may be missing.
		MayBeMissing: mgr.dash == nil || crash.Type == crash_pkg.MemoryLeak,
	}
	needRepro, err := mgr.dashRepro.NeedRepro(cid)
	if err != nil {
		log.Logf(0, "dashboard.NeedRepro failed: %v", err)
	}
	return needRepro
}

func truncateReproLog(log []byte) []byte {
	// Repro logs can get quite large and we have trouble sending large API requests (see #4495).
	// Let's truncate the log to a 512KB prefix and 512KB suffix.
	return report.Truncate(log, 512000, 512000)
}

func (mgr *Manager) saveFailedRepro(rep *report.Report, stats *repro.Stats) {
	reproLog := stats.FullLog()
	if mgr.dash != nil {
		if rep.Type == crash_pkg.MemoryLeak {
			// Don't send failed leak repro attempts to dashboard
			// as we did not send the crash itself.
			log.Logf(1, "failed repro of '%v': not sending because of the memleak type", rep.Title)
			return
		}
		cid := &dashapi.CrashID{
			BuildID:      mgr.cfg.Tag,
			Title:        rep.Title,
			Corrupted:    rep.Corrupted,
			Suppressed:   rep.Suppressed,
			MayBeMissing: rep.Type == crash_pkg.MemoryLeak,
			ReproLog:     truncateReproLog(reproLog),
		}
		if err := mgr.dash.ReportFailedRepro(cid); err != nil {
			log.Logf(0, "failed to report failed repro to dashboard (log size %d): %v",
				len(reproLog), err)
		}
		return
	}
	err := mgr.crashStore.SaveFailedRepro(rep.Title, reproLog)
	if err != nil {
		log.Logf(0, "failed to save repro log for %q: %v", rep.Title, err)
	}
}

func (mgr *Manager) saveRepro(res *manager.ReproResult) {
	repro := res.Repro
	opts := fmt.Sprintf("# %+v\n", repro.Opts)
	progText := repro.Prog.Serialize()

	// Append this repro to repro list to send to hub if it didn't come from hub originally.
	if !res.Crash.FromHub {
		progForHub := []byte(fmt.Sprintf("# %+v\n# %v\n# %v\n%s",
			repro.Opts, repro.Report.Title, mgr.cfg.Tag, progText))
		mgr.mu.Lock()
		mgr.newRepros = append(mgr.newRepros, progForHub)
		mgr.mu.Unlock()
	}

	var cprogText []byte
	if repro.CRepro {
		var err error
		cprogText, err = repro.CProgram()
		if err != nil {
			log.Logf(0, "failed to write C source: %v", err)
		}
	}

	if mgr.dash != nil {
		// Note: we intentionally don't set Corrupted for reproducers:
		// 1. This is reproducible so can be debugged even with corrupted report.
		// 2. Repro re-tried 3 times and still got corrupted report at the end,
		//    so maybe corrupted report detection is broken.
		// 3. Reproduction is expensive so it's good to persist the result.

		reproReport := repro.Report
		output := reproReport.Output

		var crashFlags dashapi.CrashFlags
		if res.Strace != nil {
			// If syzkaller managed to successfully run the repro with strace, send
			// the report and the output generated under strace.
			reproReport = res.Strace.Report
			output = res.Strace.Output
			crashFlags = dashapi.CrashUnderStrace
		}

		dc := &dashapi.Crash{
			BuildID:       mgr.cfg.Tag,
			Title:         reproReport.Title,
			AltTitles:     reproReport.AltTitles,
			Suppressed:    reproReport.Suppressed,
			Recipients:    reproReport.Recipients.ToDash(),
			Log:           output,
			Flags:         crashFlags,
			Report:        report.SplitReportBytes(reproReport.Report)[0],
			ReproOpts:     repro.Opts.Serialize(),
			ReproSyz:      progText,
			ReproC:        cprogText,
			ReproLog:      truncateReproLog(res.Stats.FullLog()),
			Assets:        mgr.uploadReproAssets(repro),
			OriginalTitle: res.Crash.Title,
		}
		setGuiltyFiles(dc, reproReport)
		if _, err := mgr.dash.ReportCrash(dc); err != nil {
			log.Logf(0, "failed to report repro to dashboard: %v", err)
		} else {
			// Don't store the crash locally, if we've successfully
			// uploaded it to the dashboard. These will just eat disk space.
			return
		}
	}
	err := mgr.crashStore.SaveRepro(res, append([]byte(opts), progText...), cprogText)
	if err != nil {
		log.Logf(0, "%s", err)
	}
}

func (mgr *Manager) ResizeReproPool(size int) {
	mgr.pool.ReserveForRun(size)
}

func (mgr *Manager) uploadReproAssets(repro *repro.Result) []dashapi.NewAsset {
	if mgr.assetStorage == nil {
		return nil
	}

	ret := []dashapi.NewAsset{}
	repro.Prog.ForEachAsset(func(name string, typ prog.AssetType, r io.Reader, c *prog.Call) {
		dashTyp, ok := map[prog.AssetType]dashapi.AssetType{
			prog.MountInRepro: dashapi.MountInRepro,
		}[typ]
		if !ok {
			panic("unknown extracted prog asset")
		}
		r2 := &bytes.Buffer{}
		r1 := io.TeeReader(r, r2)
		asset, err := mgr.assetStorage.UploadCrashAsset(r1, name, dashTyp, nil)
		if err != nil {
			log.Logf(1, "processing of the asset %v (%v) failed: %v", name, typ, err)
			return
		}
		// Report file systems that fail fsck with a separate tag.
		if mgr.cfg.RunFsck && dashTyp == dashapi.MountInRepro &&
			c.Meta.Attrs.Fsck != "" && mgr.fsckChecker.Exists(c.Meta.Attrs.Fsck) {
			logs, isClean, err := image.Fsck(r2, c.Meta.Attrs.Fsck)
			if err != nil {
				log.Errorf("fsck of the asset %v failed: %v", name, err)
			} else {
				asset.FsckLog = logs
				asset.FsIsClean = isClean
			}
		}
		ret = append(ret, asset)
	})
	return ret
}

func (mgr *Manager) extractMemoryDump(inst *vm.Instance, rep *report.Report) string {
	if !rep.Panicked {
		// We can only collect a memory dump from a kernel that panicked.
		return ""
	}
	if mgr.crashStore.HasMemoryDump(rep.Title) {
		// Keep only one memory dump to save disk space.
		// For now let it be the first one.
		return ""
	}
	tmpPath, err := osutil.TempFile("vmcore-*")
	if err != nil {
		log.Errorf("failed to create temp file for memory dump: %v", err)
		return ""
	}
	if err := instance.ExtractMemoryDump(inst, mgr.sysTarget, tmpPath); err != nil {
		log.Logf(0, "VM %v: failed to extract memory dump: %v", inst.Index(), err)
		os.Remove(tmpPath)
		return ""
	}

	log.Logf(0, "VM %v: extracted memory dump to %v", inst.Index(), tmpPath)
	return tmpPath
}

func (mgr *Manager) corpusInputHandler(updates <-chan corpus.NewItemEvent) {
	for update := range updates {
		if len(update.NewCover) != 0 && mgr.coverFilters.ExecutorFilter != nil {
			filtered := 0
			for _, pc := range update.NewCover {
				if _, ok := mgr.coverFilters.ExecutorFilter[pc]; ok {
					filtered++
				}
			}
			mgr.statCoverFiltered.Add(filtered)
		}
		if update.Exists {
			// We only save new progs into the corpus.db file.
			continue
		}
		mgr.corpusDBMu.Lock()
		mgr.corpusDB.Save(update.Sig, update.ProgData, 0)
		if err := mgr.corpusDB.Flush(); err != nil {
			log.Errorf("failed to save corpus database: %v", err)
		}
		mgr.corpusDBMu.Unlock()
	}
}

func (mgr *Manager) getMinimizedCorpus() []*corpus.Item {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	mgr.minimizeCorpusLocked()
	return mgr.corpus.Items()
}

func (mgr *Manager) getNewRepros() [][]byte {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	repros := mgr.newRepros
	mgr.newRepros = nil
	return repros
}

func (mgr *Manager) addNewCandidates(candidates []fuzzer.Candidate) {
	mgr.mu.Lock()
	if mgr.phase == phaseTriagedCorpus {
		mgr.setPhaseLocked(phaseQueriedHub)
	}
	mgr.mu.Unlock()
	if mgr.cfg.Experimental.ResetAccState {
		// Don't accept new candidates -- the execution is already very slow,
		// syz-hub will just overwhelm us.
		return
	}
	mgr.fuzzer.Load().AddCandidates(candidates)
}

func (mgr *Manager) minimizeCorpusLocked() {
	// Don't minimize corpus until we have triaged all inputs from it.
	// During corpus triage it would happen very often since we are actively adding inputs,
	// and presumably the persistent corpus was reasonably minimial, and we don't use it for fuzzing yet.
	if mgr.phase < phaseTriagedCorpus {
		return
	}
	currSize := mgr.corpus.StatProgs.Val()
	if currSize <= mgr.lastMinCorpus*103/100 {
		return
	}
	mgr.corpus.Minimize(mgr.cfg.Cover)
	newSize := mgr.corpus.StatProgs.Val()

	log.Logf(1, "minimized corpus: %v -> %v", currSize, newSize)
	mgr.lastMinCorpus = newSize

	// From time to time we get corpus explosion due to different reason:
	// generic bugs, per-OS bugs, problems with fallback coverage, kcov bugs, etc.
	// This has bad effect on the instance and especially on instances
	// connected via hub. Do some per-syscall sanity checking to prevent this.
	for call, info := range mgr.corpus.CallCover() {
		if mgr.cfg.Cover {
			// If we have less than 1K inputs per this call,
			// accept all new inputs unconditionally.
			if info.Count < 1000 {
				continue
			}
			// If we have more than 3K already, don't accept any more.
			// Between 1K and 3K look at amount of coverage we are getting from these programs.
			// Empirically, real coverage for the most saturated syscalls is ~30-60
			// per program (even when we have a thousand of them). For explosion
			// case coverage tend to be much lower (~0.3-5 per program).
			if info.Count < 3000 && len(info.Cover)/info.Count >= 10 {
				continue
			}
		} else {
			// If we don't have real coverage, signal is weak.
			// If we have more than several hundreds, there is something wrong.
			if info.Count < 300 {
				continue
			}
		}
		if mgr.saturatedCalls[call] {
			continue
		}
		mgr.saturatedCalls[call] = true
		log.Logf(0, "coverage for %v has saturated, not accepting more inputs", call)
	}

	mgr.corpusDBMu.Lock()
	defer mgr.corpusDBMu.Unlock()
	for key := range mgr.corpusDB.Records {
		ok1 := mgr.corpus.Item(key) != nil
		_, ok2 := mgr.disabledHashes[key]
		if !ok1 && !ok2 {
			mgr.corpusDB.Delete(key)
		}
	}
	if err := mgr.corpusDB.Flush(); err != nil {
		log.Fatalf("failed to save corpus database: %v", err)
	}
	mgr.corpusDB.BumpVersion(manager.CurrentDBVersion)
}

func setGuiltyFiles(crash *dashapi.Crash, report *report.Report) {
	if report.GuiltyFile != "" {
		crash.GuiltyFiles = []string{report.GuiltyFile}
	}
}

func (mgr *Manager) BugFrames() (leaks, races []string) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	for frame := range mgr.memoryLeakFrames {
		leaks = append(leaks, frame)
	}
	for frame := range mgr.dataRaceFrames {
		races = append(races, frame)
	}
	return
}

func (mgr *Manager) MachineChecked(features flatrpc.Feature,
	enabledSyscalls map[*prog.Syscall]bool) (queue.Source, error) {
	if len(enabledSyscalls) == 0 {
		return nil, fmt.Errorf("all system calls are disabled")
	}
	if mgr.mode.ExitAfterMachineCheck {
		mgr.exit(mgr.mode.Name)
	}

	// If KFuzzTest is enabled, we exclusively fuzz KFuzzTest targets - so
	// delete any existing entries in enabled syscalls, and enable all
	// discovered KFuzzTest targets explicitly.
	if mgr.cfg.Experimental.EnableKFuzzTest {
		for call := range enabledSyscalls {
			delete(enabledSyscalls, call)
		}
		data, err := kfuzztest.ExtractData(path.Join(mgr.cfg.KernelObj, "vmlinux"))
		if err != nil {
			return nil, err
		}
		for _, call := range data.Calls {
			enabledSyscalls[call] = true
		}
	}

	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	if mgr.phase != phaseInit {
		panic("machineChecked() called not during phaseInit")
	}
	if mgr.checkDone.Swap(true) {
		panic("MachineChecked called twice")
	}
	mgr.enabledFeatures = features
	mgr.http.EnabledSyscalls.Store(enabledSyscalls)
	mgr.firstConnect.Store(time.Now().Unix())
	statSyscalls := stat.New("syscalls", "Number of enabled syscalls",
		stat.Simple, stat.NoGraph, stat.Link("/syscalls"))
	statSyscalls.Add(len(enabledSyscalls))
	candidates := mgr.loadCorpus(enabledSyscalls)
	mgr.setPhaseLocked(phaseLoadedCorpus)
	opts := fuzzer.DefaultExecOpts(mgr.cfg, features, *flagDebug)

	switch mgr.mode {
	case ModeFuzzing, ModeCorpusTriage:
		corpusUpdates := make(chan corpus.NewItemEvent, 128)
		mgr.corpus = corpus.NewFocusedCorpus(context.Background(),
			corpusUpdates, mgr.coverFilters.Areas)
		mgr.http.Corpus.Store(mgr.corpus)

		rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
		fuzzerObj := fuzzer.NewFuzzer(context.Background(), &fuzzer.Config{
			Corpus:         mgr.corpus,
			Snapshot:       mgr.cfg.Snapshot,
			Coverage:       mgr.cfg.Cover,
			FaultInjection: features&flatrpc.FeatureFault != 0,
			Comparisons:    features&flatrpc.FeatureComparisons != 0,
			Collide:        true,
			EnabledCalls:   enabledSyscalls,
			NoMutateCalls:  mgr.cfg.NoMutateCalls,
			FetchRawCover:  mgr.cfg.RawCover,
			Logf: func(level int, msg string, args ...any) {
				if level != 0 {
					return
				}
				log.Logf(level, msg, args...)
			},
			NewInputFilter: func(call string) bool {
				mgr.mu.Lock()
				defer mgr.mu.Unlock()
				return !mgr.saturatedCalls[call]
			},
			ModeKFuzzTest: mgr.cfg.Experimental.EnableKFuzzTest,
		}, rnd, mgr.target)
		fuzzerObj.AddCandidates(candidates)
		mgr.fuzzer.Store(fuzzerObj)
		mgr.http.Fuzzer.Store(fuzzerObj)

		go mgr.corpusInputHandler(corpusUpdates)
		go mgr.corpusMinimization()
		go mgr.fuzzerLoop(fuzzerObj)
		if mgr.dash != nil {
			go mgr.dashboardReporter()
			if mgr.cfg.Reproduce {
				go mgr.dashboardReproTasks()
			}
		}
		source := queue.DefaultOpts(fuzzerObj, opts)
		if mgr.cfg.Snapshot {
			log.Logf(0, "restarting VMs for snapshot mode")
			mgr.snapshotSource = queue.Distribute(source)
			mgr.pool.SetDefault(mgr.snapshotInstance)
			mgr.serv.Close()
			mgr.serv = nil
			return queue.Callback(func() *queue.Request {
				return nil
			}), nil
		}
		return source, nil
	case ModeCorpusRun:
		ctx := &corpusRunner{
			candidates: candidates,
			rnd:        rand.New(rand.NewSource(time.Now().UnixNano())),
		}
		return queue.DefaultOpts(ctx, opts), nil
	case ModeRunTests:
		ctx := &runtest.Context{
			Dir:      filepath.Join(mgr.cfg.Syzkaller, "sys", mgr.cfg.Target.OS, "test"),
			Target:   mgr.cfg.Target,
			Features: features,
			EnabledCalls: map[string]map[*prog.Syscall]bool{
				mgr.cfg.Sandbox: enabledSyscalls,
			},
			LogFunc: func(text string) { fmt.Println(text) },
			Verbose: true,
			Debug:   *flagDebug,
			Tests:   *flagTests,
		}
		ctx.Init()
		go func() {
			err := ctx.Run(context.Background())
			if err != nil {
				log.Fatal(err)
			}
			mgr.exit("tests")
		}()
		return ctx, nil
	case ModeIfaceProbe:
		exec := queue.Plain()
		go func() {
			res, err := ifaceprobe.Run(vm.ShutdownCtx(), mgr.cfg, features, exec)
			if err != nil {
				log.Fatalf("interface probing failed: %v", err)
			}
			path := filepath.Join(mgr.cfg.Workdir, "interfaces.json")
			if err := osutil.WriteJSON(path, res); err != nil {
				log.Fatal(err)
			}
			mgr.exit("interface probe")
		}()
		return exec, nil
	}
	panic(fmt.Sprintf("unexpected mode %q", mgr.mode.Name))
}

type corpusRunner struct {
	candidates []fuzzer.Candidate
	mu         sync.Mutex
	rnd        *rand.Rand
	seq        int
}

func (cr *corpusRunner) Next() *queue.Request {
	cr.mu.Lock()
	defer cr.mu.Unlock()

	var p *prog.Prog
	if cr.seq < len(cr.candidates) {
		// First run all candidates sequentially.
		p = cr.candidates[cr.seq].Prog
		cr.seq++
	} else {
		// Then pick random progs.
		p = cr.candidates[cr.rnd.Intn(len(cr.candidates))].Prog
	}
	return &queue.Request{
		Prog:      p,
		Important: true,
	}
}

func (mgr *Manager) corpusMinimization() {
	for range time.NewTicker(time.Minute).C {
		mgr.mu.Lock()
		mgr.minimizeCorpusLocked()
		mgr.mu.Unlock()
	}
}

func (mgr *Manager) MaxSignal() signal.Signal {
	if fuzzer := mgr.fuzzer.Load(); fuzzer != nil {
		return fuzzer.Cover.CopyMaxSignal()
	}
	return nil
}

func (mgr *Manager) fuzzerLoop(fuzzer *fuzzer.Fuzzer) {
	for ; ; time.Sleep(time.Second / 2) {
		if mgr.cfg.Cover && !mgr.cfg.Snapshot {
			// Distribute new max signal over all instances.
			newSignal := fuzzer.Cover.GrabSignalDelta()
			if len(newSignal) != 0 {
				log.Logf(3, "distributing %d new signal", len(newSignal))
			}
			if len(newSignal) != 0 {
				mgr.serv.DistributeSignalDelta(newSignal)
			}
		}

		// Update the state machine.
		if fuzzer.CandidateTriageFinished() {
			if mgr.mode == ModeCorpusTriage {
				mgr.exit("corpus triage")
			}
			mgr.mu.Lock()
			switch mgr.phase {
			case phaseLoadedCorpus:
				if !mgr.cfg.Snapshot {
					mgr.serv.TriagedCorpus()
				}
				if mgr.cfg.HubClient != "" {
					mgr.setPhaseLocked(phaseTriagedCorpus)
					go mgr.hubSyncLoop(pickGetter(mgr.cfg.HubKey),
						fuzzer.Config.EnabledCalls)
				} else {
					mgr.setPhaseLocked(phaseTriagedHub)
				}
			case phaseQueriedHub:
				mgr.setPhaseLocked(phaseTriagedHub)
			}
			mgr.mu.Unlock()
		}
	}
}

func (mgr *Manager) setPhaseLocked(newPhase int) {
	if mgr.phase == newPhase {
		panic("repeated phase update")
	}
	// In VMLess mode, mgr.reproLoop is nil.
	if newPhase == phaseTriagedHub && mgr.reproLoop != nil {
		// Start reproductions.
		go mgr.reproLoop.Loop(vm.ShutdownCtx())
	}
	mgr.phase = newPhase
}

func (mgr *Manager) needMoreCandidates() bool {
	return mgr.fuzzer.Load().CandidateTriageFinished()
}

func (mgr *Manager) hubIsUnreachable() {
	var dash *dashapi.Dashboard
	mgr.mu.Lock()
	if mgr.phase == phaseTriagedCorpus {
		dash = mgr.dash
		mgr.setPhaseLocked(phaseTriagedHub)
		log.Errorf("did not manage to connect to syz-hub; moving forward")
	}
	mgr.mu.Unlock()
	if dash != nil {
		mgr.dash.LogError(mgr.cfg.Name, "did not manage to connect to syz-hub")
	}
}

// trackUsedFiles() is checking that the files that syz-manager needs are not changed while it's running.
func (mgr *Manager) trackUsedFiles() {
	usedFiles := make(map[string]time.Time) // file name to modification time
	addUsedFile := func(f string) {
		if f == "" {
			return
		}
		stat, err := os.Stat(f)
		if err != nil {
			log.Fatalf("failed to stat %v: %v", f, err)
		}
		usedFiles[f] = stat.ModTime()
	}
	cfg := mgr.cfg
	addUsedFile(cfg.ExecprogBin)
	addUsedFile(cfg.ExecutorBin)
	addUsedFile(cfg.SSHKey)
	if vmlinux := filepath.Join(cfg.KernelObj, mgr.sysTarget.KernelObject); osutil.IsExist(vmlinux) {
		addUsedFile(vmlinux)
	}
	if cfg.Image != "9p" {
		addUsedFile(cfg.Image)
	}
	for range time.NewTicker(30 * time.Second).C {
		for f, mod := range usedFiles {
			stat, err := os.Stat(f)
			if err != nil {
				log.Fatalf("failed to stat %v: %v", f, err)
			}
			if mod != stat.ModTime() {
				log.Fatalf("file %v that syz-manager uses has been modified by an external program\n"+
					"this can lead to arbitrary syz-manager misbehavior\n"+
					"modification time has changed: %v -> %v\n"+
					"don't modify files that syz-manager uses. exiting to prevent harm",
					f, mod, stat.ModTime())
			}
		}
	}
}

func (mgr *Manager) dashboardReporter() {
	webAddr := publicWebAddr(mgr.cfg.HTTP)
	triageInfoSent := false
	var lastFuzzingTime time.Duration
	var lastCrashes, lastSuppressedCrashes, lastExecs uint64
	for range time.NewTicker(time.Minute).C {
		mgr.mu.Lock()
		corpus := mgr.corpus
		mgr.mu.Unlock()
		if corpus == nil {
			continue
		}
		mgr.mu.Lock()
		req := &dashapi.ManagerStatsReq{
			Name:              mgr.cfg.Name,
			Addr:              webAddr,
			UpTime:            time.Duration(mgr.statUptime.Val()) * time.Second,
			Corpus:            uint64(corpus.StatProgs.Val()),
			PCs:               uint64(corpus.StatCover.Val()),
			Cover:             uint64(corpus.StatSignal.Val()),
			CrashTypes:        uint64(mgr.statCrashTypes.Val()),
			FuzzingTime:       time.Duration(mgr.statFuzzingTime.Val()) - lastFuzzingTime,
			Crashes:           uint64(mgr.statCrashes.Val()) - lastCrashes,
			SuppressedCrashes: uint64(mgr.statSuppressed.Val()) - lastSuppressedCrashes,
			Execs:             uint64(mgr.servStats.StatExecs.Val()) - lastExecs,
		}
		if mgr.phase >= phaseTriagedCorpus && !triageInfoSent {
			triageInfoSent = true
			req.TriagedCoverage = uint64(corpus.StatSignal.Val())
			req.TriagedPCs = uint64(corpus.StatCover.Val())
		}
		mgr.mu.Unlock()

		if err := mgr.dash.UploadManagerStats(req); err != nil {
			log.Logf(0, "failed to upload dashboard stats: %v", err)
			continue
		}
		mgr.mu.Lock()
		lastFuzzingTime += req.FuzzingTime
		lastCrashes += req.Crashes
		lastSuppressedCrashes += req.SuppressedCrashes
		lastExecs += req.Execs
		mgr.mu.Unlock()
	}
}

func (mgr *Manager) dashboardReproTasks() {
	for range time.NewTicker(20 * time.Minute).C {
		if !mgr.reproLoop.CanReproMore() {
			// We don't need reproducers at the moment.
			continue
		}
		resp, err := mgr.dash.LogToRepro(&dashapi.LogToReproReq{BuildID: mgr.cfg.Tag})
		if err != nil {
			log.Logf(0, "failed to query logs to reproduce: %v", err)
			continue
		}
		if len(resp.CrashLog) > 0 {
			mgr.externalReproQueue <- &manager.Crash{
				FromDashboard: true,
				Manual:        resp.Type == dashapi.ManualLog,
				Report: &report.Report{
					Title:  resp.Title,
					Output: resp.CrashLog,
				},
			}
		}
	}
}

func (mgr *Manager) CoverageFilter(modules []*vminfo.KernelModule) ([]uint64, error) {
	mgr.reportGenerator.Init(modules)
	filters, err := manager.PrepareCoverageFilters(mgr.reportGenerator, mgr.cfg, true)
	if err != nil {
		return nil, fmt.Errorf("failed to init coverage filter: %w", err)
	}
	mgr.coverFilters = filters
	mgr.http.Cover.Store(&manager.CoverageInfo{
		Modules:         modules,
		ReportGenerator: mgr.reportGenerator,
		CoverFilter:     filters.ExecutorFilter,
	})
	var pcs []uint64
	for pc := range filters.ExecutorFilter {
		pcs = append(pcs, pc)
	}
	return pcs, nil
}

func publicWebAddr(addr string) string {
	if addr == "" {
		return ""
	}
	_, port, err := net.SplitHostPort(addr)
	if err == nil && port != "" {
		if host, err := os.Hostname(); err == nil {
			addr = net.JoinHostPort(host, port)
		}
		if GCE, err := gce.NewContext(""); err == nil {
			addr = net.JoinHostPort(GCE.ExternalIP, port)
		}
	}
	return "http://" + addr
}
