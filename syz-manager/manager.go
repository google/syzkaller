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
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/asset"
	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/cover/backend"
	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/gce"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/log"
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

	flagMode = flag.String("mode", "fuzzing", "mode of operation, one of:\n"+
		" - fuzzing: the default continuous fuzzing mode\n"+
		" - smoke-test: run smoke test for syzkaller+kernel\n"+
		"	The test consists of booting VMs and running some simple test programs\n"+
		"	to ensure that fuzzing can proceed in general. After completing the test\n"+
		"	the process exits and the exit status indicates success/failure.\n"+
		"	If the kernel oopses during testing, the report is saved to workdir/report.json.\n"+
		" - corpus-triage: triage corpus and exit\n"+
		"	This is useful mostly for benchmarking with testbed.\n"+
		" - corpus-run: continuously run the corpus programs.\n"+
		" - run-tests: run unit tests\n"+
		"	Run sys/os/test/* tests in various modes and print results.\n")
)

type Manager struct {
	cfg             *mgrconfig.Config
	mode            Mode
	vmPool          *vm.Pool
	pool            *dispatcher.Pool[*vm.Instance]
	target          *prog.Target
	sysTarget       *targets.Target
	reporter        *report.Reporter
	crashdir        string
	serv            *rpcserver.Server
	corpus          *corpus.Corpus
	corpusDB        *db.DB
	corpusDBMu      sync.Mutex // for concurrent operations on corpusDB
	corpusPreload   chan []fuzzer.Candidate
	firstConnect    atomic.Int64 // unix time, or 0 if not connected
	crashTypes      map[string]bool
	loopStop        func()
	enabledFeatures flatrpc.Feature
	checkDone       atomic.Bool
	fresh           bool
	expertMode      bool
	modules         []*vminfo.KernelModule
	coverFilter     map[uint64]struct{} // includes only coverage PCs

	dash *dashapi.Dashboard
	// This is specifically separated from dash, so that we can keep dash = nil when
	// cfg.DashboardOnlyRepro is set, so that we don't accidentially use dash for anything.
	dashRepro *dashapi.Dashboard

	mu                    sync.Mutex
	fuzzer                atomic.Pointer[fuzzer.Fuzzer]
	source                queue.Source
	phase                 int
	targetEnabledSyscalls map[*prog.Syscall]bool

	disabledHashes   map[string]struct{}
	newRepros        [][]byte
	lastMinCorpus    int
	memoryLeakFrames map[string]bool
	dataRaceFrames   map[string]bool
	saturatedCalls   map[string]bool

	externalReproQueue chan *Crash
	crashes            chan *Crash

	benchMu   sync.Mutex
	benchFile *os.File

	assetStorage *asset.Storage

	reproMgr *reproManager

	Stats
}

type Mode int

// For description of modes see flagMode help.
const (
	ModeFuzzing Mode = iota
	ModeSmokeTest
	ModeCorpusTriage
	ModeCorpusRun
	ModeRunTests
)

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

const currentDBVersion = 5

type Crash struct {
	instanceIndex int
	fromHub       bool // this crash was created based on a repro from syz-hub
	fromDashboard bool // .. or from dashboard
	manual        bool
	*report.Report
}

func (c *Crash) FullTitle() string {
	if c.Report.Title != "" {
		return c.Report.Title
	}
	// Just use some unique, but stable titles.
	if c.fromDashboard {
		return fmt.Sprintf("dashboard crash %p", c)
	} else if c.fromHub {
		return fmt.Sprintf("crash from hub %p", c)
	}
	panic("the crash is expected to have a report")
}

func main() {
	if prog.GitRevision == "" {
		log.Fatalf("bad syz-manager build: build with make, run bin/syz-manager")
	}
	flag.Parse()
	log.EnableLogCaching(1000, 1<<20)
	cfg, err := mgrconfig.LoadFile(*flagConfig)
	if err != nil {
		log.Fatalf("%v", err)
	}
	if cfg.DashboardAddr != "" {
		// This lets better distinguish logs of individual syz-manager instances.
		log.SetName(cfg.Name)
	}
	var mode Mode
	switch *flagMode {
	case "fuzzing":
		mode = ModeFuzzing
	case "smoke-test":
		mode = ModeSmokeTest
		cfg.DashboardClient = ""
		cfg.HubClient = ""
	case "corpus-triage":
		mode = ModeCorpusTriage
		cfg.DashboardClient = ""
		cfg.HubClient = ""
	case "corpus-run":
		mode = ModeCorpusRun
		cfg.HubClient = ""
		cfg.DashboardClient = ""
	case "run-tests":
		mode = ModeRunTests
		cfg.DashboardClient = ""
		cfg.HubClient = ""
	default:
		flag.PrintDefaults()
		log.Fatalf("unknown mode: %v", *flagMode)
	}
	RunManager(mode, cfg)
}

func RunManager(mode Mode, cfg *mgrconfig.Config) {
	var vmPool *vm.Pool
	if !cfg.VMLess {
		var err error
		vmPool, err = vm.Create(cfg, *flagDebug)
		if err != nil {
			log.Fatalf("%v", err)
		}
	}

	crashdir := filepath.Join(cfg.Workdir, "crashes")
	osutil.MkdirAll(crashdir)

	reporter, err := report.NewReporter(cfg)
	if err != nil {
		log.Fatalf("%v", err)
	}

	corpusUpdates := make(chan corpus.NewItemEvent, 128)
	mgr := &Manager{
		cfg:                cfg,
		mode:               mode,
		vmPool:             vmPool,
		corpus:             corpus.NewMonitoredCorpus(context.Background(), corpusUpdates),
		corpusPreload:      make(chan []fuzzer.Candidate),
		target:             cfg.Target,
		sysTarget:          cfg.SysTarget,
		reporter:           reporter,
		crashdir:           crashdir,
		crashTypes:         make(map[string]bool),
		disabledHashes:     make(map[string]struct{}),
		memoryLeakFrames:   make(map[string]bool),
		dataRaceFrames:     make(map[string]bool),
		fresh:              true,
		externalReproQueue: make(chan *Crash, 10),
		crashes:            make(chan *Crash, 10),
		saturatedCalls:     make(map[string]bool),
	}

	if *flagDebug {
		mgr.cfg.Procs = 1
	}

	mgr.initStats()
	if mode == ModeFuzzing || mode == ModeCorpusTriage {
		go mgr.preloadCorpus()
	} else {
		close(mgr.corpusPreload)
	}
	mgr.initHTTP() // Creates HTTP server.
	go mgr.corpusInputHandler(corpusUpdates)
	go mgr.trackUsedFiles()

	// Create RPC server for fuzzers.
	mgr.serv, err = rpcserver.New(mgr.cfg, mgr, *flagDebug)
	if err != nil {
		log.Fatalf("failed to create rpc server: %v", err)
	}
	log.Logf(0, "serving rpc on tcp://%v", mgr.serv.Port)

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
		log.Logf(0, "syz-executor runner local manager.ip %v", mgr.serv.Port)
		<-vm.Shutdown
		return
	}
	ctx, cancel := context.WithCancel(vm.ShutdownCtx())
	mgr.loopStop = cancel
	mgr.pool = vm.NewDispatcher(mgr.vmPool, mgr.fuzzerInstance)
	mgr.reproMgr = newReproManager(mgr, mgr.vmPool.Count()-mgr.cfg.FuzzingVMs, mgr.cfg.DashboardOnlyRepro)
	go mgr.processFuzzingResults(ctx)
	go mgr.reproMgr.Loop(ctx)
	mgr.pool.Loop(ctx)
	if cfg.Snapshot {
		log.Logf(0, "starting VMs for snapshot mode")
		mgr.serv.Close()
		mgr.serv = nil
		mgr.snapshotLoop()
	}
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
		mgr.statFuzzingTime.Add(diff * queue.StatNumFuzzing.Val())
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

type ReproResult struct {
	crash  *Crash // the original crash
	repro  *repro.Result
	strace *repro.StraceResult
	stats  *repro.Stats
	err    error
}

func (mgr *Manager) processFuzzingResults(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case crash := <-mgr.crashes:
			needRepro := mgr.saveCrash(crash)
			if mgr.cfg.Reproduce && needRepro {
				mgr.reproMgr.Enqueue(crash)
			}
		case err := <-mgr.pool.BootErrors:
			crash := mgr.convertBootError(err)
			if crash != nil {
				mgr.saveCrash(crash)
			}
		case res := <-mgr.reproMgr.Done:
			if res.err != nil {
				reportReproError(res.err)
			}
			if res.repro == nil {
				if res.crash.Title == "" {
					log.Logf(1, "repro '%v' not from dashboard, so not reporting the failure",
						res.crash.FullTitle())
				} else {
					log.Logf(1, "report repro failure of '%v'", res.crash.Title)
					mgr.saveFailedRepro(res.crash.Report, res.stats)
				}
			} else {
				mgr.saveRepro(res)
			}
		case crash := <-mgr.externalReproQueue:
			if mgr.needRepro(crash) {
				mgr.reproMgr.Enqueue(crash)
			}
		}
	}
}

func (mgr *Manager) convertBootError(err error) *Crash {
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
		return &Crash{
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
	} else if errors.Is(err, repro.ErrNoVMs) {
		// This error is to be expected if we're shutting down.
		if shutdown {
			return
		}
	}
	// Report everything else as errors.
	log.Errorf("repro failed: %v", err)
}

func (mgr *Manager) runRepro(crash *Crash) *ReproResult {
	res, stats, err := repro.Run(crash.Output, mgr.cfg, mgr.enabledFeatures, mgr.reporter, mgr.pool)
	ret := &ReproResult{
		crash: crash,
		repro: res,
		stats: stats,
		err:   err,
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
				ret.strace = strace
				break
			}
		}
	}
	return ret
}

func (mgr *Manager) preloadCorpus() {
	corpusDB, err := db.Open(filepath.Join(mgr.cfg.Workdir, "corpus.db"), true)
	if err != nil {
		if corpusDB == nil {
			log.Fatalf("failed to open corpus database: %v", err)
		}
		log.Errorf("read %v inputs from corpus and got error: %v", len(corpusDB.Records), err)
	}
	mgr.corpusDB = corpusDB
	mgr.fresh = len(mgr.corpusDB.Records) == 0
	// By default we don't re-minimize/re-smash programs from corpus,
	// it takes lots of time on start and is unnecessary.
	// However, on version bumps we can selectively re-minimize/re-smash.
	corpusFlags := fuzzer.ProgFromCorpus | fuzzer.ProgMinimized | fuzzer.ProgSmashed
	switch mgr.corpusDB.Version {
	case 0:
		// Version 0 had broken minimization, so we need to re-minimize.
		corpusFlags &= ^fuzzer.ProgMinimized
		fallthrough
	case 1:
		// Version 1->2: memory is preallocated so lots of mmaps become unnecessary.
		corpusFlags &= ^fuzzer.ProgMinimized
		fallthrough
	case 2:
		// Version 2->3: big-endian hints.
		corpusFlags &= ^fuzzer.ProgSmashed
		fallthrough
	case 3:
		// Version 3->4: to shake things up.
		corpusFlags &= ^fuzzer.ProgMinimized
		fallthrough
	case 4:
		// Version 4->5: fix for comparison argument sign extension.
		// Introduced in 1ba0279d74a35e96e81de87073212d2b20256e8f.

		// Update (July 2024):
		// We used to reset the fuzzer.ProgSmashed flag here, but it has led to
		// perpetual corpus retriage on slow syzkaller instances. By now, all faster
		// instances must have already bumped their corpus versions, so let's just
		// increase the version to let all others go past the corpus triage stage.
		fallthrough
	case currentDBVersion:
	}
	type Input struct {
		IsSeed bool
		Key    string
		Data   []byte
		Prog   *prog.Prog
	}
	procs := runtime.GOMAXPROCS(0)
	inputs := make(chan *Input, procs)
	outputs := make(chan *Input, procs)
	var wg sync.WaitGroup
	wg.Add(procs)
	for p := 0; p < procs; p++ {
		go func() {
			defer wg.Done()
			for inp := range inputs {
				inp.Prog, _ = loadProg(mgr.target, inp.Data)
				outputs <- inp
			}
		}()
	}
	go func() {
		wg.Wait()
		close(outputs)
	}()
	go func() {
		for key, rec := range mgr.corpusDB.Records {
			inputs <- &Input{
				Key:  key,
				Data: rec.Val,
			}
		}
		seedDir := filepath.Join(mgr.cfg.Syzkaller, "sys", mgr.cfg.TargetOS, "test")
		if osutil.IsExist(seedDir) {
			seeds, err := os.ReadDir(seedDir)
			if err != nil {
				log.Fatalf("failed to read seeds dir: %v", err)
			}
			for _, seed := range seeds {
				data, err := os.ReadFile(filepath.Join(seedDir, seed.Name()))
				if err != nil {
					log.Fatalf("failed to read seed %v: %v", seed.Name(), err)
				}
				inputs <- &Input{
					IsSeed: true,
					Data:   data,
				}
			}
		}
		close(inputs)
	}()
	brokenSeeds := 0
	var brokenCorpus []string
	var candidates []fuzzer.Candidate
	for inp := range outputs {
		if inp.Prog == nil {
			if inp.IsSeed {
				brokenSeeds++
			} else {
				brokenCorpus = append(brokenCorpus, inp.Key)
			}
			continue
		}
		flags := corpusFlags
		if inp.IsSeed {
			if _, ok := mgr.corpusDB.Records[hash.String(inp.Prog.Serialize())]; ok {
				continue
			}
			// Seeds are not considered "from corpus" (won't be rerun multiple times)
			// b/c they are tried on every start anyway.
			flags = fuzzer.ProgMinimized
		}
		candidates = append(candidates, fuzzer.Candidate{
			Prog:  inp.Prog,
			Flags: flags,
		})
	}
	if len(brokenCorpus)+brokenSeeds != 0 {
		log.Logf(0, "broken programs in the corpus: %v, broken seeds: %v", len(brokenCorpus), brokenSeeds)
	}
	// This needs to be done outside of the loop above to not race with mgr.corpusDB reads.
	for _, sig := range brokenCorpus {
		mgr.corpusDB.Delete(sig)
	}
	if err := mgr.corpusDB.Flush(); err != nil {
		log.Fatalf("failed to save corpus database: %v", err)
	}
	// Switch database to the mode when it does not keep records in memory.
	// We don't need them anymore and they consume lots of memory.
	mgr.corpusDB.DiscardData()
	mgr.corpusPreload <- candidates
}

func (mgr *Manager) loadCorpus() []fuzzer.Candidate {
	seeds := 0
	var candidates []fuzzer.Candidate
	for _, item := range <-mgr.corpusPreload {
		if containsDisabled(item.Prog, mgr.targetEnabledSyscalls) {
			if mgr.cfg.PreserveCorpus {
				// This program contains a disabled syscall.
				// We won't execute it, but remember its hash so
				// it is not deleted during minimization.
				mgr.disabledHashes[hash.String(item.Prog.Serialize())] = struct{}{}
				continue
			}
			// We cut out the disabled syscalls and retriage/minimize what remains from the prog.
			// The original prog will be deleted from the corpus.
			item.Flags &= ^fuzzer.ProgMinimized
			programLeftover(mgr.target, mgr.targetEnabledSyscalls, item.Prog)
			if len(item.Prog.Calls) == 0 {
				continue
			}
		}
		if item.Flags&fuzzer.ProgFromCorpus == 0 {
			seeds++
		}
		candidates = append(candidates, item)
	}
	log.Logf(0, "%-24v: %v (%v seeds)", "corpus", len(candidates), seeds)
	return candidates
}

func programLeftover(target *prog.Target, enabled map[*prog.Syscall]bool, p *prog.Prog) {
	for i := 0; i < len(p.Calls); {
		c := p.Calls[i]
		if !enabled[c.Meta] {
			p.RemoveCall(i)
			continue
		}
		i++
	}
}

func loadProg(target *prog.Target, data []byte) (*prog.Prog, error) {
	p, err := target.Deserialize(data, prog.NonStrict)
	if err != nil {
		return nil, err
	}
	if len(p.Calls) > prog.MaxCalls {
		return nil, fmt.Errorf("longer than %d calls", prog.MaxCalls)
	}
	// For some yet unknown reasons, programs with fail_nth > 0 may sneak in. Ignore them.
	for _, call := range p.Calls {
		if call.Props.FailNth > 0 {
			return nil, fmt.Errorf("input has fail_nth > 0")
		}
	}
	return p, nil
}

func containsDisabled(p *prog.Prog, enabled map[*prog.Syscall]bool) bool {
	for _, c := range p.Calls {
		if !enabled[c.Meta] {
			return true
		}
	}
	return false
}

func (mgr *Manager) fuzzerInstance(ctx context.Context, inst *vm.Instance, updInfo dispatcher.UpdateInfo) {
	injectExec := make(chan bool, 10)
	mgr.serv.CreateInstance(inst.Index(), injectExec, updInfo)

	rep, vmInfo, err := mgr.runInstanceInner(ctx, inst, injectExec)
	lastExec, machineInfo := mgr.serv.ShutdownInstance(inst.Index(), rep != nil)
	if rep != nil {
		prependExecuting(rep, lastExec)
		if len(vmInfo) != 0 {
			machineInfo = append(append(vmInfo, '\n'), machineInfo...)
		}
		rep.MachineInfo = machineInfo
	}
	if err == nil && rep != nil {
		mgr.crashes <- &Crash{
			instanceIndex: inst.Index(),
			Report:        rep,
		}
	}
	if err != nil {
		log.Logf(1, "VM %v: failed with error: %v", inst.Index(), err)
	}
}

func (mgr *Manager) runInstanceInner(ctx context.Context, inst *vm.Instance,
	injectExec <-chan bool) (*report.Report, []byte, error) {
	fwdAddr, err := inst.Forward(mgr.serv.Port)
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
	_, rep, err := inst.Run(mgr.cfg.Timeouts.VMRunningTime, mgr.reporter, cmd,
		vm.ExitTimeout, vm.StopContext(ctx), vm.InjectExecuting(injectExec),
		vm.EarlyFinishCb(func() {
			// Depending on the crash type and kernel config, fuzzing may continue
			// running for several seconds even after kernel has printed a crash report.
			// This litters the log and we want to prevent it.
			mgr.serv.StopFuzzing(inst.Index())
		}),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to run fuzzer: %w", err)
	}
	if rep == nil {
		// This is the only "OK" outcome.
		log.Logf(0, "VM %v: running for %v, restarting", inst.Index(), time.Since(start))
		return nil, nil, nil
	}
	vmInfo, err := inst.Info()
	if err != nil {
		vmInfo = []byte(fmt.Sprintf("error getting VM info: %v\n", err))
	}
	return rep, vmInfo, nil
}

func prependExecuting(rep *report.Report, lastExec []rpcserver.ExecRecord) {
	buf := new(bytes.Buffer)
	fmt.Fprintf(buf, "last executing test programs:\n\n")
	for _, exec := range lastExec {
		fmt.Fprintf(buf, "%v ago: executing program %v (id=%v):\n%s\n", exec.Time, exec.Proc, exec.ID, exec.Prog)
	}
	fmt.Fprintf(buf, "kernel console output (not intermixed with test programs):\n\n")
	rep.Output = append(buf.Bytes(), rep.Output...)
	n := len(buf.Bytes())
	rep.StartPos += n
	rep.EndPos += n
	rep.SkipPos += n
}

func (mgr *Manager) emailCrash(crash *Crash) {
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

func (mgr *Manager) saveCrash(crash *Crash) bool {
	if err := mgr.reporter.Symbolize(crash.Report); err != nil {
		log.Errorf("failed to symbolize report: %v", err)
	}
	if crash.Type == crash_pkg.MemoryLeak {
		mgr.mu.Lock()
		mgr.memoryLeakFrames[crash.Frame] = true
		mgr.mu.Unlock()
	}
	if crash.Type == crash_pkg.DataRace {
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
	log.Logf(0, "VM %v: crash: %v%v", crash.instanceIndex, crash.Title, flags)

	if mgr.mode == ModeSmokeTest {
		data, err := json.Marshal(crash.Report)
		if err != nil {
			log.Fatalf("failed to serialize crash report: %v", err)
		}
		if err := osutil.WriteFile(filepath.Join(mgr.cfg.Workdir, "report.json"), data); err != nil {
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
			Report:      crash.Report.Report,
			MachineInfo: crash.MachineInfo,
		}
		setGuiltyFiles(dc, crash.Report)
		resp, err := mgr.dash.ReportCrash(dc)
		if err != nil {
			log.Logf(0, "failed to report crash to dashboard: %v", err)
		} else {
			// Don't store the crash locally, if we've successfully
			// uploaded it to the dashboard. These will just eat disk space.
			return mgr.cfg.Reproduce && resp.NeedRepro
		}
	}

	sig := hash.Hash([]byte(crash.Title))
	id := sig.String()
	dir := filepath.Join(mgr.crashdir, id)
	osutil.MkdirAll(dir)
	if err := osutil.WriteFile(filepath.Join(dir, "description"), []byte(crash.Title+"\n")); err != nil {
		log.Logf(0, "failed to write crash: %v", err)
	}

	// Save up to mgr.cfg.MaxCrashLogs reports, overwrite the oldest once we've reached that number.
	// Newer reports are generally more useful. Overwriting is also needed
	// to be able to understand if a particular bug still happens or already fixed.
	oldestI := 0
	var oldestTime time.Time
	for i := 0; i < mgr.cfg.MaxCrashLogs; i++ {
		info, err := os.Stat(filepath.Join(dir, fmt.Sprintf("log%v", i)))
		if err != nil {
			oldestI = i
			if i == 0 {
				go mgr.emailCrash(crash)
			}
			break
		}
		if oldestTime.IsZero() || info.ModTime().Before(oldestTime) {
			oldestI = i
			oldestTime = info.ModTime()
		}
	}
	writeOrRemove := func(name string, data []byte) {
		filename := filepath.Join(dir, name+fmt.Sprint(oldestI))
		if len(data) == 0 {
			os.Remove(filename)
			return
		}
		osutil.WriteFile(filename, data)
	}
	writeOrRemove("log", crash.Output)
	writeOrRemove("tag", []byte(mgr.cfg.Tag))
	writeOrRemove("report", crash.Report.Report)
	writeOrRemove("machineInfo", crash.MachineInfo)
	return mgr.needRepro(crash)
}

const maxReproAttempts = 3

func (mgr *Manager) needLocalRepro(crash *Crash) bool {
	if !mgr.cfg.Reproduce || crash.Corrupted || crash.Suppressed {
		return false
	}
	sig := hash.Hash([]byte(crash.Title))
	dir := filepath.Join(mgr.crashdir, sig.String())
	if osutil.IsExist(filepath.Join(dir, "repro.prog")) {
		return false
	}
	for i := 0; i < maxReproAttempts; i++ {
		if !osutil.IsExist(filepath.Join(dir, fmt.Sprintf("repro%v", i))) {
			return true
		}
	}
	return false
}

func (mgr *Manager) needRepro(crash *Crash) bool {
	if !mgr.cfg.Reproduce {
		return false
	}
	if crash.fromHub || crash.fromDashboard {
		return true
	}
	if !mgr.checkDone.Load() || (mgr.enabledFeatures&flatrpc.FeatureLeak != 0 &&
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
	reproLog := fullReproLog(stats)
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
		} else {
			return
		}
	}
	dir := filepath.Join(mgr.crashdir, hash.String([]byte(rep.Title)))
	osutil.MkdirAll(dir)
	for i := 0; i < maxReproAttempts; i++ {
		name := filepath.Join(dir, fmt.Sprintf("repro%v", i))
		if !osutil.IsExist(name) && len(reproLog) > 0 {
			osutil.WriteFile(name, reproLog)
			break
		}
	}
}

func (mgr *Manager) saveRepro(res *ReproResult) {
	repro := res.repro
	opts := fmt.Sprintf("# %+v\n", repro.Opts)
	progText := repro.Prog.Serialize()

	// Append this repro to repro list to send to hub if it didn't come from hub originally.
	if !res.crash.fromHub {
		progForHub := []byte(fmt.Sprintf("# %+v\n# %v\n# %v\n%s",
			repro.Opts, repro.Report.Title, mgr.cfg.Tag, progText))
		mgr.mu.Lock()
		mgr.newRepros = append(mgr.newRepros, progForHub)
		mgr.mu.Unlock()
	}

	var cprogText []byte
	if repro.CRepro {
		cprog, err := csource.Write(repro.Prog, repro.Opts)
		if err == nil {
			formatted, err := csource.Format(cprog)
			if err == nil {
				cprog = formatted
			}
			cprogText = cprog
		} else {
			log.Logf(0, "failed to write C source: %v", err)
		}
	}

	if mgr.dash != nil {
		// Note: we intentionally don't set Corrupted for reproducers:
		// 1. This is reproducible so can be debugged even with corrupted report.
		// 2. Repro re-tried 3 times and still got corrupted report at the end,
		//    so maybe corrupted report detection is broken.
		// 3. Reproduction is expensive so it's good to persist the result.

		report := repro.Report
		output := report.Output

		var crashFlags dashapi.CrashFlags
		if res.strace != nil {
			// If syzkaller managed to successfully run the repro with strace, send
			// the report and the output generated under strace.
			report = res.strace.Report
			output = res.strace.Output
			crashFlags = dashapi.CrashUnderStrace
		}

		dc := &dashapi.Crash{
			BuildID:       mgr.cfg.Tag,
			Title:         report.Title,
			AltTitles:     report.AltTitles,
			Suppressed:    report.Suppressed,
			Recipients:    report.Recipients.ToDash(),
			Log:           output,
			Flags:         crashFlags,
			Report:        report.Report,
			ReproOpts:     repro.Opts.Serialize(),
			ReproSyz:      progText,
			ReproC:        cprogText,
			ReproLog:      truncateReproLog(fullReproLog(res.stats)),
			Assets:        mgr.uploadReproAssets(repro),
			OriginalTitle: res.crash.Title,
		}
		setGuiltyFiles(dc, report)
		if _, err := mgr.dash.ReportCrash(dc); err != nil {
			log.Logf(0, "failed to report repro to dashboard: %v", err)
		} else {
			// Don't store the crash locally, if we've successfully
			// uploaded it to the dashboard. These will just eat disk space.
			return
		}
	}

	rep := repro.Report
	dir := filepath.Join(mgr.crashdir, hash.String([]byte(rep.Title)))
	osutil.MkdirAll(dir)

	if err := osutil.WriteFile(filepath.Join(dir, "description"), []byte(rep.Title+"\n")); err != nil {
		log.Logf(0, "failed to write crash: %v", err)
	}
	osutil.WriteFile(filepath.Join(dir, "repro.prog"), append([]byte(opts), progText...))
	if mgr.cfg.Tag != "" {
		osutil.WriteFile(filepath.Join(dir, "repro.tag"), []byte(mgr.cfg.Tag))
	}
	if len(rep.Output) > 0 {
		osutil.WriteFile(filepath.Join(dir, "repro.log"), rep.Output)
	}
	if len(rep.Report) > 0 {
		osutil.WriteFile(filepath.Join(dir, "repro.report"), rep.Report)
	}
	if len(cprogText) > 0 {
		osutil.WriteFile(filepath.Join(dir, "repro.cprog"), cprogText)
	}
	repro.Prog.ForEachAsset(func(name string, typ prog.AssetType, r io.Reader) {
		fileName := filepath.Join(dir, name+".gz")
		if err := osutil.WriteGzipStream(fileName, r); err != nil {
			log.Logf(0, "failed to write crash asset: type %d, write error %v", typ, err)
		}
	})
	if res.strace != nil {
		// Unlike dashboard reporting, we save strace output separately from the original log.
		if res.strace.Error != nil {
			osutil.WriteFile(filepath.Join(dir, "strace.error"),
				[]byte(fmt.Sprintf("%v", res.strace.Error)))
		}
		if len(res.strace.Output) > 0 {
			osutil.WriteFile(filepath.Join(dir, "strace.log"), res.strace.Output)
		}
	}
	if reproLog := fullReproLog(res.stats); len(reproLog) > 0 {
		osutil.WriteFile(filepath.Join(dir, "repro.stats"), reproLog)
	}
}

func (mgr *Manager) resizeReproPool(size int) {
	mgr.pool.ReserveForRun(size)
}

func (mgr *Manager) uploadReproAssets(repro *repro.Result) []dashapi.NewAsset {
	if mgr.assetStorage == nil {
		return nil
	}

	ret := []dashapi.NewAsset{}
	repro.Prog.ForEachAsset(func(name string, typ prog.AssetType, r io.Reader) {
		dashTyp, ok := map[prog.AssetType]dashapi.AssetType{
			prog.MountInRepro: dashapi.MountInRepro,
		}[typ]
		if !ok {
			panic("unknown extracted prog asset")
		}
		asset, err := mgr.assetStorage.UploadCrashAsset(r, name, dashTyp, nil)
		if err != nil {
			log.Logf(1, "processing of the asset %v (%v) failed: %v", name, typ, err)
			return
		}
		ret = append(ret, asset)
	})
	return ret
}

func fullReproLog(stats *repro.Stats) []byte {
	if stats == nil {
		return nil
	}
	return []byte(fmt.Sprintf("Extracting prog: %v\nMinimizing prog: %v\n"+
		"Simplifying prog options: %v\nExtracting C: %v\nSimplifying C: %v\n\n\n%s",
		stats.ExtractProgTime, stats.MinimizeProgTime,
		stats.SimplifyProgTime, stats.ExtractCTime, stats.SimplifyCTime, stats.Log))
}

func (mgr *Manager) corpusInputHandler(updates <-chan corpus.NewItemEvent) {
	for update := range updates {
		if len(update.NewCover) != 0 && mgr.coverFilter != nil {
			filtered := 0
			for _, pc := range update.NewCover {
				pc = backend.PreviousInstructionPC(mgr.cfg.SysTarget, mgr.cfg.Type, pc)
				if _, ok := mgr.coverFilter[pc]; ok {
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

func (mgr *Manager) getMinimizedCorpus() (corpus []*corpus.Item, repros [][]byte) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	mgr.minimizeCorpusLocked()
	corpus = mgr.corpus.Items()
	repros = mgr.newRepros
	mgr.newRepros = nil
	return
}

func (mgr *Manager) addNewCandidates(candidates []fuzzer.Candidate) {
	mgr.mu.Lock()
	if mgr.phase == phaseTriagedCorpus {
		mgr.phase = phaseQueriedHub
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
	mgr.corpusDB.BumpVersion(currentDBVersion)
}

func setGuiltyFiles(crash *dashapi.Crash, report *report.Report) {
	if report.GuiltyFile != "" {
		crash.GuiltyFiles = []string{report.GuiltyFile}
	}
}

func (mgr *Manager) collectSyscallInfo() map[string]*corpus.CallCov {
	mgr.mu.Lock()
	enabledSyscalls := mgr.targetEnabledSyscalls
	mgr.mu.Unlock()

	if enabledSyscalls == nil {
		return nil
	}
	calls := mgr.corpus.CallCover()
	// Add enabled, but not yet covered calls.
	for call := range enabledSyscalls {
		if calls[call.Name] == nil {
			calls[call.Name] = new(corpus.CallCov)
		}
	}
	return calls
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

func (mgr *Manager) MachineChecked(features flatrpc.Feature, enabledSyscalls map[*prog.Syscall]bool) queue.Source {
	if len(enabledSyscalls) == 0 {
		log.Fatalf("all system calls are disabled")
	}
	if mgr.mode == ModeSmokeTest {
		mgr.exit("smoke test")
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
	mgr.targetEnabledSyscalls = enabledSyscalls
	mgr.firstConnect.Store(time.Now().Unix())
	statSyscalls := stat.New("syscalls", "Number of enabled syscalls",
		stat.Simple, stat.NoGraph, stat.Link("/syscalls"))
	statSyscalls.Add(len(enabledSyscalls))
	corpus := mgr.loadCorpus()
	mgr.phase = phaseLoadedCorpus
	opts := mgr.defaultExecOpts()

	if mgr.mode == ModeFuzzing {
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
			Logf: func(level int, msg string, args ...interface{}) {
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
		}, rnd, mgr.target)
		fuzzerObj.AddCandidates(corpus)
		mgr.fuzzer.Store(fuzzerObj)

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
			log.Logf(0, "stopping VMs for snapshot mode")
			mgr.source = source
			mgr.loopStop()
			return queue.Callback(func() *queue.Request {
				return nil
			})
		}
		return source
	} else if mgr.mode == ModeCorpusRun {
		ctx := &corpusRunner{
			candidates: corpus,
			rnd:        rand.New(rand.NewSource(time.Now().UnixNano())),
		}
		return queue.DefaultOpts(ctx, opts)
	} else if mgr.mode == ModeRunTests {
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
		}
		ctx.Init()
		go func() {
			err := ctx.Run(context.Background())
			if err != nil {
				log.Fatal(err)
			}
			mgr.exit("tests")
		}()
		return ctx
	}
	panic(fmt.Sprintf("unexpected mode %q", mgr.mode))
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

func (mgr *Manager) defaultExecOpts() flatrpc.ExecOpts {
	env := csource.FeaturesToFlags(mgr.enabledFeatures, nil)
	if *flagDebug {
		env |= flatrpc.ExecEnvDebug
	}
	if mgr.cfg.Experimental.ResetAccState {
		env |= flatrpc.ExecEnvResetState
	}
	if mgr.cfg.Cover {
		env |= flatrpc.ExecEnvSignal
	}
	sandbox, err := flatrpc.SandboxToFlags(mgr.cfg.Sandbox)
	if err != nil {
		panic(fmt.Sprintf("failed to parse sandbox: %v", err))
	}
	env |= sandbox

	exec := flatrpc.ExecFlagThreaded
	if !mgr.cfg.RawCover {
		exec |= flatrpc.ExecFlagDedupCover
	}
	return flatrpc.ExecOpts{
		EnvFlags:   env,
		ExecFlags:  exec,
		SandboxArg: mgr.cfg.SandboxArg,
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
			log.Logf(3, "distributing %d new signal", len(newSignal))
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
			if mgr.phase == phaseLoadedCorpus {
				if !mgr.cfg.Snapshot {
					mgr.serv.TriagedCorpus()
				}
				if mgr.cfg.HubClient != "" {
					mgr.phase = phaseTriagedCorpus
					go mgr.hubSyncLoop(pickGetter(mgr.cfg.HubKey))
				} else {
					mgr.phase = phaseTriagedHub
					mgr.reproMgr.StartReproduction()
				}
			} else if mgr.phase == phaseQueriedHub {
				mgr.phase = phaseTriagedHub
				mgr.reproMgr.StartReproduction()
			}
			mgr.mu.Unlock()
		}
	}
}

func (mgr *Manager) needMoreCandidates() bool {
	return mgr.fuzzer.Load().CandidateTriageFinished()
}

func (mgr *Manager) hubIsUnreachable() {
	var dash *dashapi.Dashboard
	mgr.mu.Lock()
	if mgr.phase == phaseTriagedCorpus {
		dash = mgr.dash
		mgr.phase = phaseTriagedHub
		mgr.reproMgr.StartReproduction()
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
		req := &dashapi.ManagerStatsReq{
			Name:              mgr.cfg.Name,
			Addr:              webAddr,
			UpTime:            time.Duration(mgr.statUptime.Val()) * time.Second,
			Corpus:            uint64(mgr.corpus.StatProgs.Val()),
			PCs:               uint64(mgr.corpus.StatCover.Val()),
			Cover:             uint64(mgr.corpus.StatSignal.Val()),
			CrashTypes:        uint64(mgr.statCrashTypes.Val()),
			FuzzingTime:       time.Duration(mgr.statFuzzingTime.Val()) - lastFuzzingTime,
			Crashes:           uint64(mgr.statCrashes.Val()) - lastCrashes,
			SuppressedCrashes: uint64(mgr.statSuppressed.Val()) - lastSuppressedCrashes,
			Execs:             uint64(queue.StatExecs.Val()) - lastExecs,
		}
		if mgr.phase >= phaseTriagedCorpus && !triageInfoSent {
			triageInfoSent = true
			req.TriagedCoverage = uint64(mgr.corpus.StatSignal.Val())
			req.TriagedPCs = uint64(mgr.corpus.StatCover.Val())
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
		if !mgr.reproMgr.CanReproMore() {
			// We don't need reproducers at the moment.
			continue
		}
		resp, err := mgr.dash.LogToRepro(&dashapi.LogToReproReq{BuildID: mgr.cfg.Tag})
		if err != nil {
			log.Logf(0, "failed to query logs to reproduce: %v", err)
			continue
		}
		if len(resp.CrashLog) > 0 {
			mgr.externalReproQueue <- &Crash{
				fromDashboard: true,
				manual:        resp.Type == dashapi.ManualLog,
				Report: &report.Report{
					Title:  resp.Title,
					Output: resp.CrashLog,
				},
			}
		}
	}
}

func publicWebAddr(addr string) string {
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
