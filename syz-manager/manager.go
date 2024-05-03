// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/asset"
	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/gce"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	crash_pkg "github.com/google/syzkaller/pkg/report/crash"
	"github.com/google/syzkaller/pkg/repro"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/stats"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/vm"
)

var (
	flagConfig = flag.String("config", "", "configuration file")
	flagDebug  = flag.Bool("debug", false, "dump all VM output to console")
	flagBench  = flag.String("bench", "", "write execution statistics into this file periodically")
)

type Manager struct {
	cfg             *mgrconfig.Config
	vmPool          *vm.Pool
	target          *prog.Target
	sysTarget       *targets.Target
	reporter        *report.Reporter
	crashdir        string
	serv            *RPCServer
	corpus          *corpus.Corpus
	corpusDB        *db.DB
	corpusDBMu      sync.Mutex // for concurrent operations on corpusDB
	corpusPreloaded chan bool
	firstConnect    atomic.Int64 // unix time, or 0 if not connected
	crashTypes      map[string]bool
	vmStop          chan bool
	enabledFeatures flatrpc.Feature
	checkDone       bool
	fresh           bool
	expertMode      bool
	nextInstanceID  atomic.Uint64

	dash *dashapi.Dashboard

	mu                    sync.Mutex
	fuzzer                atomic.Pointer[fuzzer.Fuzzer]
	execSource            atomic.Value // queue.Source
	phase                 int
	targetEnabledSyscalls map[*prog.Syscall]bool

	disabledHashes   map[string]struct{}
	seeds            [][]byte
	newRepros        [][]byte
	lastMinCorpus    int
	memoryLeakFrames map[string]bool
	dataRaceFrames   map[string]bool
	saturatedCalls   map[string]bool

	needMoreRepros     chan chan bool
	externalReproQueue chan *Crash
	reproRequest       chan chan map[string]bool

	// For checking that files that we are using are not changing under us.
	// Maps file name to modification time.
	usedFiles map[string]time.Time

	assetStorage *asset.Storage

	bootTime stats.AverageValue[time.Duration]

	Stats
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

const currentDBVersion = 4

type Crash struct {
	instanceName  string
	fromHub       bool // this crash was created based on a repro from syz-hub
	fromDashboard bool // .. or from dashboard
	*report.Report
	machineInfo []byte
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
	RunManager(cfg)
}

func RunManager(cfg *mgrconfig.Config) {
	var vmPool *vm.Pool
	// Type "none" is a special case for debugging/development when manager
	// does not start any VMs, but instead you start them manually
	// and start syz-fuzzer there.
	if cfg.Type != "none" {
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

	corpusUpdates := make(chan corpus.NewItemEvent, 32)
	mgr := &Manager{
		cfg:                cfg,
		vmPool:             vmPool,
		corpus:             corpus.NewMonitoredCorpus(context.Background(), corpusUpdates),
		corpusPreloaded:    make(chan bool),
		target:             cfg.Target,
		sysTarget:          cfg.SysTarget,
		reporter:           reporter,
		crashdir:           crashdir,
		crashTypes:         make(map[string]bool),
		disabledHashes:     make(map[string]struct{}),
		memoryLeakFrames:   make(map[string]bool),
		dataRaceFrames:     make(map[string]bool),
		fresh:              true,
		vmStop:             make(chan bool),
		externalReproQueue: make(chan *Crash, 10),
		needMoreRepros:     make(chan chan bool),
		reproRequest:       make(chan chan map[string]bool),
		usedFiles:          make(map[string]time.Time),
		saturatedCalls:     make(map[string]bool),
	}

	mgr.initStats()
	go mgr.preloadCorpus()
	mgr.initHTTP() // Creates HTTP server.
	mgr.collectUsedFiles()
	go mgr.corpusInputHandler(corpusUpdates)

	// Create RPC server for fuzzers.
	mgr.serv, err = startRPCServer(mgr)
	if err != nil {
		log.Fatalf("failed to create rpc server: %v", err)
	}

	if cfg.DashboardAddr != "" {
		mgr.dash, err = dashapi.New(cfg.DashboardClient, cfg.DashboardAddr, cfg.DashboardKey)
		if err != nil {
			log.Fatalf("failed to create dashapi connection: %v", err)
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
	osutil.HandleInterrupts(vm.Shutdown)
	if mgr.vmPool == nil {
		log.Logf(0, "no VMs started (type=none)")
		log.Logf(0, "you are supposed to start syz-fuzzer manually as:")
		log.Logf(0, "syz-fuzzer -manager=manager.ip:%v [other flags as necessary]", mgr.serv.port)
		<-vm.Shutdown
		return
	}
	mgr.vmLoop()
}

func (mgr *Manager) heartbeatLoop() {
	lastTime := time.Now()
	for now := range time.NewTicker(10 * time.Second).C {
		diff := int(now.Sub(lastTime))
		lastTime = now
		if mgr.firstConnect.Load() == 0 {
			continue
		}
		mgr.statFuzzingTime.Add(diff * mgr.statNumFuzzing.Val())
		buf := new(bytes.Buffer)
		for _, stat := range stats.Collect(stats.Console) {
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
	go func() {
		for range time.NewTicker(time.Minute).C {
			vals := make(map[string]int)
			for _, stat := range stats.Collect(stats.All) {
				vals[stat.Name] = stat.V
			}
			data, err := json.MarshalIndent(vals, "", "  ")
			if err != nil {
				log.Fatalf("failed to serialize bench data")
			}
			if _, err := f.Write(append(data, '\n')); err != nil {
				log.Fatalf("failed to write bench data")
			}
		}
	}()
}

type RunResult struct {
	idx   int
	crash *Crash
	err   error
}

type ReproResult struct {
	instances     []int
	report0       *report.Report // the original report we started reproducing
	repro         *repro.Result
	strace        *repro.StraceResult
	stats         *repro.Stats
	err           error
	fromHub       bool
	fromDashboard bool
	originalTitle string // crash title before we started bug reproduction
}

// Manager needs to be refactored (#605).
// nolint: gocyclo, gocognit, funlen
func (mgr *Manager) vmLoop() {
	log.Logf(0, "booting test machines...")
	log.Logf(0, "wait for the connection from test machine...")
	instancesPerRepro := 3
	vmCount := mgr.vmPool.Count()
	maxReproVMs := vmCount - mgr.cfg.FuzzingVMs
	if instancesPerRepro > maxReproVMs && maxReproVMs > 0 {
		instancesPerRepro = maxReproVMs
	}
	instances := SequentialResourcePool(vmCount, 5*time.Second)
	runDone := make(chan *RunResult, 1)
	pendingRepro := make(map[*Crash]bool)
	reproducing := make(map[string]bool)
	var reproQueue []*Crash
	reproDone := make(chan *ReproResult, 1)
	stopPending := false
	shutdown := vm.Shutdown
	for shutdown != nil || instances.Len() != vmCount {
		mgr.mu.Lock()
		phase := mgr.phase
		mgr.mu.Unlock()

		for crash := range pendingRepro {
			if reproducing[crash.Title] {
				continue
			}
			delete(pendingRepro, crash)
			if !mgr.needRepro(crash) {
				continue
			}
			log.Logf(1, "loop: add to repro queue '%v'", crash.Title)
			reproducing[crash.Title] = true
			reproQueue = append(reproQueue, crash)
		}

		log.Logf(1, "loop: phase=%v shutdown=%v instances=%v/%v %+v repro: pending=%v reproducing=%v queued=%v",
			phase, shutdown == nil, instances.Len(), vmCount, instances.Snapshot(),
			len(pendingRepro), len(reproducing), len(reproQueue))

		canRepro := func() bool {
			return phase >= phaseTriagedHub && len(reproQueue) != 0 &&
				(mgr.statNumReproducing.Val()+1)*instancesPerRepro <= maxReproVMs
		}

		if shutdown != nil {
			for canRepro() {
				vmIndexes := instances.Take(instancesPerRepro)
				if vmIndexes == nil {
					break
				}
				last := len(reproQueue) - 1
				crash := reproQueue[last]
				reproQueue[last] = nil
				reproQueue = reproQueue[:last]
				mgr.statNumReproducing.Add(1)
				log.Logf(0, "loop: starting repro of '%v' on instances %+v", crash.Title, vmIndexes)
				go func() {
					reproDone <- mgr.runRepro(crash, vmIndexes, instances.Put)
				}()
			}
			for !canRepro() {
				idx := instances.TakeOne()
				if idx == nil {
					break
				}
				log.Logf(1, "loop: starting instance %v", *idx)
				go func() {
					crash, err := mgr.runInstance(*idx)
					runDone <- &RunResult{*idx, crash, err}
				}()
			}
		}

		var stopRequest chan bool
		if !stopPending && canRepro() {
			stopRequest = mgr.vmStop
		}

	wait:
		select {
		case <-instances.Freed:
			// An instance has been released.
		case stopRequest <- true:
			log.Logf(1, "loop: issued stop request")
			stopPending = true
		case res := <-runDone:
			log.Logf(1, "loop: instance %v finished, crash=%v", res.idx, res.crash != nil)
			if res.err != nil && shutdown != nil {
				log.Logf(0, "%v", res.err)
			}
			stopPending = false
			instances.Put(res.idx)
			// On shutdown qemu crashes with "qemu: terminating on signal 2",
			// which we detect as "lost connection". Don't save that as crash.
			if shutdown != nil && res.crash != nil {
				needRepro := mgr.saveCrash(res.crash)
				if needRepro {
					log.Logf(1, "loop: add pending repro for '%v'", res.crash.Title)
					pendingRepro[res.crash] = true
				}
			}
		case res := <-reproDone:
			mgr.statNumReproducing.Add(-1)
			crepro := false
			title := ""
			if res.repro != nil {
				crepro = res.repro.CRepro
				title = res.repro.Report.Title
			}
			log.Logf(0, "loop: repro on %+v finished '%v', repro=%v crepro=%v desc='%v'"+
				" hub=%v from_dashboard=%v",
				res.instances, res.report0.Title, res.repro != nil, crepro, title,
				res.fromHub, res.fromDashboard,
			)
			if res.err != nil {
				reportReproError(res.err)
			}
			delete(reproducing, res.report0.Title)
			if res.repro == nil {
				if res.fromHub {
					log.Logf(1, "repro '%v' came from syz-hub, not reporting the failure",
						res.report0.Title)
				} else {
					log.Logf(1, "report repro failure of '%v'", res.report0.Title)
					mgr.saveFailedRepro(res.report0, res.stats)
				}
			} else {
				mgr.saveRepro(res)
			}
		case <-shutdown:
			log.Logf(1, "loop: shutting down...")
			shutdown = nil
		case crash := <-mgr.externalReproQueue:
			log.Logf(1, "loop: got repro request")
			pendingRepro[crash] = true
		case reply := <-mgr.needMoreRepros:
			reply <- phase >= phaseTriagedHub &&
				len(reproQueue)+len(pendingRepro)+len(reproducing) == 0
			goto wait
		case reply := <-mgr.reproRequest:
			repros := make(map[string]bool)
			for title := range reproducing {
				repros[title] = true
			}
			reply <- repros
			goto wait
		}
	}
}

func reportReproError(err error) {
	shutdown := false
	select {
	case <-vm.Shutdown:
		shutdown = true
	default:
	}

	switch err {
	case repro.ErrNoPrograms:
		// This is not extraordinary as programs are collected via SSH.
		log.Logf(0, "repro failed: %v", err)
		return
	case repro.ErrNoVMs:
		// This error is to be expected if we're shutting down.
		if shutdown {
			return
		}
	}
	// Report everything else as errors.
	log.Errorf("repro failed: %v", err)
}

func (mgr *Manager) runRepro(crash *Crash, vmIndexes []int, putInstances func(...int)) *ReproResult {
	res, stats, err := repro.Run(crash.Output, mgr.cfg, mgr.enabledFeatures, mgr.reporter, mgr.vmPool, vmIndexes)
	ret := &ReproResult{
		instances:     vmIndexes,
		report0:       crash.Report,
		repro:         res,
		stats:         stats,
		err:           err,
		fromHub:       crash.fromHub,
		fromDashboard: crash.fromDashboard,
		originalTitle: crash.Title,
	}
	if err == nil && res != nil && mgr.cfg.StraceBin != "" {
		// We need only one instance to get strace output, release the rest.
		putInstances(vmIndexes[1:]...)
		defer putInstances(vmIndexes[0])

		const straceAttempts = 2
		for i := 1; i <= straceAttempts; i++ {
			strace := repro.RunStrace(res, mgr.cfg, mgr.reporter, mgr.vmPool, vmIndexes[0])
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
	} else {
		putInstances(vmIndexes...)
	}
	return ret
}

type ResourcePool struct {
	ids   []int
	mu    sync.RWMutex
	Freed chan interface{}
}

func SequentialResourcePool(count int, delay time.Duration) *ResourcePool {
	ret := &ResourcePool{Freed: make(chan interface{}, 1)}
	go func() {
		for i := 0; i < count; i++ {
			ret.Put(i)
			time.Sleep(delay)
		}
	}()
	return ret
}

func (pool *ResourcePool) Put(ids ...int) {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	pool.ids = append(pool.ids, ids...)
	// Notify the listener.
	select {
	case pool.Freed <- true:
	default:
	}
}

func (pool *ResourcePool) Len() int {
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	return len(pool.ids)
}

func (pool *ResourcePool) Snapshot() []int {
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	return append([]int{}, pool.ids...)
}

func (pool *ResourcePool) Take(cnt int) []int {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	totalItems := len(pool.ids)
	if totalItems < cnt {
		return nil
	}
	ret := append([]int{}, pool.ids[totalItems-cnt:]...)
	pool.ids = pool.ids[:totalItems-cnt]
	return ret
}

func (pool *ResourcePool) TakeOne() *int {
	ret := pool.Take(1)
	if ret == nil {
		return nil
	}
	return &ret[0]
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

	if seedDir := filepath.Join(mgr.cfg.Syzkaller, "sys", mgr.cfg.TargetOS, "test"); osutil.IsExist(seedDir) {
		seeds, err := os.ReadDir(seedDir)
		if err != nil {
			log.Fatalf("failed to read seeds dir: %v", err)
		}
		for _, seed := range seeds {
			data, err := os.ReadFile(filepath.Join(seedDir, seed.Name()))
			if err != nil {
				log.Fatalf("failed to read seed %v: %v", seed.Name(), err)
			}
			mgr.seeds = append(mgr.seeds, data)
		}
	}
	close(mgr.corpusPreloaded)
}

func (mgr *Manager) loadCorpus() {
	<-mgr.corpusPreloaded
	// By default we don't re-minimize/re-smash programs from corpus,
	// it takes lots of time on start and is unnecessary.
	// However, on version bumps we can selectively re-minimize/re-smash.
	minimized, smashed := true, true
	switch mgr.corpusDB.Version {
	case 0:
		// Version 0 had broken minimization, so we need to re-minimize.
		minimized = false
		fallthrough
	case 1:
		// Version 1->2: memory is preallocated so lots of mmaps become unnecessary.
		minimized = false
		fallthrough
	case 2:
		// Version 2->3: big-endian hints.
		smashed = false
		fallthrough
	case 3:
		// Version 3->4: to shake things up.
		minimized = false
		fallthrough
	case currentDBVersion:
	}
	var candidates []fuzzer.Candidate
	broken := 0
	for key, rec := range mgr.corpusDB.Records {
		drop, item := mgr.loadProg(rec.Val, minimized, smashed)
		if drop {
			mgr.corpusDB.Delete(key)
			broken++
		}
		if item != nil {
			candidates = append(candidates, *item)
		}
	}
	mgr.fresh = len(mgr.corpusDB.Records) == 0
	seeds := 0
	for _, seed := range mgr.seeds {
		_, item := mgr.loadProg(seed, true, false)
		if item != nil {
			candidates = append(candidates, *item)
			seeds++
		}
	}
	log.Logf(0, "%-24v: %v (%v broken, %v seeds)", "corpus", len(candidates), broken, seeds)
	mgr.seeds = nil

	// We duplicate all inputs in the corpus and shuffle the second part.
	// This solves the following problem. A fuzzer can crash while triaging candidates,
	// in such case it will also lost all cached candidates. Or, the input can be somewhat flaky
	// and doesn't give the coverage on first try. So we give each input the second chance.
	// Shuffling should alleviate deterministically losing the same inputs on fuzzer crashing.
	candidates = append(candidates, candidates...)
	shuffle := candidates[len(candidates)/2:]
	rand.Shuffle(len(shuffle), func(i, j int) {
		shuffle[i], shuffle[j] = shuffle[j], shuffle[i]
	})
	if mgr.phase != phaseInit {
		panic(fmt.Sprintf("loadCorpus: bad phase %v", mgr.phase))
	}
	mgr.phase = phaseLoadedCorpus
	mgr.fuzzer.Load().AddCandidates(candidates)
}

// Returns (delete item from the corpus, a fuzzer.Candidate object).
func (mgr *Manager) loadProg(data []byte, minimized, smashed bool) (drop bool, candidate *fuzzer.Candidate) {
	p, disabled, bad := parseProgram(mgr.target, mgr.targetEnabledSyscalls, data)
	if bad != nil {
		return true, nil
	}
	if disabled {
		if mgr.cfg.PreserveCorpus {
			// This program contains a disabled syscall.
			// We won't execute it, but remember its hash so
			// it is not deleted during minimization.
			mgr.disabledHashes[hash.String(data)] = struct{}{}
		} else {
			// We cut out the disabled syscalls and let syz-fuzzer retriage and
			// minimize what remains from the prog. The original prog will be
			// deleted from the corpus.
			leftover := programLeftover(mgr.target, mgr.targetEnabledSyscalls, data)
			if leftover != nil {
				candidate = &fuzzer.Candidate{
					Prog:      leftover,
					Minimized: false,
					Smashed:   smashed,
				}
			}
		}
		return false, candidate
	}
	return false, &fuzzer.Candidate{
		Prog:      p,
		Minimized: minimized,
		Smashed:   smashed,
	}
}

func programLeftover(target *prog.Target, enabled map[*prog.Syscall]bool, data []byte) *prog.Prog {
	p, err := target.Deserialize(data, prog.NonStrict)
	if err != nil {
		panic(fmt.Sprintf("subsequent deserialization failed: %s", data))
	}
	for i := 0; i < len(p.Calls); {
		c := p.Calls[i]
		if !enabled[c.Meta] {
			p.RemoveCall(i)
			continue
		}
		i++
	}
	return p
}

func parseProgram(target *prog.Target, enabled map[*prog.Syscall]bool, data []byte) (
	p *prog.Prog, disabled bool, err error) {
	p, err = target.Deserialize(data, prog.NonStrict)
	if err != nil {
		return
	}
	if len(p.Calls) > prog.MaxCalls {
		return nil, false, fmt.Errorf("longer than %d calls", prog.MaxCalls)
	}
	// For some yet unknown reasons, programs with fail_nth > 0 may sneak in. Ignore them.
	for _, call := range p.Calls {
		if call.Props.FailNth > 0 {
			return nil, false, fmt.Errorf("input has fail_nth > 0")
		}
	}
	for _, c := range p.Calls {
		if !enabled[c.Meta] {
			return p, true, nil
		}
	}
	return p, false, nil
}

func (mgr *Manager) runInstance(index int) (*Crash, error) {
	mgr.checkUsedFiles()
	var maxSignal signal.Signal
	if fuzzer := mgr.fuzzer.Load(); fuzzer != nil {
		maxSignal = fuzzer.Cover.CopyMaxSignal()
	}
	// Use unique instance names to prevent name collisions in case of untimely RPC messages.
	instanceName := fmt.Sprintf("vm-%d", mgr.nextInstanceID.Add(1))
	injectLog := make(chan []byte, 10)
	mgr.serv.createInstance(instanceName, maxSignal, injectLog)

	rep, vmInfo, err := mgr.runInstanceInner(index, instanceName, injectLog)
	machineInfo := mgr.serv.shutdownInstance(instanceName, rep != nil)
	if len(vmInfo) != 0 {
		machineInfo = append(append(vmInfo, '\n'), machineInfo...)
	}

	// Error that is not a VM crash.
	if err != nil {
		return nil, err
	}
	// No crash.
	if rep == nil {
		return nil, nil
	}
	crash := &Crash{
		instanceName: instanceName,
		Report:       rep,
		machineInfo:  machineInfo,
	}
	return crash, nil
}

func (mgr *Manager) runInstanceInner(index int, instanceName string, injectLog <-chan []byte) (
	*report.Report, []byte, error) {
	start := time.Now()

	inst, err := mgr.vmPool.Create(index)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create instance: %w", err)
	}
	defer inst.Close()

	fwdAddr, err := inst.Forward(mgr.serv.port)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to setup port forwarding: %w", err)
	}

	fuzzerBin, err := inst.Copy(mgr.cfg.FuzzerBin)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to copy binary: %w", err)
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

	fuzzerV := 0
	procs := mgr.cfg.Procs
	if *flagDebug {
		fuzzerV = 100
		procs = 1
	}

	// Run the fuzzer binary.
	mgr.bootTime.Save(time.Since(start))
	start = time.Now()
	mgr.statNumFuzzing.Add(1)
	defer mgr.statNumFuzzing.Add(-1)

	args := &instance.FuzzerCmdArgs{
		Fuzzer:    fuzzerBin,
		Executor:  executorBin,
		Name:      instanceName,
		OS:        mgr.cfg.TargetOS,
		Arch:      mgr.cfg.TargetArch,
		FwdAddr:   fwdAddr,
		Sandbox:   mgr.cfg.Sandbox,
		Procs:     procs,
		Verbosity: fuzzerV,
		Cover:     mgr.cfg.Cover,
		Debug:     *flagDebug,
		Test:      false,
		Optional: &instance.OptionalFuzzerArgs{
			Slowdown:   mgr.cfg.Timeouts.Slowdown,
			SandboxArg: mgr.cfg.SandboxArg,
			PprofPort:  inst.PprofPort(),
		},
	}
	cmd := instance.FuzzerCmd(args)
	_, rep, err := inst.Run(mgr.cfg.Timeouts.VMRunningTime, mgr.reporter, cmd,
		vm.ExitTimeout, vm.StopChan(mgr.vmStop), vm.InjectOutput(injectLog),
		vm.EarlyFinishCb(func() {
			// Depending on the crash type and kernel config, fuzzing may continue
			// running for several seconds even after kernel has printed a crash report.
			// This litters the log and we want to prevent it.
			mgr.serv.stopFuzzing(instanceName)
		}),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to run fuzzer: %w", err)
	}
	if rep == nil {
		// This is the only "OK" outcome.
		log.Logf(0, "%s: running for %v, restarting", instanceName, time.Since(start))
		return nil, nil, nil
	}
	vmInfo, err := inst.Info()
	if err != nil {
		vmInfo = []byte(fmt.Sprintf("error getting VM info: %v\n", err))
	}
	return rep, vmInfo, nil
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
	log.Logf(0, "%s: crash: %v%v", crash.instanceName, crash.Title, flags)

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
			MachineInfo: crash.machineInfo,
		}
		setGuiltyFiles(dc, crash.Report)
		resp, err := mgr.dash.ReportCrash(dc)
		if err != nil {
			log.Logf(0, "failed to report crash to dashboard: %v", err)
		} else {
			// Don't store the crash locally, if we've successfully
			// uploaded it to the dashboard. These will just eat disk space.
			return resp.NeedRepro
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
	writeOrRemove("machineInfo", crash.machineInfo)
	return mgr.needLocalRepro(crash)
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
	if crash.fromHub || crash.fromDashboard {
		return true
	}
	if !mgr.checkDone || (mgr.enabledFeatures&flatrpc.FeatureLeak != 0 &&
		crash.Type != crash_pkg.MemoryLeak) {
		// Leak checking is very slow, don't bother reproducing other crashes on leak instance.
		return false
	}
	if mgr.dash == nil {
		return mgr.needLocalRepro(crash)
	}
	cid := &dashapi.CrashID{
		BuildID:      mgr.cfg.Tag,
		Title:        crash.Title,
		Corrupted:    crash.Corrupted,
		Suppressed:   crash.Suppressed,
		MayBeMissing: crash.Type == crash_pkg.MemoryLeak, // we did not send the original crash w/o repro
	}
	needRepro, err := mgr.dash.NeedRepro(cid)
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
	if !res.fromHub {
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
			OriginalTitle: res.originalTitle,
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
		mgr.serv.updateCoverFilter(update.NewCover)
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

func (mgr *Manager) getMinimizedCorpus() (corpus, repros [][]byte) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	mgr.minimizeCorpusLocked()
	items := mgr.corpus.Items()
	corpus = make([][]byte, 0, len(items))
	for _, inp := range items {
		corpus = append(corpus, inp.ProgData)
	}
	repros = mgr.newRepros
	mgr.newRepros = nil
	return
}

func (mgr *Manager) addNewCandidates(candidates []fuzzer.Candidate) {
	if mgr.cfg.Experimental.ResetAccState {
		// Don't accept new candidates -- the execution is already very slow,
		// syz-hub will just overwhelm us.
		return
	}
	mgr.fuzzer.Load().AddCandidates(candidates)
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	if mgr.phase == phaseTriagedCorpus {
		mgr.phase = phaseQueriedHub
	}
}

func (mgr *Manager) minimizeCorpusLocked() {
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

	// Don't minimize persistent corpus until fuzzers have triaged all inputs from it.
	if mgr.phase < phaseTriagedCorpus {
		return
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

func (mgr *Manager) currentBugFrames() BugFrames {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	frames := BugFrames{
		memoryLeaks: make([]string, 0, len(mgr.memoryLeakFrames)),
		dataRaces:   make([]string, 0, len(mgr.dataRaceFrames)),
	}
	for frame := range mgr.memoryLeakFrames {
		frames.memoryLeaks = append(frames.memoryLeaks, frame)
	}
	for frame := range mgr.dataRaceFrames {
		frames.dataRaces = append(frames.dataRaces, frame)
	}
	return frames
}

func (mgr *Manager) machineChecked(features flatrpc.Feature, enabledSyscalls map[*prog.Syscall]bool) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	if mgr.checkDone {
		panic("machineChecked() called twice")
	}
	mgr.checkDone = true
	mgr.enabledFeatures = features
	mgr.targetEnabledSyscalls = enabledSyscalls
	statSyscalls := stats.Create("syscalls", "Number of enabled syscalls",
		stats.Simple, stats.NoGraph, stats.Link("/syscalls"))
	statSyscalls.Add(len(enabledSyscalls))

	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	fuzzerObj := fuzzer.NewFuzzer(context.Background(), &fuzzer.Config{
		Corpus:         mgr.corpus,
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
	mgr.fuzzer.Store(fuzzerObj)
	mgr.execSource.Store(queue.Retry(fuzzerObj))

	mgr.loadCorpus()
	mgr.firstConnect.Store(time.Now().Unix())
	go mgr.corpusMinimization()
	go mgr.fuzzerLoop(fuzzerObj)
	if mgr.dash != nil {
		go mgr.dashboardReporter()
		if mgr.cfg.Reproduce {
			go mgr.dashboardReproTasks()
		}
	}
}

func (mgr *Manager) corpusMinimization() {
	for range time.NewTicker(time.Minute).C {
		mgr.mu.Lock()
		mgr.minimizeCorpusLocked()
		mgr.mu.Unlock()
	}
}

// We need this method since we're not supposed to access Manager fields from RPCServer.
func (mgr *Manager) getExecSource() queue.Source {
	return mgr.execSource.Load().(queue.Source)
}

func (mgr *Manager) fuzzerSignalRotation() {
	const (
		rotateSignals      = 1000
		timeBetweenRotates = 15 * time.Minute
		// Every X dropped signals may in the worst case lead up to 3 * X
		// additional triage executions, which is in this case constitutes
		// 3000/60000 = 5%.
		execsBetweenRotates = 60000
	)
	lastExecTotal := 0
	lastRotation := time.Now()
	for range time.NewTicker(5 * time.Minute).C {
		if mgr.statExecs.Val()-lastExecTotal < execsBetweenRotates {
			continue
		}
		if time.Since(lastRotation) < timeBetweenRotates {
			continue
		}
		mgr.fuzzer.Load().RotateMaxSignal(rotateSignals)
		lastRotation = time.Now()
		lastExecTotal = mgr.statExecs.Val()
	}
}

func (mgr *Manager) fuzzerLoop(fuzzer *fuzzer.Fuzzer) {
	for ; ; time.Sleep(time.Second / 2) {
		// Distribute new max signal over all instances.
		newSignal, dropSignal := fuzzer.Cover.GrabSignalDelta()
		log.Logf(2, "distributing %d new signal, %d dropped signal",
			len(newSignal), len(dropSignal))
		mgr.serv.distributeSignalDelta(newSignal, dropSignal)

		// Update the state machine.
		if fuzzer.StatCandidates.Val() == 0 {
			mgr.mu.Lock()
			if mgr.phase == phaseLoadedCorpus {
				go mgr.fuzzerSignalRotation()
				if mgr.cfg.HubClient != "" {
					mgr.phase = phaseTriagedCorpus
					go mgr.hubSyncLoop(pickGetter(mgr.cfg.HubKey))
				} else {
					mgr.phase = phaseTriagedHub
				}
			} else if mgr.phase == phaseQueriedHub {
				mgr.phase = phaseTriagedHub
			}
			mgr.mu.Unlock()
		}
	}
}

func (mgr *Manager) hubIsUnreachable() {
	var dash *dashapi.Dashboard
	mgr.mu.Lock()
	if mgr.phase == phaseTriagedCorpus {
		dash = mgr.dash
		mgr.phase = phaseTriagedHub
		log.Errorf("did not manage to connect to syz-hub; moving forward")
	}
	mgr.mu.Unlock()
	if dash != nil {
		mgr.dash.LogError(mgr.cfg.Name, "did not manage to connect to syz-hub")
	}
}

func (mgr *Manager) collectUsedFiles() {
	if mgr.vmPool == nil {
		return
	}
	addUsedFile := func(f string) {
		if f == "" {
			return
		}
		stat, err := os.Stat(f)
		if err != nil {
			log.Fatalf("failed to stat %v: %v", f, err)
		}
		mgr.usedFiles[f] = stat.ModTime()
	}
	cfg := mgr.cfg
	addUsedFile(cfg.FuzzerBin)
	addUsedFile(cfg.ExecprogBin)
	addUsedFile(cfg.ExecutorBin)
	addUsedFile(cfg.SSHKey)
	if vmlinux := filepath.Join(cfg.KernelObj, mgr.sysTarget.KernelObject); osutil.IsExist(vmlinux) {
		addUsedFile(vmlinux)
	}
	if cfg.Image != "9p" {
		addUsedFile(cfg.Image)
	}
}

func (mgr *Manager) checkUsedFiles() {
	for f, mod := range mgr.usedFiles {
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
			Execs:             uint64(mgr.statExecs.Val()) - lastExecs,
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
		needReproReply := make(chan bool)
		mgr.needMoreRepros <- needReproReply
		if !<-needReproReply {
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
