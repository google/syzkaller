// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
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
	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/gce"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/repro"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/signal"
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
	cfg            *mgrconfig.Config
	vmPool         *vm.Pool
	target         *prog.Target
	sysTarget      *targets.Target
	reporter       *report.Reporter
	crashdir       string
	serv           *RPCServer
	corpusDB       *db.DB
	startTime      time.Time
	firstConnect   time.Time
	fuzzingTime    time.Duration
	stats          *Stats
	crashTypes     map[string]bool
	vmStop         chan bool
	checkResult    *rpctype.CheckArgs
	fresh          bool
	numFuzzing     uint32
	numReproducing uint32

	dash *dashapi.Dashboard

	mu                    sync.Mutex
	phase                 int
	targetEnabledSyscalls map[*prog.Syscall]bool

	candidates       []rpctype.Candidate // untriaged inputs from corpus and hub
	disabledHashes   map[string]struct{}
	corpus           map[string]CorpusItem
	seeds            [][]byte
	newRepros        [][]byte
	lastMinCorpus    int
	memoryLeakFrames map[string]bool
	dataRaceFrames   map[string]bool
	saturatedCalls   map[string]bool

	needMoreRepros chan chan bool
	hubReproQueue  chan *Crash
	reproRequest   chan chan map[string]bool

	// For checking that files that we are using are not changing under us.
	// Maps file name to modification time.
	usedFiles map[string]time.Time

	modules            []host.KernelModule
	coverFilter        map[uint32]uint32
	coverFilterBitmap  []byte
	modulesInitialized bool

	assetStorage *asset.Storage
}

type CorpusItemUpdate struct {
	CallID   int
	RawCover []uint32
}

type CorpusItem struct {
	Call    string
	Prog    []byte
	Signal  signal.Serial
	Cover   []uint32
	Updates []CorpusItemUpdate
}

func (item *CorpusItem) RPCInput() rpctype.Input {
	return rpctype.Input{
		Call:   item.Call,
		Prog:   item.Prog,
		Signal: item.Signal,
		Cover:  item.Cover,
	}
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
	vmIndex int
	hub     bool // this crash was created based on a repro from hub
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

	mgr := &Manager{
		cfg:              cfg,
		vmPool:           vmPool,
		target:           cfg.Target,
		sysTarget:        cfg.SysTarget,
		reporter:         reporter,
		crashdir:         crashdir,
		startTime:        time.Now(),
		stats:            &Stats{haveHub: cfg.HubClient != ""},
		crashTypes:       make(map[string]bool),
		corpus:           make(map[string]CorpusItem),
		disabledHashes:   make(map[string]struct{}),
		memoryLeakFrames: make(map[string]bool),
		dataRaceFrames:   make(map[string]bool),
		fresh:            true,
		vmStop:           make(chan bool),
		hubReproQueue:    make(chan *Crash, 10),
		needMoreRepros:   make(chan chan bool),
		reproRequest:     make(chan chan map[string]bool),
		usedFiles:        make(map[string]time.Time),
		saturatedCalls:   make(map[string]bool),
	}

	mgr.preloadCorpus()
	mgr.initStats() // Initializes prometheus variables.
	mgr.initHTTP()  // Creates HTTP server.
	mgr.collectUsedFiles()

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

	go func() {
		for lastTime := time.Now(); ; {
			time.Sleep(10 * time.Second)
			now := time.Now()
			diff := now.Sub(lastTime)
			lastTime = now
			mgr.mu.Lock()
			if mgr.firstConnect.IsZero() {
				mgr.mu.Unlock()
				continue
			}
			mgr.fuzzingTime += diff * time.Duration(atomic.LoadUint32(&mgr.numFuzzing))
			executed := mgr.stats.execTotal.get()
			crashes := mgr.stats.crashes.get()
			corpusCover := mgr.stats.corpusCover.get()
			corpusSignal := mgr.stats.corpusSignal.get()
			maxSignal := mgr.stats.maxSignal.get()
			mgr.mu.Unlock()
			numReproducing := atomic.LoadUint32(&mgr.numReproducing)
			numFuzzing := atomic.LoadUint32(&mgr.numFuzzing)

			log.Logf(0, "VMs %v, executed %v, cover %v, signal %v/%v, crashes %v, repro %v",
				numFuzzing, executed, corpusCover, corpusSignal, maxSignal, crashes, numReproducing)
		}
	}()

	if *flagBench != "" {
		mgr.initBench()
	}

	if mgr.dash != nil {
		go mgr.dashboardReporter()
	}

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

func (mgr *Manager) initBench() {
	f, err := os.OpenFile(*flagBench, os.O_WRONLY|os.O_CREATE|os.O_EXCL, osutil.DefaultFilePerm)
	if err != nil {
		log.Fatalf("failed to open bench file: %v", err)
	}
	go func() {
		for {
			time.Sleep(time.Minute)
			vals := mgr.stats.all()
			mgr.mu.Lock()
			if mgr.firstConnect.IsZero() {
				mgr.mu.Unlock()
				continue
			}
			mgr.minimizeCorpus()
			vals["corpus"] = uint64(len(mgr.corpus))
			vals["uptime"] = uint64(time.Since(mgr.firstConnect)) / 1e9
			vals["fuzzing"] = uint64(mgr.fuzzingTime) / 1e9
			mgr.mu.Unlock()

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
	instances []int
	report0   *report.Report // the original report we started reproducing
	repro     *repro.Result
	strace    *repro.StraceResult
	stats     *repro.Stats
	err       error
	hub       bool // repro came from hub
}

// Manager needs to be refactored (#605).
// nolint: gocyclo, gocognit, funlen
func (mgr *Manager) vmLoop() {
	log.Logf(0, "booting test machines...")
	log.Logf(0, "wait for the connection from test machine...")
	instancesPerRepro := 4
	vmCount := mgr.vmPool.Count()
	maxReproVMs := vmCount - mgr.cfg.FuzzingVMs
	if instancesPerRepro > maxReproVMs && maxReproVMs > 0 {
		instancesPerRepro = maxReproVMs
	}
	instances := SequentialResourcePool(vmCount, 10*time.Second*mgr.cfg.Timeouts.Scale)
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
				(int(atomic.LoadUint32(&mgr.numReproducing))+1)*instancesPerRepro <= maxReproVMs
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
				atomic.AddUint32(&mgr.numReproducing, 1)
				log.Logf(1, "loop: starting repro of '%v' on instances %+v", crash.Title, vmIndexes)
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
			atomic.AddUint32(&mgr.numReproducing, ^uint32(0))
			crepro := false
			title := ""
			if res.repro != nil {
				crepro = res.repro.CRepro
				title = res.repro.Report.Title
			}
			log.Logf(1, "loop: repro on %+v finished '%v', repro=%v crepro=%v desc='%v'",
				res.instances, res.report0.Title, res.repro != nil, crepro, title)
			if res.err != nil {
				log.Logf(0, "repro failed: %v", res.err)
			}
			delete(reproducing, res.report0.Title)
			if res.repro == nil {
				if !res.hub {
					mgr.saveFailedRepro(res.report0, res.stats)
				}
			} else {
				mgr.saveRepro(res)
			}
		case <-shutdown:
			log.Logf(1, "loop: shutting down...")
			shutdown = nil
		case crash := <-mgr.hubReproQueue:
			log.Logf(1, "loop: get repro from hub")
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

func (mgr *Manager) runRepro(crash *Crash, vmIndexes []int, putInstances func(...int)) *ReproResult {
	features := mgr.checkResult.Features
	res, stats, err := repro.Run(crash.Output, mgr.cfg, features, mgr.reporter, mgr.vmPool, vmIndexes)
	ret := &ReproResult{
		instances: vmIndexes,
		report0:   crash.Report,
		repro:     res,
		stats:     stats,
		err:       err,
		hub:       crash.hub,
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
	log.Logf(0, "loading corpus...")
	corpusDB, err := db.Open(filepath.Join(mgr.cfg.Workdir, "corpus.db"), true)
	if err != nil {
		if corpusDB == nil {
			log.Fatalf("failed to open corpus database: %v", err)
		}
		log.Logf(0, "read %v inputs from corpus and got error: %v", len(corpusDB.Records), err)
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
}

func (mgr *Manager) loadCorpus() {
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
	broken := 0
	for key, rec := range mgr.corpusDB.Records {
		if !mgr.loadProg(rec.Val, minimized, smashed) {
			mgr.corpusDB.Delete(key)
			broken++
		}
	}
	mgr.fresh = len(mgr.corpusDB.Records) == 0
	corpusSize := len(mgr.candidates)
	log.Logf(0, "%-24v: %v (deleted %v broken)", "corpus", corpusSize, broken)

	for _, seed := range mgr.seeds {
		mgr.loadProg(seed, true, false)
	}
	log.Logf(0, "%-24v: %v/%v", "seeds", len(mgr.candidates)-corpusSize, len(mgr.seeds))
	mgr.seeds = nil

	// We duplicate all inputs in the corpus and shuffle the second part.
	// This solves the following problem. A fuzzer can crash while triaging candidates,
	// in such case it will also lost all cached candidates. Or, the input can be somewhat flaky
	// and doesn't give the coverage on first try. So we give each input the second chance.
	// Shuffling should alleviate deterministically losing the same inputs on fuzzer crashing.
	mgr.candidates = append(mgr.candidates, mgr.candidates...)
	shuffle := mgr.candidates[len(mgr.candidates)/2:]
	rand.Shuffle(len(shuffle), func(i, j int) {
		shuffle[i], shuffle[j] = shuffle[j], shuffle[i]
	})
	if mgr.phase != phaseInit {
		panic(fmt.Sprintf("loadCorpus: bad phase %v", mgr.phase))
	}
	mgr.phase = phaseLoadedCorpus
}

func (mgr *Manager) loadProg(data []byte, minimized, smashed bool) bool {
	bad, disabled := checkProgram(mgr.target, mgr.targetEnabledSyscalls, data)
	if bad {
		return false
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
			if len(leftover) > 0 {
				mgr.candidates = append(mgr.candidates, rpctype.Candidate{
					Prog:      leftover,
					Minimized: false,
					Smashed:   smashed,
				})
			}
		}
		return true
	}
	mgr.candidates = append(mgr.candidates, rpctype.Candidate{
		Prog:      data,
		Minimized: minimized,
		Smashed:   smashed,
	})
	return true
}

func programLeftover(target *prog.Target, enabled map[*prog.Syscall]bool, data []byte) []byte {
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
	return p.Serialize()
}

func checkProgram(target *prog.Target, enabled map[*prog.Syscall]bool, data []byte) (bad, disabled bool) {
	p, err := target.Deserialize(data, prog.NonStrict)
	if err != nil {
		return true, true
	}
	if len(p.Calls) > prog.MaxCalls {
		return true, true
	}
	for _, c := range p.Calls {
		if !enabled[c.Meta] {
			return false, true
		}
	}
	return false, false
}

func (mgr *Manager) runInstance(index int) (*Crash, error) {
	mgr.checkUsedFiles()
	instanceName := fmt.Sprintf("vm-%d", index)

	rep, vmInfo, err := mgr.runInstanceInner(index, instanceName)

	machineInfo := mgr.serv.shutdownInstance(instanceName)
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
		vmIndex:     index,
		hub:         false,
		Report:      rep,
		machineInfo: machineInfo,
	}
	return crash, nil
}

func (mgr *Manager) runInstanceInner(index int, instanceName string) (*report.Report, []byte, error) {
	inst, err := mgr.vmPool.Create(index)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create instance: %v", err)
	}
	defer inst.Close()

	fwdAddr, err := inst.Forward(mgr.serv.port)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to setup port forwarding: %v", err)
	}

	fuzzerBin, err := inst.Copy(mgr.cfg.FuzzerBin)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to copy binary: %v", err)
	}

	// If ExecutorBin is provided, it means that syz-executor is already in the image,
	// so no need to copy it.
	executorBin := mgr.sysTarget.ExecutorBin
	if executorBin == "" {
		executorBin, err = inst.Copy(mgr.cfg.ExecutorBin)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to copy binary: %v", err)
		}
	}

	fuzzerV := 0
	procs := mgr.cfg.Procs
	if *flagDebug {
		fuzzerV = 100
		procs = 1
	}

	// Run the fuzzer binary.
	start := time.Now()
	atomic.AddUint32(&mgr.numFuzzing, 1)
	defer atomic.AddUint32(&mgr.numFuzzing, ^uint32(0))

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
		Runtest:   false,
		Optional: &instance.OptionalFuzzerArgs{
			Slowdown:   mgr.cfg.Timeouts.Slowdown,
			RawCover:   mgr.cfg.RawCover,
			SandboxArg: mgr.cfg.SandboxArg,
		},
	}
	cmd := instance.FuzzerCmd(args)
	outc, errc, err := inst.Run(mgr.cfg.Timeouts.VMRunningTime, mgr.vmStop, cmd)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to run fuzzer: %v", err)
	}

	var vmInfo []byte
	rep := inst.MonitorExecution(outc, errc, mgr.reporter, vm.ExitTimeout)
	if rep == nil {
		// This is the only "OK" outcome.
		log.Logf(0, "%s: running for %v, restarting", instanceName, time.Since(start))
	} else {
		vmInfo, err = inst.Info()
		if err != nil {
			vmInfo = []byte(fmt.Sprintf("error getting VM info: %v\n", err))
		}
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
		log.Logf(0, "failed to symbolize report: %v", err)
	}
	if crash.Type == report.MemoryLeak {
		mgr.mu.Lock()
		mgr.memoryLeakFrames[crash.Frame] = true
		mgr.mu.Unlock()
	}
	if crash.Type == report.DataRace {
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
	log.Logf(0, "vm-%v: crash: %v%v", crash.vmIndex, crash.Title, flags)

	if crash.Suppressed {
		// Collect all of them into a single bucket so that it's possible to control and assess them,
		// e.g. if there are some spikes in suppressed reports.
		crash.Title = "suppressed report"
		mgr.stats.crashSuppressed.inc()
	}

	mgr.stats.crashes.inc()
	mgr.mu.Lock()
	if !mgr.crashTypes[crash.Title] {
		mgr.crashTypes[crash.Title] = true
		mgr.stats.crashTypes.inc()
	}
	mgr.mu.Unlock()

	if mgr.dash != nil {
		if crash.Type == report.MemoryLeak {
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
	if crash.hub {
		return true
	}
	if mgr.checkResult == nil || (mgr.checkResult.Features[host.FeatureLeak].Enabled &&
		crash.Type != report.MemoryLeak) {
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
		MayBeMissing: crash.Type == report.MemoryLeak, // we did not send the original crash w/o repro
	}
	needRepro, err := mgr.dash.NeedRepro(cid)
	if err != nil {
		log.Logf(0, "dashboard.NeedRepro failed: %v", err)
	}
	return needRepro
}

func (mgr *Manager) saveFailedRepro(rep *report.Report, stats *repro.Stats) {
	if mgr.dash != nil {
		if rep.Type == report.MemoryLeak {
			// Don't send failed leak repro attempts to dashboard
			// as we did not send the crash itself.
			return
		}
		cid := &dashapi.CrashID{
			BuildID:      mgr.cfg.Tag,
			Title:        rep.Title,
			Corrupted:    rep.Corrupted,
			Suppressed:   rep.Suppressed,
			MayBeMissing: rep.Type == report.MemoryLeak,
		}
		if err := mgr.dash.ReportFailedRepro(cid); err != nil {
			log.Logf(0, "failed to report failed repro to dashboard: %v", err)
		} else {
			return
		}
	}
	dir := filepath.Join(mgr.crashdir, hash.String([]byte(rep.Title)))
	osutil.MkdirAll(dir)
	for i := 0; i < maxReproAttempts; i++ {
		name := filepath.Join(dir, fmt.Sprintf("repro%v", i))
		if !osutil.IsExist(name) {
			saveReproStats(name, stats)
			break
		}
	}
}

func (mgr *Manager) saveRepro(res *ReproResult) {
	repro := res.repro
	opts := fmt.Sprintf("# %+v\n", repro.Opts)
	progText := repro.Prog.Serialize()

	// Append this repro to repro list to send to hub if it didn't come from hub originally.
	if !res.hub {
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
			BuildID:    mgr.cfg.Tag,
			Title:      report.Title,
			AltTitles:  report.AltTitles,
			Suppressed: report.Suppressed,
			Recipients: report.Recipients.ToDash(),
			Log:        output,
			Flags:      crashFlags,
			Report:     report.Report,
			ReproOpts:  repro.Opts.Serialize(),
			ReproSyz:   progText,
			ReproC:     cprogText,
			Assets:     mgr.uploadReproAssets(repro),
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
		if err := osutil.WriteGzipStream(name+".gz", r); err != nil {
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
	saveReproStats(filepath.Join(dir, "repro.stats"), res.stats)
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

func saveReproStats(filename string, stats *repro.Stats) {
	text := ""
	if stats != nil {
		text = fmt.Sprintf("Extracting prog: %v\nMinimizing prog: %v\n"+
			"Simplifying prog options: %v\nExtracting C: %v\nSimplifying C: %v\n\n\n%s",
			stats.ExtractProgTime, stats.MinimizeProgTime,
			stats.SimplifyProgTime, stats.ExtractCTime, stats.SimplifyCTime, stats.Log)
	}
	osutil.WriteFile(filename, []byte(text))
}

func (mgr *Manager) getMinimizedCorpus() (corpus, repros [][]byte) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	mgr.minimizeCorpus()
	corpus = make([][]byte, 0, len(mgr.corpus))
	for _, inp := range mgr.corpus {
		corpus = append(corpus, inp.Prog)
	}
	repros = mgr.newRepros
	mgr.newRepros = nil
	return
}

func (mgr *Manager) addNewCandidates(candidates []rpctype.Candidate) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	mgr.candidates = append(mgr.candidates, candidates...)
	if mgr.phase == phaseTriagedCorpus {
		mgr.phase = phaseQueriedHub
	}
}

func (mgr *Manager) minimizeCorpus() {
	if mgr.phase < phaseLoadedCorpus || len(mgr.corpus) <= mgr.lastMinCorpus*103/100 {
		return
	}
	inputs := make([]signal.Context, 0, len(mgr.corpus))
	for _, inp := range mgr.corpus {
		inputs = append(inputs, signal.Context{
			Signal:  inp.Signal.Deserialize(),
			Context: inp,
		})
	}
	newCorpus := make(map[string]CorpusItem)
	// Note: inputs are unsorted (based on map iteration).
	// This gives some intentional non-determinism during minimization.
	for _, ctx := range signal.Minimize(inputs) {
		inp := ctx.(CorpusItem)
		newCorpus[hash.String(inp.Prog)] = inp
	}
	log.Logf(1, "minimized corpus: %v -> %v", len(mgr.corpus), len(newCorpus))
	mgr.corpus = newCorpus
	mgr.lastMinCorpus = len(newCorpus)

	// From time to time we get corpus explosion due to different reason:
	// generic bugs, per-OS bugs, problems with fallback coverage, kcov bugs, etc.
	// This has bad effect on the instance and especially on instances
	// connected via hub. Do some per-syscall sanity checking to prevent this.
	for call, info := range mgr.collectSyscallInfoUnlocked() {
		if mgr.cfg.Cover {
			// If we have less than 1K inputs per this call,
			// accept all new inputs unconditionally.
			if info.count < 1000 {
				continue
			}
			// If we have more than 3K already, don't accept any more.
			// Between 1K and 3K look at amount of coverage we are getting from these programs.
			// Empirically, real coverage for the most saturated syscalls is ~30-60
			// per program (even when we have a thousand of them). For explosion
			// case coverage tend to be much lower (~0.3-5 per program).
			if info.count < 3000 && len(info.cov)/info.count >= 10 {
				continue
			}
		} else {
			// If we don't have real coverage, signal is weak.
			// If we have more than several hundreds, there is something wrong.
			if info.count < 300 {
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
	for key := range mgr.corpusDB.Records {
		_, ok1 := mgr.corpus[key]
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

type CallCov struct {
	count int
	cov   cover.Cover
}

func (mgr *Manager) collectSyscallInfo() map[string]*CallCov {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	return mgr.collectSyscallInfoUnlocked()
}

func (mgr *Manager) collectSyscallInfoUnlocked() map[string]*CallCov {
	if mgr.checkResult == nil {
		return nil
	}
	calls := make(map[string]*CallCov)
	for _, call := range mgr.checkResult.EnabledCalls[mgr.cfg.Sandbox] {
		calls[mgr.target.Syscalls[call].Name] = new(CallCov)
	}
	for _, inp := range mgr.corpus {
		if calls[inp.Call] == nil {
			calls[inp.Call] = new(CallCov)
		}
		cc := calls[inp.Call]
		cc.count++
		cc.cov.Merge(inp.Cover)
	}
	return calls
}

func (mgr *Manager) fuzzerConnect(modules []host.KernelModule) (
	[]rpctype.Input, BugFrames, map[uint32]uint32, []byte, error) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	mgr.minimizeCorpus()
	corpus := make([]rpctype.Input, 0, len(mgr.corpus))
	for _, inp := range mgr.corpus {
		corpus = append(corpus, inp.RPCInput())
	}
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
	if !mgr.modulesInitialized {
		var err error
		mgr.modules = modules
		mgr.coverFilterBitmap, mgr.coverFilter, err = mgr.createCoverageFilter()
		if err != nil {
			log.Fatalf("failed to create coverage filter: %v", err)
		}
		mgr.modulesInitialized = true
	}
	return corpus, frames, mgr.coverFilter, mgr.coverFilterBitmap, nil
}

func (mgr *Manager) machineChecked(a *rpctype.CheckArgs, enabledSyscalls map[*prog.Syscall]bool) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	mgr.checkResult = a
	mgr.targetEnabledSyscalls = enabledSyscalls
	mgr.target.UpdateGlobs(a.GlobFiles)
	mgr.loadCorpus()
	mgr.firstConnect = time.Now()
}

func (mgr *Manager) newInput(inp rpctype.Input, sign signal.Signal) bool {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	if mgr.saturatedCalls[inp.Call] {
		return false
	}
	update := CorpusItemUpdate{
		CallID:   inp.CallID,
		RawCover: inp.RawCover,
	}
	sig := hash.String(inp.Prog)
	if old, ok := mgr.corpus[sig]; ok {
		// The input is already present, but possibly with diffent signal/coverage/call.
		sign.Merge(old.Signal.Deserialize())
		old.Signal = sign.Serialize()
		var cov cover.Cover
		cov.Merge(old.Cover)
		cov.Merge(inp.Cover)
		old.Cover = cov.Serialize()
		const maxUpdates = 32
		old.Updates = append(old.Updates, update)
		if len(old.Updates) > maxUpdates {
			old.Updates = old.Updates[:maxUpdates]
		}
		mgr.corpus[sig] = old
	} else {
		mgr.corpus[sig] = CorpusItem{
			Call:    inp.Call,
			Prog:    inp.Prog,
			Signal:  inp.Signal,
			Cover:   inp.Cover,
			Updates: []CorpusItemUpdate{update},
		}
		mgr.corpusDB.Save(sig, inp.Prog, 0)
		if err := mgr.corpusDB.Flush(); err != nil {
			log.Logf(0, "failed to save corpus database: %v", err)
		}
	}
	return true
}

func (mgr *Manager) candidateBatch(size int) []rpctype.Candidate {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	var res []rpctype.Candidate
	for i := 0; i < size && len(mgr.candidates) > 0; i++ {
		last := len(mgr.candidates) - 1
		res = append(res, mgr.candidates[last])
		mgr.candidates[last] = rpctype.Candidate{}
		mgr.candidates = mgr.candidates[:last]
	}
	if len(mgr.candidates) == 0 {
		mgr.candidates = nil
		if mgr.phase == phaseLoadedCorpus {
			if mgr.cfg.HubClient != "" {
				mgr.phase = phaseTriagedCorpus
				go mgr.hubSyncLoop(pickGetter(mgr.cfg.HubKey))
			} else {
				mgr.phase = phaseTriagedHub
			}
		} else if mgr.phase == phaseQueriedHub {
			mgr.phase = phaseTriagedHub
		}
	}
	return res
}

func (mgr *Manager) rotateCorpus() bool {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	return mgr.phase == phaseTriagedHub
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
	var lastFuzzingTime time.Duration
	var lastCrashes, lastSuppressedCrashes, lastExecs uint64
	for {
		time.Sleep(time.Minute)
		mgr.mu.Lock()
		if mgr.firstConnect.IsZero() {
			mgr.mu.Unlock()
			continue
		}
		crashes := mgr.stats.crashes.get()
		suppressedCrashes := mgr.stats.crashSuppressed.get()
		execs := mgr.stats.execTotal.get()
		req := &dashapi.ManagerStatsReq{
			Name:              mgr.cfg.Name,
			Addr:              webAddr,
			UpTime:            time.Since(mgr.firstConnect),
			Corpus:            uint64(len(mgr.corpus)),
			PCs:               mgr.stats.corpusCover.get(),
			Cover:             mgr.stats.corpusSignal.get(),
			CrashTypes:        mgr.stats.crashTypes.get(),
			FuzzingTime:       mgr.fuzzingTime - lastFuzzingTime,
			Crashes:           crashes - lastCrashes,
			SuppressedCrashes: suppressedCrashes - lastSuppressedCrashes,
			Execs:             execs - lastExecs,
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
