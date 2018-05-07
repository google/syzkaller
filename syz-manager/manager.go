// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/gce"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/repro"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/syz-manager/mgrconfig"
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
	reporter       report.Reporter
	crashdir       string
	port           int
	corpusDB       *db.DB
	startTime      time.Time
	firstConnect   time.Time
	lastPrioCalc   time.Time
	fuzzingTime    time.Duration
	stats          map[string]uint64
	crashTypes     map[string]bool
	vmStop         chan bool
	vmChecked      bool
	fresh          bool
	numFuzzing     uint32
	numReproducing uint32

	dash *dashapi.Dashboard

	mu              sync.Mutex
	phase           int
	enabledSyscalls []int
	enabledCalls    []string // as determined by fuzzer

	candidates     []rpctype.RPCCandidate // untriaged inputs from corpus and hub
	disabledHashes map[string]struct{}
	corpus         map[string]rpctype.RPCInput
	corpusCover    cover.Cover
	corpusSignal   signal.Signal
	maxSignal      signal.Signal
	prios          [][]float32
	newRepros      [][]byte

	fuzzers        map[string]*Fuzzer
	hub            *rpctype.RPCClient
	hubCorpus      map[hash.Sig]bool
	needMoreRepros chan chan bool
	hubReproQueue  chan *Crash
	reproRequest   chan chan map[string]bool

	// For checking that files that we are using are not changing under us.
	// Maps file name to modification time.
	usedFiles map[string]time.Time
}

const (
	// Just started, nothing done yet.
	phaseInit = iota
	// Triaged all inputs from corpus.
	// This is when we start querying hub and minimizing persistent corpus.
	phaseTriagedCorpus
	// Done the first request to hub.
	phaseQueriedHub
	// Triaged all new inputs from hub.
	// This is when we start reproducing crashes.
	phaseTriagedHub
)

const currentDBVersion = 3

type Fuzzer struct {
	name         string
	inputs       []rpctype.RPCInput
	newMaxSignal signal.Signal
}

type Crash struct {
	vmIndex int
	hub     bool // this crash was created based on a repro from hub
	*report.Report
}

func main() {
	if sys.GitRevision == "" {
		log.Fatalf("Bad syz-manager build. Build with make, run bin/syz-manager.")
	}
	flag.Parse()
	log.EnableLogCaching(1000, 1<<20)
	cfg, err := mgrconfig.LoadFile(*flagConfig)
	if err != nil {
		log.Fatalf("%v", err)
	}
	target, err := prog.GetTarget(cfg.TargetOS, cfg.TargetArch)
	if err != nil {
		log.Fatalf("%v", err)
	}
	syscalls, err := mgrconfig.ParseEnabledSyscalls(target, cfg.EnabledSyscalls, cfg.DisabledSyscalls)
	if err != nil {
		log.Fatalf("%v", err)
	}
	initAllCover(cfg.TargetOS, cfg.TargetVMArch, cfg.Vmlinux)
	RunManager(cfg, target, syscalls)
}

func RunManager(cfg *mgrconfig.Config, target *prog.Target, syscalls map[int]bool) {
	var vmPool *vm.Pool
	// Type "none" is a special case for debugging/development when manager
	// does not start any VMs, but instead you start them manually
	// and start syz-fuzzer there.
	if cfg.Type != "none" {
		env := mgrconfig.CreateVMEnv(cfg, *flagDebug)
		var err error
		vmPool, err = vm.Create(cfg.Type, env)
		if err != nil {
			log.Fatalf("%v", err)
		}
	}

	crashdir := filepath.Join(cfg.Workdir, "crashes")
	osutil.MkdirAll(crashdir)

	var enabledSyscalls []int
	for c := range syscalls {
		enabledSyscalls = append(enabledSyscalls, c)
	}

	mgr := &Manager{
		cfg:             cfg,
		vmPool:          vmPool,
		target:          target,
		crashdir:        crashdir,
		startTime:       time.Now(),
		stats:           make(map[string]uint64),
		crashTypes:      make(map[string]bool),
		enabledSyscalls: enabledSyscalls,
		corpus:          make(map[string]rpctype.RPCInput),
		disabledHashes:  make(map[string]struct{}),
		fuzzers:         make(map[string]*Fuzzer),
		fresh:           true,
		vmStop:          make(chan bool),
		hubReproQueue:   make(chan *Crash, 10),
		needMoreRepros:  make(chan chan bool),
		reproRequest:    make(chan chan map[string]bool),
		usedFiles:       make(map[string]time.Time),
	}

	log.Logf(0, "loading corpus...")
	var err error
	mgr.corpusDB, err = db.Open(filepath.Join(cfg.Workdir, "corpus.db"))
	if err != nil {
		log.Fatalf("failed to open corpus database: %v", err)
	}
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
	case currentDBVersion:
	}
	deleted := 0
	for key, rec := range mgr.corpusDB.Records {
		p, err := mgr.target.Deserialize(rec.Val)
		if err != nil {
			if deleted < 10 {
				log.Logf(0, "deleting broken program: %v\n%s", err, rec.Val)
			}
			mgr.corpusDB.Delete(key)
			deleted++
			continue
		}
		disabled := false
		for _, c := range p.Calls {
			if !syscalls[c.Meta.ID] {
				disabled = true
				break
			}
		}
		if disabled {
			// This program contains a disabled syscall.
			// We won't execute it, but remember its hash so
			// it is not deleted during minimization.
			// TODO: use mgr.enabledCalls which accounts for missing devices, etc.
			// But it is available only after vm check.
			mgr.disabledHashes[hash.String(rec.Val)] = struct{}{}
			continue
		}
		mgr.candidates = append(mgr.candidates, rpctype.RPCCandidate{
			Prog:      rec.Val,
			Minimized: minimized,
			Smashed:   smashed,
		})
	}
	mgr.fresh = len(mgr.corpusDB.Records) == 0
	log.Logf(0, "loaded %v programs (%v total, %v deleted)",
		len(mgr.candidates), len(mgr.corpusDB.Records), deleted)

	// Now this is ugly.
	// We duplicate all inputs in the corpus and shuffle the second part.
	// This solves the following problem. A fuzzer can crash while triaging candidates,
	// in such case it will also lost all cached candidates. Or, the input can be somewhat flaky
	// and doesn't give the coverage on first try. So we give each input the second chance.
	// Shuffling should alleviate deterministically losing the same inputs on fuzzer crashing.
	mgr.candidates = append(mgr.candidates, mgr.candidates...)
	shuffle := mgr.candidates[len(mgr.candidates)/2:]
	for i := range shuffle {
		j := i + rand.Intn(len(shuffle)-i)
		shuffle[i], shuffle[j] = shuffle[j], shuffle[i]
	}

	// Create HTTP server.
	mgr.initHTTP()
	mgr.collectUsedFiles()

	// Create RPC server for fuzzers.
	s, err := rpctype.NewRPCServer(cfg.RPC, mgr)
	if err != nil {
		log.Fatalf("failed to create rpc server: %v", err)
	}
	log.Logf(0, "serving rpc on tcp://%v", s.Addr())
	mgr.port = s.Addr().(*net.TCPAddr).Port
	go s.Serve()

	if cfg.DashboardAddr != "" {
		mgr.dash = dashapi.New(cfg.DashboardClient, cfg.DashboardAddr, cfg.DashboardKey)
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
			executed := mgr.stats["exec total"]
			crashes := mgr.stats["crashes"]
			signal := mgr.corpusSignal.Len()
			mgr.mu.Unlock()
			numReproducing := atomic.LoadUint32(&mgr.numReproducing)
			numFuzzing := atomic.LoadUint32(&mgr.numFuzzing)

			log.Logf(0, "VMs %v, executed %v, cover %v, crashes %v, repro %v",
				numFuzzing, executed, signal, crashes, numReproducing)
		}
	}()

	if *flagBench != "" {
		f, err := os.OpenFile(*flagBench, os.O_WRONLY|os.O_CREATE|os.O_EXCL, osutil.DefaultFilePerm)
		if err != nil {
			log.Fatalf("failed to open bench file: %v", err)
		}
		go func() {
			for {
				time.Sleep(time.Minute)
				vals := make(map[string]uint64)
				mgr.mu.Lock()
				if mgr.firstConnect.IsZero() {
					mgr.mu.Unlock()
					continue
				}
				mgr.minimizeCorpus()
				vals["corpus"] = uint64(len(mgr.corpus))
				vals["uptime"] = uint64(time.Since(mgr.firstConnect)) / 1e9
				vals["fuzzing"] = uint64(mgr.fuzzingTime) / 1e9
				vals["signal"] = uint64(mgr.corpusSignal.Len())
				vals["coverage"] = uint64(len(mgr.corpusCover))
				for k, v := range mgr.stats {
					vals[k] = v
				}
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

	if mgr.dash != nil {
		go mgr.dashboardReporter()
	}

	if mgr.cfg.HubClient != "" {
		go func() {
			for {
				time.Sleep(time.Minute)
				mgr.hubSync()
			}
		}()
	}

	osutil.HandleInterrupts(vm.Shutdown)
	if mgr.vmPool == nil {
		log.Logf(0, "no VMs started (type=none)")
		log.Logf(0, "you are supposed to start syz-fuzzer manually as:")
		log.Logf(0, "syz-fuzzer -manager=manager.ip:%v [other flags as necessary]", mgr.port)
		<-vm.Shutdown
		return
	}
	mgr.vmLoop()
}

type RunResult struct {
	idx   int
	crash *Crash
	err   error
}

type ReproResult struct {
	instances []int
	title0    string
	res       *repro.Result
	err       error
	hub       bool // repro came from hub
}

func (mgr *Manager) vmLoop() {
	log.Logf(0, "booting test machines...")
	log.Logf(0, "wait for the connection from test machine...")
	instancesPerRepro := 4
	vmCount := mgr.vmPool.Count()
	if instancesPerRepro > vmCount {
		instancesPerRepro = vmCount
	}
	instances := make([]int, vmCount)
	for i := range instances {
		instances[i] = vmCount - i - 1
	}
	runDone := make(chan *RunResult, 1)
	pendingRepro := make(map[*Crash]bool)
	reproducing := make(map[string]bool)
	reproInstances := 0
	var reproQueue []*Crash
	reproDone := make(chan *ReproResult, 1)
	stopPending := false
	shutdown := vm.Shutdown
	for {
		mgr.mu.Lock()
		phase := mgr.phase
		mgr.mu.Unlock()

		for crash := range pendingRepro {
			if reproducing[crash.Title] {
				continue
			}
			delete(pendingRepro, crash)
			if !crash.hub {
				if mgr.dash == nil {
					if !mgr.needRepro(crash) {
						continue
					}
				} else {
					cid := &dashapi.CrashID{
						BuildID:   mgr.cfg.Tag,
						Title:     crash.Title,
						Corrupted: crash.Corrupted,
					}
					needRepro, err := mgr.dash.NeedRepro(cid)
					if err != nil {
						log.Logf(0, "dashboard.NeedRepro failed: %v", err)
					}
					if !needRepro {
						continue
					}
				}
			}
			log.Logf(1, "loop: add to repro queue '%v'", crash.Title)
			reproducing[crash.Title] = true
			reproQueue = append(reproQueue, crash)
		}

		log.Logf(1, "loop: phase=%v shutdown=%v instances=%v/%v %+v repro: pending=%v reproducing=%v queued=%v",
			phase, shutdown == nil, len(instances), vmCount, instances,
			len(pendingRepro), len(reproducing), len(reproQueue))

		canRepro := func() bool {
			return phase >= phaseTriagedHub &&
				len(reproQueue) != 0 && reproInstances+instancesPerRepro <= vmCount
		}

		if shutdown == nil {
			if len(instances) == vmCount {
				return
			}
		} else {
			for canRepro() && len(instances) >= instancesPerRepro {
				last := len(reproQueue) - 1
				crash := reproQueue[last]
				reproQueue[last] = nil
				reproQueue = reproQueue[:last]
				vmIndexes := append([]int{}, instances[len(instances)-instancesPerRepro:]...)
				instances = instances[:len(instances)-instancesPerRepro]
				reproInstances += instancesPerRepro
				atomic.AddUint32(&mgr.numReproducing, 1)
				log.Logf(1, "loop: starting repro of '%v' on instances %+v", crash.Title, vmIndexes)
				go func() {
					res, err := repro.Run(crash.Output, mgr.cfg, mgr.getReporter(), mgr.vmPool, vmIndexes)
					reproDone <- &ReproResult{vmIndexes, crash.Title, res, err, crash.hub}
				}()
			}
			for !canRepro() && len(instances) != 0 {
				last := len(instances) - 1
				idx := instances[last]
				instances = instances[:last]
				log.Logf(1, "loop: starting instance %v", idx)
				go func() {
					crash, err := mgr.runInstance(idx)
					runDone <- &RunResult{idx, crash, err}
				}()
			}
		}

		var stopRequest chan bool
		if !stopPending && canRepro() {
			stopRequest = mgr.vmStop
		}

		select {
		case stopRequest <- true:
			log.Logf(1, "loop: issued stop request")
			stopPending = true
		case res := <-runDone:
			log.Logf(1, "loop: instance %v finished, crash=%v", res.idx, res.crash != nil)
			if res.err != nil && shutdown != nil {
				log.Logf(0, "%v", res.err)
			}
			stopPending = false
			instances = append(instances, res.idx)
			// On shutdown qemu crashes with "qemu: terminating on signal 2",
			// which we detect as "lost connection". Don't save that as crash.
			if shutdown != nil && res.crash != nil && !mgr.isSuppressed(res.crash) {
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
			if res.res != nil {
				crepro = res.res.CRepro
				title = res.res.Report.Title
			}
			log.Logf(1, "loop: repro on %+v finished '%v', repro=%v crepro=%v desc='%v'",
				res.instances, res.title0, res.res != nil, crepro, title)
			if res.err != nil {
				log.Logf(0, "repro failed: %v", res.err)
			}
			delete(reproducing, res.title0)
			instances = append(instances, res.instances...)
			reproInstances -= instancesPerRepro
			if res.res == nil {
				if !res.hub {
					mgr.saveFailedRepro(res.title0)
				}
			} else {
				mgr.saveRepro(res.res, res.hub)
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
		case reply := <-mgr.reproRequest:
			repros := make(map[string]bool)
			for title := range reproducing {
				repros[title] = true
			}
			reply <- repros
		}
	}
}

func (mgr *Manager) runInstance(index int) (*Crash, error) {
	mgr.checkUsedFiles()
	inst, err := mgr.vmPool.Create(index)
	if err != nil {
		return nil, fmt.Errorf("failed to create instance: %v", err)
	}
	defer inst.Close()

	fwdAddr, err := inst.Forward(mgr.port)
	if err != nil {
		return nil, fmt.Errorf("failed to setup port forwarding: %v", err)
	}
	fuzzerBin, err := inst.Copy(mgr.cfg.SyzFuzzerBin)
	if err != nil {
		return nil, fmt.Errorf("failed to copy binary: %v", err)
	}
	executorBin, err := inst.Copy(mgr.cfg.SyzExecutorBin)
	if err != nil {
		return nil, fmt.Errorf("failed to copy binary: %v", err)
	}

	// Leak detection significantly slows down fuzzing, so detect leaks only on the first instance.
	leak := mgr.cfg.Leak && index == 0
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
	cmd := fmt.Sprintf("%v -executor=%v -name=vm-%v -arch=%v -manager=%v -procs=%v"+
		" -leak=%v -cover=%v -sandbox=%v -debug=%v -v=%d",
		fuzzerBin, executorBin, index, mgr.cfg.TargetArch, fwdAddr, procs,
		leak, mgr.cfg.Cover, mgr.cfg.Sandbox, *flagDebug, fuzzerV)
	outc, errc, err := inst.Run(time.Hour, mgr.vmStop, cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to run fuzzer: %v", err)
	}

	rep := vm.MonitorExecution(outc, errc, mgr.getReporter(), false)
	if rep == nil {
		// This is the only "OK" outcome.
		log.Logf(0, "vm-%v: running for %v, restarting", index, time.Since(start))
		return nil, nil
	}
	cash := &Crash{
		vmIndex: index,
		hub:     false,
		Report:  rep,
	}
	return cash, nil
}

func (mgr *Manager) isSuppressed(crash *Crash) bool {
	for _, re := range mgr.cfg.ParsedSuppressions {
		if !re.Match(crash.Output) {
			continue
		}
		log.Logf(0, "vm-%v: suppressing '%v' with '%v'", crash.vmIndex, crash.Title, re.String())
		mgr.mu.Lock()
		mgr.stats["suppressed"]++
		mgr.mu.Unlock()
		return true
	}
	return false
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
	corrupted := ""
	if crash.Corrupted {
		corrupted = " [corrupted]"
	}
	log.Logf(0, "vm-%v: crash: %v%v", crash.vmIndex, crash.Title, corrupted)
	if err := mgr.getReporter().Symbolize(crash.Report); err != nil {
		log.Logf(0, "failed to symbolize report: %v", err)
	}

	mgr.mu.Lock()
	mgr.stats["crashes"]++
	if !mgr.crashTypes[crash.Title] {
		mgr.crashTypes[crash.Title] = true
		mgr.stats["crash types"]++
	}
	mgr.mu.Unlock()

	if mgr.dash != nil {
		dc := &dashapi.Crash{
			BuildID:     mgr.cfg.Tag,
			Title:       crash.Title,
			Corrupted:   crash.Corrupted,
			Maintainers: crash.Maintainers,
			Log:         crash.Output,
			Report:      crash.Report.Report,
		}
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
	// Save up to 100 reports. If we already have 100, overwrite the oldest one.
	// Newer reports are generally more useful. Overwriting is also needed
	// to be able to understand if a particular bug still happens or already fixed.
	oldestI := 0
	var oldestTime time.Time
	for i := 0; i < 100; i++ {
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
	osutil.WriteFile(filepath.Join(dir, fmt.Sprintf("log%v", oldestI)), crash.Output)
	if len(mgr.cfg.Tag) > 0 {
		osutil.WriteFile(filepath.Join(dir, fmt.Sprintf("tag%v", oldestI)), []byte(mgr.cfg.Tag))
	}
	if len(crash.Report.Report) > 0 {
		osutil.WriteFile(filepath.Join(dir, fmt.Sprintf("report%v", oldestI)), crash.Report.Report)
	}

	return mgr.needRepro(crash)
}

const maxReproAttempts = 3

func (mgr *Manager) needRepro(crash *Crash) bool {
	if !mgr.cfg.Reproduce || crash.Corrupted {
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

func (mgr *Manager) saveFailedRepro(desc string) {
	if mgr.dash != nil {
		cid := &dashapi.CrashID{
			BuildID: mgr.cfg.Tag,
			Title:   desc,
		}
		if err := mgr.dash.ReportFailedRepro(cid); err != nil {
			log.Logf(0, "failed to report failed repro to dashboard: %v", err)
		}
	}
	dir := filepath.Join(mgr.crashdir, hash.String([]byte(desc)))
	osutil.MkdirAll(dir)
	for i := 0; i < maxReproAttempts; i++ {
		name := filepath.Join(dir, fmt.Sprintf("repro%v", i))
		if !osutil.IsExist(name) {
			osutil.WriteFile(name, nil)
			break
		}
	}
}

func (mgr *Manager) saveRepro(res *repro.Result, hub bool) {
	rep := res.Report
	if err := mgr.getReporter().Symbolize(rep); err != nil {
		log.Logf(0, "failed to symbolize repro: %v", err)
	}
	dir := filepath.Join(mgr.crashdir, hash.String([]byte(rep.Title)))
	osutil.MkdirAll(dir)

	if err := osutil.WriteFile(filepath.Join(dir, "description"), []byte(rep.Title+"\n")); err != nil {
		log.Logf(0, "failed to write crash: %v", err)
	}
	opts := fmt.Sprintf("# %+v\n", res.Opts)
	prog := res.Prog.Serialize()
	osutil.WriteFile(filepath.Join(dir, "repro.prog"), append([]byte(opts), prog...))
	if len(mgr.cfg.Tag) > 0 {
		osutil.WriteFile(filepath.Join(dir, "repro.tag"), []byte(mgr.cfg.Tag))
	}
	if len(rep.Output) > 0 {
		osutil.WriteFile(filepath.Join(dir, "repro.log"), rep.Output)
	}
	if len(rep.Report) > 0 {
		osutil.WriteFile(filepath.Join(dir, "repro.report"), rep.Report)
	}
	osutil.WriteFile(filepath.Join(dir, "repro.stats.log"), res.Stats.Log)
	stats := fmt.Sprintf("Extracting prog: %s\nMinimizing prog: %s\nSimplifying prog options: %s\n"+
		"Extracting C: %s\nSimplifying C: %s\n",
		res.Stats.ExtractProgTime, res.Stats.MinimizeProgTime, res.Stats.SimplifyProgTime,
		res.Stats.ExtractCTime, res.Stats.SimplifyCTime)
	osutil.WriteFile(filepath.Join(dir, "repro.stats"), []byte(stats))
	var cprogText []byte
	if res.CRepro {
		cprog, err := csource.Write(res.Prog, res.Opts)
		if err == nil {
			formatted, err := csource.Format(cprog)
			if err == nil {
				cprog = formatted
			}
			osutil.WriteFile(filepath.Join(dir, "repro.cprog"), cprog)
			cprogText = cprog
		} else {
			log.Logf(0, "failed to write C source: %v", err)
		}
	}

	// Append this repro to repro list to send to hub if it didn't come from hub originally.
	if !hub {
		progForHub := []byte(fmt.Sprintf("# %+v\n# %v\n# %v\n%s",
			res.Opts, res.Report.Title, mgr.cfg.Tag, prog))
		mgr.mu.Lock()
		mgr.newRepros = append(mgr.newRepros, progForHub)
		mgr.mu.Unlock()
	}

	if mgr.dash != nil {
		// Note: we intentionally don't set Corrupted for reproducers:
		// 1. This is reproducible so can be debugged even with corrupted report.
		// 2. Repro re-tried 3 times and still got corrupted report at the end,
		//    so maybe corrupted report detection is broken.
		// 3. Reproduction is expensive so it's good to persist the result.
		dc := &dashapi.Crash{
			BuildID:     mgr.cfg.Tag,
			Title:       res.Report.Title,
			Maintainers: res.Report.Maintainers,
			Log:         res.Report.Output,
			Report:      res.Report.Report,
			ReproOpts:   res.Opts.Serialize(),
			ReproSyz:    res.Prog.Serialize(),
			ReproC:      cprogText,
		}
		if _, err := mgr.dash.ReportCrash(dc); err != nil {
			log.Logf(0, "failed to report repro to dashboard: %v", err)
		}
	}
}

func (mgr *Manager) getReporter() report.Reporter {
	if mgr.reporter == nil {
		<-allSymbolsReady
		var err error
		// TODO(dvyukov): we should introduce cfg.Kernel_Obj dir instead of Vmlinux.
		// This will be more general taking into account modules and other OSes.
		kernelSrc, kernelObj := "", ""
		if mgr.cfg.Vmlinux != "" {
			kernelSrc = mgr.cfg.KernelSrc
			kernelObj = filepath.Dir(mgr.cfg.Vmlinux)
		}
		mgr.reporter, err = report.NewReporter(mgr.cfg.TargetOS, kernelSrc, kernelObj,
			allSymbols, mgr.cfg.ParsedIgnores)
		if err != nil {
			log.Fatalf("%v", err)
		}
	}
	return mgr.reporter
}

func (mgr *Manager) minimizeCorpus() {
	if mgr.cfg.Cover && len(mgr.corpus) != 0 {
		inputs := make([]signal.Context, 0, len(mgr.corpus))
		for _, inp := range mgr.corpus {
			inputs = append(inputs, signal.Context{
				Signal:  inp.Signal.Deserialize(),
				Context: inp,
			})
		}
		newCorpus := make(map[string]rpctype.RPCInput)
		for _, ctx := range signal.Minimize(inputs) {
			inp := ctx.(rpctype.RPCInput)
			newCorpus[hash.String(inp.Prog)] = inp
		}
		log.Logf(1, "minimized corpus: %v -> %v", len(mgr.corpus), len(newCorpus))
		mgr.corpus = newCorpus
	}

	// Don't minimize persistent corpus until fuzzers have triaged all inputs from it.
	if mgr.phase >= phaseTriagedCorpus {
		for key := range mgr.corpusDB.Records {
			_, ok1 := mgr.corpus[key]
			_, ok2 := mgr.disabledHashes[key]
			if !ok1 && !ok2 {
				mgr.corpusDB.Delete(key)
			}
		}
		mgr.corpusDB.BumpVersion(currentDBVersion)
	}
}

func (mgr *Manager) Connect(a *rpctype.ConnectArgs, r *rpctype.ConnectRes) error {
	log.Logf(1, "fuzzer %v connected", a.Name)
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	if mgr.firstConnect.IsZero() {
		mgr.firstConnect = time.Now()
		log.Logf(0, "received first connection from test machine %v", a.Name)
	}

	mgr.stats["vm restarts"]++
	f := &Fuzzer{
		name: a.Name,
	}
	mgr.fuzzers[a.Name] = f
	mgr.minimizeCorpus()

	if mgr.prios == nil || time.Since(mgr.lastPrioCalc) > 30*time.Minute {
		// Deserializing all programs is slow, so we do it episodically and without holding the mutex.
		mgr.lastPrioCalc = time.Now()
		inputs := make([][]byte, 0, len(mgr.corpus))
		for _, inp := range mgr.corpus {
			inputs = append(inputs, inp.Prog)
		}
		mgr.mu.Unlock()

		corpus := make([]*prog.Prog, 0, len(inputs))
		for _, inp := range inputs {
			p, err := mgr.target.Deserialize(inp)
			if err != nil {
				panic(err)
			}
			corpus = append(corpus, p)
		}
		prios := mgr.target.CalculatePriorities(corpus)

		mgr.mu.Lock()
		mgr.prios = prios
	}

	for _, inp := range mgr.corpus {
		r.Inputs = append(r.Inputs, inp)
	}
	r.Prios = mgr.prios
	r.EnabledCalls = mgr.enabledSyscalls
	r.NeedCheck = !mgr.vmChecked
	r.MaxSignal = mgr.maxSignal.Serialize()
	for i := 0; i < mgr.cfg.Procs && len(mgr.candidates) > 0; i++ {
		last := len(mgr.candidates) - 1
		r.Candidates = append(r.Candidates, mgr.candidates[last])
		mgr.candidates = mgr.candidates[:last]
	}
	if len(mgr.candidates) == 0 {
		mgr.candidates = nil
	}
	return nil
}

func (mgr *Manager) Check(a *rpctype.CheckArgs, r *int) error {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	if mgr.vmChecked {
		return nil
	}
	log.Logf(0, "machine check: %v calls enabled, kcov=%v, kleakcheck=%v, faultinjection=%v, comps=%v",
		len(a.Calls), a.Kcov, a.Leak, a.Fault, a.CompsSupported)
	if mgr.cfg.Cover && !a.Kcov {
		log.Fatalf("/sys/kernel/debug/kcov is missing on target machine. Enable CONFIG_KCOV and mount debugfs")
	}
	if mgr.cfg.Sandbox == "namespace" && !a.UserNamespaces {
		log.Fatalf("/proc/self/ns/user is missing on target machine or permission is denied." +
			" Can't use requested namespace sandbox. Enable CONFIG_USER_NS")
	}
	if mgr.vmPool != nil {
		if mgr.target.Arch != a.ExecutorArch {
			log.Fatalf("mismatching target/executor arch: target=%v executor=%v",
				mgr.target.Arch, a.ExecutorArch)
		}
		if sys.GitRevision != a.FuzzerGitRev || sys.GitRevision != a.ExecutorGitRev {
			log.Fatalf("syz-manager, syz-fuzzer and syz-executor binaries are built"+
				" on different git revisions\n"+
				"manager= %v\nfuzzer=  %v\nexecutor=%v\n"+
				"this is not supported, rebuild all binaries with make",
				sys.GitRevision, a.FuzzerGitRev, a.ExecutorGitRev)
		}
		if mgr.target.Revision != a.FuzzerSyzRev || mgr.target.Revision != a.ExecutorSyzRev {
			log.Fatalf("syz-manager, syz-fuzzer and syz-executor binaries have different"+
				" versions of system call descriptions compiled in\n"+
				"manager= %v\nfuzzer=  %v\nexecutor=%v\n"+
				"this is not supported, rebuild all binaries with make",
				mgr.target.Revision, a.FuzzerSyzRev, a.ExecutorSyzRev)
		}
	}
	if len(mgr.cfg.EnabledSyscalls) != 0 && len(a.DisabledCalls) != 0 {
		disabled := make(map[string]string)
		for _, dc := range a.DisabledCalls {
			disabled[dc.Name] = dc.Reason
		}
		for _, id := range mgr.enabledSyscalls {
			name := mgr.target.Syscalls[id].Name
			if reason := disabled[name]; reason != "" {
				log.Logf(0, "disabling %v: %v", name, reason)
			}
		}
	}
	if len(a.Calls) == 0 {
		log.Fatalf("all system calls are disabled")
	}
	mgr.vmChecked = true
	mgr.enabledCalls = a.Calls
	return nil
}

func (mgr *Manager) NewInput(a *rpctype.NewInputArgs, r *int) error {
	inputSignal := a.Signal.Deserialize()
	log.Logf(4, "new input from %v for syscall %v (signal=%v, cover=%v)",
		a.Name, a.Call, inputSignal.Len(), len(a.Cover))
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	f := mgr.fuzzers[a.Name]
	if f == nil {
		log.Fatalf("fuzzer %v is not connected", a.Name)
	}

	if _, err := mgr.target.Deserialize(a.RPCInput.Prog); err != nil {
		// This should not happen, but we see such cases episodically, reason unknown.
		log.Logf(0, "failed to deserialize program from fuzzer: %v\n%s", err, a.RPCInput.Prog)
		return nil
	}
	if mgr.corpusSignal.Diff(inputSignal).Empty() {
		return nil
	}
	mgr.stats["manager new inputs"]++
	mgr.corpusSignal.Merge(inputSignal)
	mgr.corpusCover.Merge(a.Cover)
	sig := hash.String(a.RPCInput.Prog)
	if inp, ok := mgr.corpus[sig]; ok {
		// The input is already present, but possibly with diffent signal/coverage/call.
		inputSignal.Merge(inp.Signal.Deserialize())
		inp.Signal = inputSignal.Serialize()
		var inputCover cover.Cover
		inputCover.Merge(inp.Cover)
		inputCover.Merge(a.RPCInput.Cover)
		inp.Cover = inputCover.Serialize()
		mgr.corpus[sig] = inp
	} else {
		mgr.corpus[sig] = a.RPCInput
		mgr.corpusDB.Save(sig, a.RPCInput.Prog, 0)
		if err := mgr.corpusDB.Flush(); err != nil {
			log.Logf(0, "failed to save corpus database: %v", err)
		}
		for _, f1 := range mgr.fuzzers {
			if f1 == f {
				continue
			}
			inp := a.RPCInput
			inp.Cover = nil // Don't send coverage back to all fuzzers.
			f1.inputs = append(f1.inputs, inp)
		}
	}
	return nil
}

func (mgr *Manager) Poll(a *rpctype.PollArgs, r *rpctype.PollRes) error {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	for k, v := range a.Stats {
		mgr.stats[k] += v
	}

	f := mgr.fuzzers[a.Name]
	if f == nil {
		log.Fatalf("fuzzer %v is not connected", a.Name)
	}
	newMaxSignal := mgr.maxSignal.Diff(a.MaxSignal.Deserialize())
	if !newMaxSignal.Empty() {
		mgr.maxSignal.Merge(newMaxSignal)
		for _, f1 := range mgr.fuzzers {
			if f1 == f {
				continue
			}
			f1.newMaxSignal.Merge(newMaxSignal)
		}
	}
	if !f.newMaxSignal.Empty() {
		r.MaxSignal = f.newMaxSignal.Serialize()
		f.newMaxSignal = nil
	}
	for i := 0; i < 100 && len(f.inputs) > 0; i++ {
		last := len(f.inputs) - 1
		r.NewInputs = append(r.NewInputs, f.inputs[last])
		f.inputs = f.inputs[:last]
	}
	if len(f.inputs) == 0 {
		f.inputs = nil
	}

	if a.NeedCandidates {
		for i := 0; i < mgr.cfg.Procs && len(mgr.candidates) > 0; i++ {
			last := len(mgr.candidates) - 1
			r.Candidates = append(r.Candidates, mgr.candidates[last])
			mgr.candidates = mgr.candidates[:last]
		}
	}
	if len(mgr.candidates) == 0 {
		mgr.candidates = nil
		if mgr.phase == phaseInit {
			if mgr.cfg.HubClient != "" {
				mgr.phase = phaseTriagedCorpus
			} else {
				mgr.phase = phaseTriagedHub
			}
		}
	}
	log.Logf(4, "poll from %v: candidates=%v inputs=%v", a.Name, len(r.Candidates), len(r.NewInputs))
	return nil
}

func (mgr *Manager) hubSync() {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	switch mgr.phase {
	case phaseInit:
		return
	case phaseTriagedCorpus:
		mgr.phase = phaseQueriedHub
	case phaseQueriedHub:
		if len(mgr.candidates) == 0 {
			mgr.phase = phaseTriagedHub
		}
	case phaseTriagedHub:
	default:
		panic("unknown phase")
	}

	mgr.minimizeCorpus()
	if mgr.hub == nil {
		a := &rpctype.HubConnectArgs{
			Client:  mgr.cfg.HubClient,
			Key:     mgr.cfg.HubKey,
			Manager: mgr.cfg.Name,
			Fresh:   mgr.fresh,
			Calls:   mgr.enabledCalls,
		}
		hubCorpus := make(map[hash.Sig]bool)
		for _, inp := range mgr.corpus {
			hubCorpus[hash.Hash(inp.Prog)] = true
			a.Corpus = append(a.Corpus, inp.Prog)
		}
		mgr.mu.Unlock()
		// Hub.Connect request can be very large, so do it on a transient connection
		// (rpc connection buffers never shrink).
		// Also don't do hub rpc's under the mutex -- hub can be slow or inaccessible.
		if err := rpctype.RPCCall(mgr.cfg.HubAddr, "Hub.Connect", a, nil); err != nil {
			mgr.mu.Lock()
			log.Logf(0, "Hub.Connect rpc failed: %v", err)
			return
		}
		conn, err := rpctype.NewRPCClient(mgr.cfg.HubAddr)
		if err != nil {
			mgr.mu.Lock()
			log.Logf(0, "failed to connect to hub at %v: %v", mgr.cfg.HubAddr, err)
			return
		}
		mgr.mu.Lock()
		mgr.hub = conn
		mgr.hubCorpus = hubCorpus
		mgr.fresh = false
		log.Logf(0, "connected to hub at %v, corpus %v", mgr.cfg.HubAddr, len(mgr.corpus))
	}

	a := &rpctype.HubSyncArgs{
		Client:  mgr.cfg.HubClient,
		Key:     mgr.cfg.HubKey,
		Manager: mgr.cfg.Name,
	}
	corpus := make(map[hash.Sig]bool)
	for _, inp := range mgr.corpus {
		sig := hash.Hash(inp.Prog)
		corpus[sig] = true
		if mgr.hubCorpus[sig] {
			continue
		}
		mgr.hubCorpus[sig] = true
		a.Add = append(a.Add, inp.Prog)
	}
	for sig := range mgr.hubCorpus {
		if corpus[sig] {
			continue
		}
		delete(mgr.hubCorpus, sig)
		a.Del = append(a.Del, sig.String())
	}
	for {
		a.Repros = mgr.newRepros

		mgr.mu.Unlock()

		if mgr.cfg.Reproduce && mgr.dash != nil {
			needReproReply := make(chan bool)
			mgr.needMoreRepros <- needReproReply
			a.NeedRepros = <-needReproReply
		}

		r := new(rpctype.HubSyncRes)
		if err := mgr.hub.Call("Hub.Sync", a, r); err != nil {
			mgr.mu.Lock()
			log.Logf(0, "Hub.Sync rpc failed: %v", err)
			mgr.hub.Close()
			mgr.hub = nil
			return
		}

		reproDropped := 0
		for _, repro := range r.Repros {
			_, err := mgr.target.Deserialize(repro)
			if err != nil {
				reproDropped++
				continue
			}
			mgr.hubReproQueue <- &Crash{
				vmIndex: -1,
				hub:     true,
				Report: &report.Report{
					Title:  "external repro",
					Output: repro,
				},
			}
		}

		mgr.mu.Lock()
		mgr.newRepros = nil
		dropped := 0
		for _, inp := range r.Progs {
			_, err := mgr.target.Deserialize(inp)
			if err != nil {
				dropped++
				continue
			}
			mgr.candidates = append(mgr.candidates, rpctype.RPCCandidate{
				Prog:      inp,
				Minimized: false, // don't trust programs from hub
				Smashed:   false,
			})
		}
		mgr.stats["hub add"] += uint64(len(a.Add))
		mgr.stats["hub del"] += uint64(len(a.Del))
		mgr.stats["hub drop"] += uint64(dropped)
		mgr.stats["hub new"] += uint64(len(r.Progs) - dropped)
		mgr.stats["hub sent repros"] += uint64(len(a.Repros))
		mgr.stats["hub recv repros"] += uint64(len(r.Repros) - reproDropped)
		log.Logf(0, "hub sync: send: add %v, del %v, repros %v; recv: progs: drop %v, new %v,"+
			" repros: drop: %v, new %v; more %v",
			len(a.Add), len(a.Del), len(a.Repros), dropped, len(r.Progs)-dropped,
			reproDropped, len(r.Repros)-reproDropped, r.More)
		if len(r.Progs)+r.More == 0 {
			break
		}
		a.Add = nil
		a.Del = nil
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
	addUsedFile(cfg.SyzFuzzerBin)
	addUsedFile(cfg.SyzExecprogBin)
	addUsedFile(cfg.SyzExecutorBin)
	addUsedFile(cfg.SSHKey)
	addUsedFile(cfg.Vmlinux)
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
	var lastCrashes, lastExecs uint64
	for {
		time.Sleep(time.Minute)
		mgr.mu.Lock()
		if mgr.firstConnect.IsZero() {
			mgr.mu.Unlock()
			continue
		}
		crashes := mgr.stats["crashes"]
		execs := mgr.stats["exec total"]
		req := &dashapi.ManagerStatsReq{
			Name:        mgr.cfg.Name,
			Addr:        webAddr,
			UpTime:      time.Since(mgr.firstConnect),
			Corpus:      uint64(len(mgr.corpus)),
			Cover:       uint64(mgr.corpusSignal.Len()),
			FuzzingTime: mgr.fuzzingTime - lastFuzzingTime,
			Crashes:     crashes - lastCrashes,
			Execs:       execs - lastExecs,
		}
		mgr.mu.Unlock()

		if err := mgr.dash.UploadManagerStats(req); err != nil {
			log.Logf(0, "faield to upload dashboard stats: %v", err)
			continue
		}
		mgr.mu.Lock()
		lastFuzzingTime += req.FuzzingTime
		lastCrashes += req.Crashes
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
		if GCE, err := gce.NewContext(); err == nil {
			addr = net.JoinHostPort(GCE.ExternalIP, port)
		}
	}
	return "http://" + addr
}
