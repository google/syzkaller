// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/syzkaller/config"
	"github.com/google/syzkaller/cover"
	"github.com/google/syzkaller/csource"
	"github.com/google/syzkaller/dashboard"
	"github.com/google/syzkaller/db"
	"github.com/google/syzkaller/hash"
	. "github.com/google/syzkaller/log"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/report"
	"github.com/google/syzkaller/repro"
	. "github.com/google/syzkaller/rpctype"
	"github.com/google/syzkaller/vm"
	_ "github.com/google/syzkaller/vm/adb"
	_ "github.com/google/syzkaller/vm/gce"
	_ "github.com/google/syzkaller/vm/kvm"
	_ "github.com/google/syzkaller/vm/local"
	_ "github.com/google/syzkaller/vm/qemu"
)

var (
	flagConfig = flag.String("config", "", "configuration file")
	flagDebug  = flag.Bool("debug", false, "dump all VM output to console")
	flagBench  = flag.String("bench", "", "write execution statistics into this file periodically")
)

type Manager struct {
	cfg          *config.Config
	crashdir     string
	port         int
	corpusDB     *db.DB
	startTime    time.Time
	firstConnect time.Time
	lastPrioCalc time.Time
	fuzzingTime  time.Duration
	stats        map[string]uint64
	crashTypes   map[string]bool
	vmStop       chan bool
	vmChecked    bool
	fresh        bool
	numFuzzing   uint32

	dash *dashboard.Dashboard

	mu              sync.Mutex
	enabledSyscalls string
	enabledCalls    []string // as determined by fuzzer

	candidates     []RpcCandidate // untriaged inputs
	disabledHashes map[string]struct{}
	corpus         map[string]RpcInput
	corpusSignal   map[uint32]struct{}
	maxSignal      map[uint32]struct{}
	corpusCover    map[uint32]struct{}
	prios          [][]float32

	fuzzers   map[string]*Fuzzer
	hub       *RpcClient
	hubCorpus map[hash.Sig]bool
}

type Fuzzer struct {
	name         string
	inputs       []RpcInput
	newMaxSignal []uint32
}

type Crash struct {
	vmName string
	desc   string
	text   []byte
	output []byte
}

func main() {
	flag.Parse()
	EnableLogCaching(1000, 1<<20)
	cfg, syscalls, err := config.Parse(*flagConfig)
	if err != nil {
		Fatalf("%v", err)
	}
	if *flagDebug {
		cfg.Debug = true
		cfg.Count = 1
	}
	initAllCover(cfg.Vmlinux)
	RunManager(cfg, syscalls)
}

func RunManager(cfg *config.Config, syscalls map[int]bool) {
	crashdir := filepath.Join(cfg.Workdir, "crashes")
	os.MkdirAll(crashdir, 0700)

	enabledSyscalls := ""
	if len(syscalls) != 0 {
		buf := new(bytes.Buffer)
		for c := range syscalls {
			fmt.Fprintf(buf, ",%v", c)
		}
		enabledSyscalls = buf.String()[1:]
		Logf(1, "enabled syscalls: %v", enabledSyscalls)
	}

	mgr := &Manager{
		cfg:             cfg,
		crashdir:        crashdir,
		startTime:       time.Now(),
		stats:           make(map[string]uint64),
		crashTypes:      make(map[string]bool),
		enabledSyscalls: enabledSyscalls,
		corpus:          make(map[string]RpcInput),
		disabledHashes:  make(map[string]struct{}),
		corpusSignal:    make(map[uint32]struct{}),
		maxSignal:       make(map[uint32]struct{}),
		corpusCover:     make(map[uint32]struct{}),
		fuzzers:         make(map[string]*Fuzzer),
		fresh:           true,
		vmStop:          make(chan bool),
	}

	Logf(0, "loading corpus...")
	dbFilename := filepath.Join(cfg.Workdir, "corpus.db")
	if _, err := os.Stat(dbFilename); err != nil {
		if err := convertPersistentToDB(filepath.Join(cfg.Workdir, "corpus"), dbFilename); err != nil {
			Fatalf("failed to convert old corpus: %v", err)
		}
	}
	var err error
	mgr.corpusDB, err = db.Open(dbFilename)
	if err != nil {
		Fatalf("failed to open corpus database: %v", err)
	}
	deleted := 0
	for key, rec := range mgr.corpusDB.Records {
		p, err := prog.Deserialize(rec.Val)
		if err != nil {
			if deleted < 10 {
				Logf(0, "deleting broken program: %v\n%s", err, rec.Val)
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
			// We won't execute it, but remeber its hash so
			// it is not deleted during minimization.
			// TODO: use mgr.enabledCalls which accounts for missing devices, etc.
			// But it is available only after vm check.
			mgr.disabledHashes[hash.String(rec.Val)] = struct{}{}
			continue
		}
		mgr.candidates = append(mgr.candidates, RpcCandidate{
			Prog:      rec.Val,
			Minimized: true, // don't reminimize programs from corpus, it takes lots of time on start
		})
	}
	mgr.fresh = len(mgr.corpusDB.Records) == 0
	Logf(0, "loaded %v programs (%v total, %v deleted)", len(mgr.candidates), len(mgr.corpusDB.Records), deleted)

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
	mgr.initHttp()

	// Create RPC server for fuzzers.
	s, err := NewRpcServer(cfg.Rpc, mgr)
	if err != nil {
		Fatalf("failed to create rpc server: %v", err)
	}
	Logf(0, "serving rpc on tcp://%v", s.Addr())
	mgr.port = s.Addr().(*net.TCPAddr).Port
	go s.Serve()

	if cfg.Dashboard_Addr != "" {
		mgr.dash = &dashboard.Dashboard{
			Addr:   cfg.Dashboard_Addr,
			Client: cfg.Name,
			Key:    cfg.Dashboard_Key,
		}
	}

	go func() {
		for lastTime := time.Now(); ; {
			time.Sleep(10 * time.Second)
			now := time.Now()
			diff := now.Sub(lastTime)
			lastTime = now
			mgr.mu.Lock()
			mgr.fuzzingTime += diff * time.Duration(atomic.LoadUint32(&mgr.numFuzzing))
			executed := mgr.stats["exec total"]
			crashes := mgr.stats["crashes"]
			mgr.mu.Unlock()
			Logf(0, "executed programs: %v, crashes: %v", executed, crashes)
		}
	}()

	if *flagBench != "" {
		f, err := os.OpenFile(*flagBench, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0640)
		if err != nil {
			Fatalf("failed to open bench file: %v", err)
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
				vals["signal"] = uint64(len(mgr.corpusSignal))
				vals["coverage"] = uint64(len(mgr.corpusCover))
				for k, v := range mgr.stats {
					vals[k] = v
				}
				mgr.mu.Unlock()

				data, err := json.MarshalIndent(vals, "", "  ")
				if err != nil {
					Fatalf("failed to serialize bench data")
				}
				if _, err := f.Write(append(data, '\n')); err != nil {
					Fatalf("failed to write bench data")
				}
			}
		}()
	}

	if mgr.cfg.Hub_Addr != "" {
		go func() {
			for {
				time.Sleep(time.Minute)
				mgr.hubSync()
			}
		}()
	}

	go func() {
		c := make(chan os.Signal, 2)
		signal.Notify(c, syscall.SIGINT)
		<-c
		close(vm.Shutdown)
		Logf(0, "shutting down...")
		<-c
		Fatalf("terminating")
	}()

	mgr.vmLoop()
}

type RunResult struct {
	idx   int
	crash *Crash
	err   error
}

type ReproResult struct {
	instances []int
	crash     *Crash
	res       *repro.Result
	err       error
}

func (mgr *Manager) vmLoop() {
	Logf(0, "booting test machines...")
	reproInstances := 4
	if reproInstances > mgr.cfg.Count {
		reproInstances = mgr.cfg.Count
	}
	instances := make([]int, mgr.cfg.Count)
	for i := range instances {
		instances[i] = mgr.cfg.Count - i - 1
	}
	runDone := make(chan *RunResult, 1)
	pendingRepro := make(map[*Crash]bool)
	reproducing := make(map[string]bool)
	var reproQueue []*Crash
	reproDone := make(chan *ReproResult, 1)
	stopPending := false
	shutdown := vm.Shutdown
	for {
		for crash := range pendingRepro {
			if reproducing[crash.desc] {
				continue
			}
			delete(pendingRepro, crash)
			if !mgr.needRepro(crash.desc) {
				continue
			}
			Logf(1, "loop: add to repro queue '%v'", crash.desc)
			reproducing[crash.desc] = true
			reproQueue = append(reproQueue, crash)
		}

		Logf(1, "loop: shutdown=%v instances=%v/%v %+v repro: pending=%v reproducing=%v queued=%v",
			shutdown == nil, len(instances), mgr.cfg.Count, instances,
			len(pendingRepro), len(reproducing), len(reproQueue))
		if shutdown == nil {
			if len(instances) == mgr.cfg.Count {
				return
			}
		} else {
			for len(reproQueue) != 0 && len(instances) >= reproInstances {
				last := len(reproQueue) - 1
				crash := reproQueue[last]
				reproQueue[last] = nil
				reproQueue = reproQueue[:last]
				vmIndexes := append([]int{}, instances[len(instances)-reproInstances:]...)
				instances = instances[:len(instances)-reproInstances]
				Logf(1, "loop: starting repro of '%v' on instances %+v", crash.desc, vmIndexes)
				go func() {
					res, err := repro.Run(crash.output, mgr.cfg, vmIndexes)
					reproDone <- &ReproResult{vmIndexes, crash, res, err}
				}()
			}
			for len(reproQueue) == 0 && len(instances) != 0 {
				last := len(instances) - 1
				idx := instances[last]
				instances = instances[:last]
				Logf(1, "loop: starting instance %v", idx)
				go func() {
					vmCfg, err := config.CreateVMConfig(mgr.cfg, idx)
					if err != nil {
						Fatalf("failed to create VM config: %v", err)
					}
					crash, err := mgr.runInstance(vmCfg, idx == 0)
					runDone <- &RunResult{idx, crash, err}
				}()
			}
		}

		var stopRequest chan bool
		if len(reproQueue) != 0 && !stopPending {
			stopRequest = mgr.vmStop
		}

		select {
		case stopRequest <- true:
			Logf(1, "loop: issued stop request")
			stopPending = true
		case res := <-runDone:
			Logf(1, "loop: instance %v finished, crash=%v", res.idx, res.crash != nil)
			if res.err != nil && shutdown != nil {
				Logf(0, "%v", res.err)
			}
			stopPending = false
			instances = append(instances, res.idx)
			// On shutdown qemu crashes with "qemu: terminating on signal 2",
			// which we detect as "lost connection". Don't save that as crash.
			if shutdown != nil && res.crash != nil && !mgr.isSuppressed(res.crash) {
				mgr.saveCrash(res.crash)
				if mgr.needRepro(res.crash.desc) {
					Logf(1, "loop: add pending repro for '%v'", res.crash.desc)
					pendingRepro[res.crash] = true
				}
			}
		case res := <-reproDone:
			crepro := false
			if res.res != nil {
				crepro = res.res.CRepro
			}
			Logf(1, "loop: repro on instances %+v finished '%v', repro=%v crepro=%v",
				res.instances, res.crash.desc, res.res != nil, crepro)
			if res.err != nil {
				Logf(0, "repro failed: %v", res.err)
			}
			delete(reproducing, res.crash.desc)
			instances = append(instances, res.instances...)
			mgr.saveRepro(res.crash, res.res)
		case <-shutdown:
			Logf(1, "loop: shutting down...")
			shutdown = nil
		}
	}
}

func (mgr *Manager) runInstance(vmCfg *vm.Config, first bool) (*Crash, error) {
	inst, err := vm.Create(mgr.cfg.Type, vmCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create instance: %v", err)
	}
	defer inst.Close()

	fwdAddr, err := inst.Forward(mgr.port)
	if err != nil {
		return nil, fmt.Errorf("failed to setup port forwarding: %v", err)
	}
	fuzzerBin, err := inst.Copy(filepath.Join(mgr.cfg.Syzkaller, "bin", "syz-fuzzer"))
	if err != nil {
		return nil, fmt.Errorf("failed to copy binary: %v", err)
	}
	executorBin, err := inst.Copy(filepath.Join(mgr.cfg.Syzkaller, "bin", "syz-executor"))
	if err != nil {
		return nil, fmt.Errorf("failed to copy binary: %v", err)
	}

	// Leak detection significantly slows down fuzzing, so detect leaks only on the first instance.
	leak := first && mgr.cfg.Leak
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
	cmd := fmt.Sprintf("%v -executor=%v -name=%v -manager=%v -output=%v -procs=%v -leak=%v -cover=%v -sandbox=%v -debug=%v -v=%d",
		fuzzerBin, executorBin, vmCfg.Name, fwdAddr, mgr.cfg.Output, procs, leak, mgr.cfg.Cover, mgr.cfg.Sandbox, *flagDebug, fuzzerV)
	outc, errc, err := inst.Run(time.Hour, mgr.vmStop, cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to run fuzzer: %v", err)
	}

	desc, text, output, crashed, timedout := vm.MonitorExecution(outc, errc, mgr.cfg.Type == "local", true, mgr.cfg.ParsedIgnores)
	if timedout {
		// This is the only "OK" outcome.
		Logf(0, "%v: running for %v, restarting (%v)", vmCfg.Name, time.Since(start), desc)
		return nil, nil
	}
	if !crashed {
		// syz-fuzzer exited, but it should not.
		desc = "lost connection to test machine"
	}
	return &Crash{vmCfg.Name, desc, text, output}, nil
}

func (mgr *Manager) isSuppressed(crash *Crash) bool {
	for _, re := range mgr.cfg.ParsedSuppressions {
		if !re.Match(crash.output) {
			continue
		}
		Logf(1, "%v: suppressing '%v' with '%v'", crash.vmName, crash.desc, re.String())
		mgr.mu.Lock()
		mgr.stats["suppressed"]++
		mgr.mu.Unlock()
		return true
	}
	return false
}

func (mgr *Manager) saveCrash(crash *Crash) {
	Logf(0, "%v: crash: %v", crash.vmName, crash.desc)
	mgr.mu.Lock()
	mgr.stats["crashes"]++
	if !mgr.crashTypes[crash.desc] {
		mgr.crashTypes[crash.desc] = true
		mgr.stats["crash types"]++
	}
	mgr.mu.Unlock()

	sig := hash.Hash([]byte(crash.desc))
	id := sig.String()
	dir := filepath.Join(mgr.crashdir, id)
	os.MkdirAll(dir, 0700)
	if err := ioutil.WriteFile(filepath.Join(dir, "description"), []byte(crash.desc+"\n"), 0660); err != nil {
		Logf(0, "failed to write crash: %v", err)
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
			break
		}
		if oldestTime.IsZero() || info.ModTime().Before(oldestTime) {
			oldestI = i
			oldestTime = info.ModTime()
		}
	}
	ioutil.WriteFile(filepath.Join(dir, fmt.Sprintf("log%v", oldestI)), crash.output, 0660)
	if len(mgr.cfg.Tag) > 0 {
		ioutil.WriteFile(filepath.Join(dir, fmt.Sprintf("tag%v", oldestI)), []byte(mgr.cfg.Tag), 0660)
	}
	if len(crash.text) > 0 {
		symbolized, err := report.Symbolize(mgr.cfg.Vmlinux, crash.text)
		if err != nil {
			Logf(0, "failed to symbolize crash: %v", err)
		} else {
			crash.text = symbolized
		}
		ioutil.WriteFile(filepath.Join(dir, fmt.Sprintf("report%v", oldestI)), crash.text, 0660)
	}

	if mgr.dash != nil {
		dc := &dashboard.Crash{
			Tag:    mgr.cfg.Tag,
			Desc:   crash.desc,
			Log:    crash.output,
			Report: crash.text,
		}
		if err := mgr.dash.ReportCrash(dc); err != nil {
			Logf(0, "failed to report crash to dashboard: %v", err)
		}
	}
}

const maxReproAttempts = 3

func (mgr *Manager) needRepro(desc string) bool {
	if !mgr.cfg.Reproduce {
		return false
	}
	sig := hash.Hash([]byte(desc))
	dir := filepath.Join(mgr.crashdir, sig.String())
	if _, err := os.Stat(filepath.Join(dir, "repro.prog")); err == nil {
		return false
	}
	for i := 0; i < maxReproAttempts; i++ {
		if _, err := os.Stat(filepath.Join(dir, fmt.Sprintf("repro%v", i))); err != nil {
			return true
		}
	}
	return false
}

func (mgr *Manager) saveRepro(crash *Crash, res *repro.Result) {
	sig := hash.Hash([]byte(crash.desc))
	dir := filepath.Join(mgr.crashdir, sig.String())
	if res == nil {
		if mgr.dash != nil {
			dr := &dashboard.Repro{
				Crash: dashboard.Crash{
					Tag:  mgr.cfg.Tag,
					Desc: crash.desc,
				},
				Reproduced: false,
			}
			if err := mgr.dash.ReportRepro(dr); err != nil {
				Logf(0, "failed to report repro to dashboard: %v", err)
			}
		}
		for i := 0; i < maxReproAttempts; i++ {
			name := filepath.Join(dir, fmt.Sprintf("repro%v", i))
			if _, err := os.Stat(name); err != nil {
				ioutil.WriteFile(name, nil, 0660)
				break
			}
		}
		return
	}
	opts := fmt.Sprintf("# %+v\n", res.Opts)
	prog := res.Prog.Serialize()
	ioutil.WriteFile(filepath.Join(dir, "repro.prog"), append([]byte(opts), prog...), 0660)
	if len(mgr.cfg.Tag) > 0 {
		ioutil.WriteFile(filepath.Join(dir, "repro.tag"), []byte(mgr.cfg.Tag), 0660)
	}
	if len(crash.text) > 0 {
		ioutil.WriteFile(filepath.Join(dir, "repro.report"), []byte(crash.text), 0660)
	}
	var cprogText []byte
	if res.CRepro {
		cprog, err := csource.Write(res.Prog, res.Opts)
		if err == nil {
			formatted, err := csource.Format(cprog)
			if err == nil {
				cprog = formatted
			}
			ioutil.WriteFile(filepath.Join(dir, "repro.cprog"), cprog, 0660)
			cprogText = cprog
		} else {
			Logf(0, "failed to write C source: %v", err)
		}
	}

	if mgr.dash != nil {
		dr := &dashboard.Repro{
			Crash: dashboard.Crash{
				Tag:    mgr.cfg.Tag,
				Desc:   crash.desc,
				Report: crash.text,
			},
			Reproduced: true,
			Opts:       fmt.Sprintf("%+v", res.Opts),
			Prog:       res.Prog.Serialize(),
			CProg:      cprogText,
		}
		if err := mgr.dash.ReportRepro(dr); err != nil {
			Logf(0, "failed to report repro to dashboard: %v", err)
		}
	}
}

func (mgr *Manager) minimizeCorpus() {
	if mgr.cfg.Cover && len(mgr.corpus) != 0 {
		var cov []cover.Cover
		var inputs []RpcInput
		for _, inp := range mgr.corpus {
			cov = append(cov, inp.Signal)
			inputs = append(inputs, inp)
		}
		newCorpus := make(map[string]RpcInput)
		for _, idx := range cover.Minimize(cov) {
			inp := inputs[idx]
			newCorpus[hash.String(inp.Prog)] = inp
		}
		Logf(1, "minimized corpus: %v -> %v", len(mgr.corpus), len(newCorpus))
		mgr.corpus = newCorpus
	}

	// Don't minimize persistent corpus until fuzzers have triaged all inputs from it.
	if len(mgr.candidates) == 0 {
		for key := range mgr.corpusDB.Records {
			_, ok1 := mgr.corpus[key]
			_, ok2 := mgr.disabledHashes[key]
			if !ok1 && !ok2 {
				mgr.corpusDB.Delete(key)
			}
		}
		mgr.corpusDB.Flush()
	}
}

func (mgr *Manager) Connect(a *ConnectArgs, r *ConnectRes) error {
	Logf(1, "fuzzer %v connected", a.Name)
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	if mgr.firstConnect.IsZero() {
		mgr.firstConnect = time.Now()
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
			p, err := prog.Deserialize(inp)
			if err != nil {
				panic(err)
			}
			corpus = append(corpus, p)
		}
		prios := prog.CalculatePriorities(corpus)

		mgr.mu.Lock()
		mgr.prios = prios
	}

	f.inputs = nil
	for _, inp := range mgr.corpus {
		r.Inputs = append(r.Inputs, inp)
	}
	r.Prios = mgr.prios
	r.EnabledCalls = mgr.enabledSyscalls
	r.NeedCheck = !mgr.vmChecked
	r.MaxSignal = make([]uint32, 0, len(mgr.maxSignal))
	for s := range mgr.maxSignal {
		r.MaxSignal = append(r.MaxSignal, s)
	}
	f.newMaxSignal = nil
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

func (mgr *Manager) Check(a *CheckArgs, r *int) error {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	if mgr.vmChecked {
		return nil
	}
	Logf(1, "fuzzer %v vm check: %v calls enabled", a.Name, len(a.Calls))
	if len(a.Calls) == 0 {
		Fatalf("no system calls enabled")
	}
	if mgr.cfg.Cover && !a.Kcov {
		Fatalf("/sys/kernel/debug/kcov is missing. Enable CONFIG_KCOV and mount debugfs")
	}
	mgr.vmChecked = true
	mgr.enabledCalls = a.Calls
	return nil
}

func (mgr *Manager) NewInput(a *NewInputArgs, r *int) error {
	Logf(2, "new input from %v for syscall %v (signal=%v cover=%v)", a.Name, a.Call, len(a.Signal), len(a.Cover))
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	f := mgr.fuzzers[a.Name]
	if f == nil {
		Fatalf("fuzzer %v is not connected", a.Name)
	}

	if !cover.SignalNew(mgr.corpusSignal, a.Signal) {
		return nil
	}
	mgr.stats["manager new inputs"]++
	cover.SignalAdd(mgr.corpusSignal, a.Signal)
	cover.SignalAdd(mgr.corpusCover, a.Cover)
	sig := hash.String(a.RpcInput.Prog)
	if inp, ok := mgr.corpus[sig]; ok {
		// The input is already present, but possibly with diffent signal/coverage/call.
		inp.Signal = cover.Union(inp.Signal, a.RpcInput.Signal)
		inp.Cover = cover.Union(inp.Cover, a.RpcInput.Cover)
		mgr.corpus[sig] = inp
	} else {
		mgr.corpus[sig] = a.RpcInput
		mgr.corpusDB.Save(sig, a.RpcInput.Prog, 0)
		if err := mgr.corpusDB.Flush(); err != nil {
			Logf(0, "failed to save corpus database: %v", err)
		}
		for _, f1 := range mgr.fuzzers {
			if f1 == f {
				continue
			}
			inp := a.RpcInput
			inp.Cover = nil // Don't send coverage back to all fuzzers.
			f1.inputs = append(f1.inputs, inp)
		}
	}
	return nil
}

func (mgr *Manager) Poll(a *PollArgs, r *PollRes) error {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	for k, v := range a.Stats {
		mgr.stats[k] += v
	}

	f := mgr.fuzzers[a.Name]
	if f == nil {
		Fatalf("fuzzer %v is not connected", a.Name)
	}
	var newMaxSignal []uint32
	for _, s := range a.MaxSignal {
		if _, ok := mgr.maxSignal[s]; ok {
			continue
		}
		mgr.maxSignal[s] = struct{}{}
		newMaxSignal = append(newMaxSignal, s)
	}
	for _, f1 := range mgr.fuzzers {
		if f1 == f {
			continue
		}
		f1.newMaxSignal = append(f1.newMaxSignal, newMaxSignal...)
	}
	r.MaxSignal = f.newMaxSignal
	f.newMaxSignal = nil
	for i := 0; i < 100 && len(f.inputs) > 0; i++ {
		last := len(f.inputs) - 1
		r.NewInputs = append(r.NewInputs, f.inputs[last])
		f.inputs = f.inputs[:last]
	}
	if len(f.inputs) == 0 {
		f.inputs = nil
	}

	for i := 0; i < mgr.cfg.Procs && len(mgr.candidates) > 0; i++ {
		last := len(mgr.candidates) - 1
		r.Candidates = append(r.Candidates, mgr.candidates[last])
		mgr.candidates = mgr.candidates[:last]
	}
	if len(mgr.candidates) == 0 {
		mgr.candidates = nil
	}
	Logf(2, "poll from %v: recv maxsignal=%v, send maxsignal=%v candidates=%v inputs=%v",
		a.Name, len(a.MaxSignal), len(r.MaxSignal), len(r.Candidates), len(r.NewInputs))
	return nil
}

func (mgr *Manager) hubSync() {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	if !mgr.vmChecked || len(mgr.candidates) != 0 {
		return
	}

	mgr.minimizeCorpus()
	if mgr.hub == nil {
		a := &HubConnectArgs{
			Name:  mgr.cfg.Name,
			Key:   mgr.cfg.Hub_Key,
			Fresh: mgr.fresh,
			Calls: mgr.enabledCalls,
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
		if err := RpcCall(mgr.cfg.Hub_Addr, "Hub.Connect", a, nil); err != nil {
			mgr.mu.Lock()
			Logf(0, "Hub.Connect rpc failed: %v", err)
			return
		}
		conn, err := NewRpcClient(mgr.cfg.Hub_Addr)
		if err != nil {
			mgr.mu.Lock()
			Logf(0, "failed to connect to hub at %v: %v", mgr.cfg.Hub_Addr, err)
			return
		}
		mgr.mu.Lock()
		mgr.hub = conn
		mgr.hubCorpus = hubCorpus
		mgr.fresh = false
		Logf(0, "connected to hub at %v, corpus %v", mgr.cfg.Hub_Addr, len(mgr.corpus))
	}

	a := &HubSyncArgs{
		Name: mgr.cfg.Name,
		Key:  mgr.cfg.Hub_Key,
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
	mgr.mu.Unlock()
	r := new(HubSyncRes)
	if err := mgr.hub.Call("Hub.Sync", a, r); err != nil {
		mgr.mu.Lock()
		Logf(0, "Hub.Sync rpc failed: %v", err)
		mgr.hub.Close()
		mgr.hub = nil
		return
	}
	mgr.mu.Lock()
	dropped := 0
	for _, inp := range r.Inputs {
		_, err := prog.Deserialize(inp)
		if err != nil {
			dropped++
			continue
		}
		mgr.candidates = append(mgr.candidates, RpcCandidate{
			Prog:      inp,
			Minimized: false, // don't trust programs from hub
		})
	}
	mgr.stats["hub add"] += uint64(len(a.Add))
	mgr.stats["hub del"] += uint64(len(a.Del))
	mgr.stats["hub drop"] += uint64(dropped)
	mgr.stats["hub new"] += uint64(len(r.Inputs) - dropped)
	Logf(0, "hub sync: add %v, del %v, drop %v, new %v", len(a.Add), len(a.Del), dropped, len(r.Inputs)-dropped)
}
