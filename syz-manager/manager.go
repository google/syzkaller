// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/syzkaller/config"
	"github.com/google/syzkaller/cover"
	"github.com/google/syzkaller/hash"
	. "github.com/google/syzkaller/log"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/report"
	. "github.com/google/syzkaller/rpctype"
	"github.com/google/syzkaller/sys"
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
)

type Manager struct {
	cfg              *config.Config
	crashdir         string
	port             int
	persistentCorpus *PersistentSet
	startTime        time.Time
	firstConnect     time.Time
	stats            map[string]uint64
	shutdown         uint32
	vmChecked        bool
	fresh            bool

	mu              sync.Mutex
	enabledSyscalls string
	enabledCalls    []string // as determined by fuzzer
	suppressions    []*regexp.Regexp

	candidates     [][]byte // untriaged inputs
	disabledHashes []string
	corpus         []RpcInput
	corpusCover    []cover.Cover
	prios          [][]float32

	fuzzers   map[string]*Fuzzer
	hub       *rpc.Client
	hubCorpus map[hash.Sig]bool
}

type Fuzzer struct {
	name   string
	inputs []RpcInput
}

type Crash struct {
	desc   string
	text   []byte
	output []byte
}

func main() {
	flag.Parse()
	EnableLogCaching(1000, 1<<20)
	cfg, syscalls, suppressions, err := config.Parse(*flagConfig)
	if err != nil {
		Fatalf("%v", err)
	}
	if *flagDebug {
		cfg.Debug = true
		cfg.Count = 1
	}
	initAllCover(cfg.Vmlinux)
	RunManager(cfg, syscalls, suppressions)
}

func RunManager(cfg *config.Config, syscalls map[int]bool, suppressions []*regexp.Regexp) {
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
		enabledSyscalls: enabledSyscalls,
		suppressions:    suppressions,
		corpusCover:     make([]cover.Cover, sys.CallCount),
		fuzzers:         make(map[string]*Fuzzer),
		fresh:           true,
	}

	Logf(0, "loading corpus...")
	mgr.persistentCorpus = newPersistentSet(filepath.Join(cfg.Workdir, "corpus"), func(data []byte) bool {
		mgr.fresh = false
		if _, err := prog.Deserialize(data); err != nil {
			Logf(0, "deleting broken program: %v\n%s", err, data)
			return false
		}
		return true
	})
	for _, data := range mgr.persistentCorpus.a {
		p, err := prog.Deserialize(data)
		if err != nil {
			Fatalf("failed to deserialize program: %v", err)
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
			sig := hash.Hash(data)
			mgr.disabledHashes = append(mgr.disabledHashes, sig.String())
			continue
		}
		mgr.candidates = append(mgr.candidates, data)
	}
	Logf(0, "loaded %v programs", len(mgr.persistentCorpus.m))

	// Create HTTP server.
	mgr.initHttp()

	// Create RPC server for fuzzers.
	ln, err := net.Listen("tcp", cfg.Rpc)
	if err != nil {
		Fatalf("failed to listen on %v: %v", cfg.Rpc, err)
	}
	Logf(0, "serving rpc on tcp://%v", ln.Addr())
	mgr.port = ln.Addr().(*net.TCPAddr).Port
	s := rpc.NewServer()
	s.Register(mgr)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				Logf(0, "failed to accept an rpc connection: %v", err)
				continue
			}
			conn.(*net.TCPConn).SetKeepAlive(true)
			conn.(*net.TCPConn).SetKeepAlivePeriod(time.Minute)
			go s.ServeCodec(jsonrpc.NewServerCodec(conn))
		}
	}()

	Logf(0, "booting test machines...")
	var shutdown uint32
	var wg sync.WaitGroup
	wg.Add(cfg.Count + 1)
	for i := 0; i < cfg.Count; i++ {
		i := i
		go func() {
			defer wg.Done()
			for {
				vmCfg, err := config.CreateVMConfig(cfg, i)
				if atomic.LoadUint32(&shutdown) != 0 {
					break
				}
				if err != nil {
					Fatalf("failed to create VM config: %v", err)
				}
				crash := mgr.runInstance(vmCfg, i == 0)
				if atomic.LoadUint32(&shutdown) != 0 {
					break
				}
				if crash != nil {
					mgr.saveCrasher(vmCfg.Name, crash)
				}
			}
		}()
	}

	go func() {
		for {
			time.Sleep(10 * time.Second)
			mgr.mu.Lock()
			executed := mgr.stats["exec total"]
			crashes := mgr.stats["crashes"]
			mgr.mu.Unlock()
			Logf(0, "executed programs: %v, crashes: %v", executed, crashes)
		}
	}()

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
		wg.Done()
		DisableLog() // VMs will fail
		atomic.StoreUint32(&mgr.shutdown, 1)
		close(vm.Shutdown)
		Logf(-1, "shutting down...")
		atomic.StoreUint32(&shutdown, 1)
		<-c
		Fatalf("terminating")
	}()
	wg.Wait()
}

func (mgr *Manager) runInstance(vmCfg *vm.Config, first bool) *Crash {
	inst, err := vm.Create(mgr.cfg.Type, vmCfg)
	if err != nil {
		Logf(0, "failed to create instance: %v", err)
		return nil
	}
	defer inst.Close()

	fwdAddr, err := inst.Forward(mgr.port)
	if err != nil {
		Logf(0, "failed to setup port forwarding: %v", err)
		return nil
	}
	fuzzerBin, err := inst.Copy(filepath.Join(mgr.cfg.Syzkaller, "bin", "syz-fuzzer"))
	if err != nil {
		Logf(0, "failed to copy binary: %v", err)
		return nil
	}
	executorBin, err := inst.Copy(filepath.Join(mgr.cfg.Syzkaller, "bin", "syz-executor"))
	if err != nil {
		Logf(0, "failed to copy binary: %v", err)
		return nil
	}

	// Leak detection significantly slows down fuzzing, so detect leaks only on the first instance.
	leak := first && mgr.cfg.Leak
	fuzzerV := 0
	if *flagDebug {
		fuzzerV = 100
	}

	// Run the fuzzer binary.
	cmd := fmt.Sprintf("%v -executor=%v -name=%v -manager=%v -output=%v -procs=%v -leak=%v -cover=%v -sandbox=%v -debug=%v -v=%d",
		fuzzerBin, executorBin, vmCfg.Name, fwdAddr, mgr.cfg.Output, mgr.cfg.Procs, leak, mgr.cfg.Cover, mgr.cfg.Sandbox, *flagDebug, fuzzerV)
	outc, errc, err := inst.Run(time.Hour, nil, cmd)
	if err != nil {
		Logf(0, "failed to run fuzzer: %v", err)
		return nil
	}

	desc, text, output, crashed, timedout := vm.MonitorExecution(outc, errc, mgr.cfg.Type == "local", true)
	if timedout {
		// This is the only "OK" outcome.
		Logf(0, "%v: running long enough, restarting", vmCfg.Name)
		return nil
	}
	if !crashed {
		// syz-fuzzer exited, but it should not.
		desc = "lost connection to test machine"
	}
	return &Crash{desc, text, output}
}

func (mgr *Manager) saveCrasher(vmName string, crash *Crash) {
	if atomic.LoadUint32(&mgr.shutdown) != 0 {
		// qemu crashes with "qemu: terminating on signal 2",
		// which we detect as "lost connection".
		return
	}
	for _, re := range mgr.suppressions {
		if re.Match(crash.output) {
			Logf(1, "%v: suppressing '%v' with '%v'", vmName, crash.desc, re.String())
			mgr.mu.Lock()
			mgr.stats["suppressed"]++
			mgr.mu.Unlock()
			return
		}
	}

	Logf(0, "%v: crash: %v", vmName, crash.desc)
	mgr.mu.Lock()
	mgr.stats["crashes"]++
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
		ioutil.WriteFile(filepath.Join(dir, fmt.Sprintf("report%v", oldestI)), []byte(crash.text), 0660)
	}
}

func (mgr *Manager) minimizeCorpus() {
	if mgr.cfg.Cover && len(mgr.corpus) != 0 {
		// First, sort corpus per call.
		type Call struct {
			inputs []RpcInput
			cov    []cover.Cover
		}
		calls := make(map[string]Call)
		for _, inp := range mgr.corpus {
			c := calls[inp.Call]
			c.inputs = append(c.inputs, inp)
			c.cov = append(c.cov, inp.Cover)
			calls[inp.Call] = c
		}
		// Now minimize and build new corpus.
		var newCorpus []RpcInput
		for _, c := range calls {
			for _, idx := range cover.Minimize(c.cov) {
				newCorpus = append(newCorpus, c.inputs[idx])
			}
		}
		Logf(1, "minimized corpus: %v -> %v", len(mgr.corpus), len(newCorpus))
		mgr.corpus = newCorpus
	}
	var corpus []*prog.Prog
	for _, inp := range mgr.corpus {
		p, err := prog.Deserialize(inp.Prog)
		if err != nil {
			panic(err)
		}
		corpus = append(corpus, p)
	}
	mgr.prios = prog.CalculatePriorities(corpus)

	// Don't minimize persistent corpus until fuzzers have triaged all inputs from it.
	if len(mgr.candidates) == 0 {
		hashes := make(map[string]bool)
		for _, inp := range mgr.corpus {
			sig := hash.Hash(inp.Prog)
			hashes[sig.String()] = true
		}
		for _, h := range mgr.disabledHashes {
			hashes[h] = true
		}
		mgr.persistentCorpus.minimize(hashes)
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
	for _, inp := range mgr.corpus {
		f.inputs = append(f.inputs, inp)
	}
	r.Prios = mgr.prios
	r.EnabledCalls = mgr.enabledSyscalls
	r.NeedCheck = !mgr.vmChecked

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
	Logf(2, "new input from %v for syscall %v", a.Name, a.Call)
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	f := mgr.fuzzers[a.Name]
	if f == nil {
		Fatalf("fuzzer %v is not connected", a.Name)
	}

	call := sys.CallID[a.Call]
	if len(cover.Difference(a.Cover, mgr.corpusCover[call])) == 0 {
		return nil
	}
	mgr.corpusCover[call] = cover.Union(mgr.corpusCover[call], a.Cover)
	mgr.corpus = append(mgr.corpus, a.RpcInput)
	mgr.stats["manager new inputs"]++
	mgr.persistentCorpus.add(a.RpcInput.Prog)
	for _, f1 := range mgr.fuzzers {
		if f1 == f {
			continue
		}
		f1.inputs = append(f1.inputs, a.RpcInput)
	}
	return nil
}

func (mgr *Manager) Poll(a *PollArgs, r *PollRes) error {
	Logf(2, "poll from %v", a.Name)
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	for k, v := range a.Stats {
		mgr.stats[k] += v
	}

	f := mgr.fuzzers[a.Name]
	if f == nil {
		Fatalf("fuzzer %v is not connected", a.Name)
	}

	for i := 0; i < 100 && len(f.inputs) > 0; i++ {
		last := len(f.inputs) - 1
		r.NewInputs = append(r.NewInputs, f.inputs[last])
		f.inputs = f.inputs[:last]
	}
	if len(f.inputs) == 0 {
		f.inputs = nil
	}

	for i := 0; i < 10 && len(mgr.candidates) > 0; i++ {
		last := len(mgr.candidates) - 1
		r.Candidates = append(r.Candidates, mgr.candidates[last])
		mgr.candidates = mgr.candidates[:last]
	}
	if len(mgr.candidates) == 0 {
		mgr.candidates = nil
	}

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
		conn, err := rpc.Dial("tcp", mgr.cfg.Hub_Addr)
		if err != nil {
			Logf(0, "failed to connect to hub at %v: %v", mgr.cfg.Hub_Addr, err)
			return
		}
		mgr.hub = conn
		a := &HubConnectArgs{
			Name:  mgr.cfg.Name,
			Key:   mgr.cfg.Hub_Key,
			Fresh: mgr.fresh,
			Calls: mgr.enabledCalls,
		}
		mgr.hubCorpus = make(map[hash.Sig]bool)
		for _, inp := range mgr.corpus {
			mgr.hubCorpus[hash.Hash(inp.Prog)] = true
			a.Corpus = append(a.Corpus, inp.Prog)
		}
		if err := mgr.hub.Call("Hub.Connect", a, nil); err != nil {
			Logf(0, "Hub.Connect rpc failed: %v", err)
			mgr.hub.Close()
			mgr.hub = nil
			return
		}
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
	r := new(HubSyncRes)
	if err := mgr.hub.Call("Hub.Sync", a, r); err != nil {
		Logf(0, "Hub.Sync rpc failed: %v", err)
		mgr.hub.Close()
		mgr.hub = nil
		return
	}
	dropped := 0
	for _, inp := range r.Inputs {
		_, err := prog.Deserialize(inp)
		if err != nil {
			dropped++
			continue
		}
		mgr.candidates = append(mgr.candidates, inp)
	}
	mgr.stats["hub add"] += uint64(len(a.Add))
	mgr.stats["hub del"] += uint64(len(a.Del))
	mgr.stats["hub drop"] += uint64(dropped)
	mgr.stats["hub new"] += uint64(len(r.Inputs) - dropped)
	Logf(0, "hub sync: add %v, del %v, drop %v, new %v", len(a.Add), len(a.Del), dropped, len(r.Inputs)-dropped)
}
