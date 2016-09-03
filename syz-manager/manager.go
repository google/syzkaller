// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
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
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/report"
	. "github.com/google/syzkaller/rpctype"
	"github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/vm"
	_ "github.com/google/syzkaller/vm/adb"
	_ "github.com/google/syzkaller/vm/kvm"
	_ "github.com/google/syzkaller/vm/local"
	_ "github.com/google/syzkaller/vm/qemu"
)

var (
	flagConfig = flag.String("config", "", "configuration file")
	flagV      = flag.Int("v", 0, "verbosity")
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

	mu              sync.Mutex
	enabledSyscalls string
	suppressions    []*regexp.Regexp

	candidates     [][]byte // untriaged inputs
	disabledHashes []string
	corpus         []RpcInput
	corpusCover    []cover.Cover
	prios          [][]float32

	fuzzers map[string]*Fuzzer
}

type Fuzzer struct {
	name  string
	input int
}

func main() {
	flag.Parse()
	cfg, syscalls, suppressions, err := config.Parse(*flagConfig)
	if err != nil {
		fatalf("%v", err)
	}
	if *flagDebug {
		cfg.Debug = true
		cfg.Count = 1
	}
	RunManager(cfg, syscalls, suppressions)
}

func RunManager(cfg *config.Config, syscalls map[int]bool, suppressions []*regexp.Regexp) {
	crashdir := filepath.Join(cfg.Workdir, "crashes")

	enabledSyscalls := ""
	if len(syscalls) != 0 {
		buf := new(bytes.Buffer)
		for c := range syscalls {
			fmt.Fprintf(buf, ",%v", c)
		}
		enabledSyscalls = buf.String()[1:]
		logf(1, "enabled syscalls: %v", enabledSyscalls)
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
	}

	logf(0, "loading corpus...")
	mgr.persistentCorpus = newPersistentSet(filepath.Join(cfg.Workdir, "corpus"), func(data []byte) bool {
		if _, err := prog.Deserialize(data); err != nil {
			logf(0, "deleting broken program: %v\n%s", err, data)
			return false
		}
		return true
	})
	for _, data := range mgr.persistentCorpus.a {
		p, err := prog.Deserialize(data)
		if err != nil {
			fatalf("failed to deserialize program: %v", err)
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
			h := hash(data)
			mgr.disabledHashes = append(mgr.disabledHashes, hex.EncodeToString(h[:]))
			continue
		}
		mgr.candidates = append(mgr.candidates, data)
	}
	logf(0, "loaded %v programs", len(mgr.persistentCorpus.m))

	// Create HTTP server.
	mgr.initHttp()

	// Create RPC server for fuzzers.
	ln, err := net.Listen("tcp", cfg.Rpc)
	if err != nil {
		fatalf("failed to listen on localhost:0: %v", err)
	}
	logf(0, "serving rpc on tcp://%v", ln.Addr())
	mgr.port = ln.Addr().(*net.TCPAddr).Port
	s := rpc.NewServer()
	s.Register(mgr)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				logf(0, "failed to accept an rpc connection: %v", err)
				continue
			}
			go s.ServeCodec(jsonrpc.NewServerCodec(conn))
		}
	}()

	logf(0, "booting test machines...")
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
					fatalf("failed to create VM config: %v", err)
				}
				ok := mgr.runInstance(vmCfg, i == 0)
				if atomic.LoadUint32(&shutdown) != 0 {
					break
				}
				if !ok {
					time.Sleep(10 * time.Second)
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
			logf(0, "executed programs: %v, crashes: %v", executed, crashes)
		}
	}()

	go func() {
		c := make(chan os.Signal, 2)
		signal.Notify(c, syscall.SIGINT)
		<-c
		wg.Done()
		atomic.StoreUint32(&mgr.shutdown, 1)
		*flagV = -1 // VMs will fail
		logf(-1, "shutting down...")
		atomic.StoreUint32(&shutdown, 1)
		<-c
		log.Fatalf("terminating")
	}()
	wg.Wait()
}

func (mgr *Manager) runInstance(vmCfg *vm.Config, first bool) bool {
	inst, err := vm.Create(mgr.cfg.Type, vmCfg)
	if err != nil {
		logf(0, "failed to create instance: %v", err)
		return false
	}
	defer inst.Close()

	fwdAddr, err := inst.Forward(mgr.port)
	if err != nil {
		logf(0, "failed to setup port forwarding: %v", err)
		return false
	}
	fuzzerBin, err := inst.Copy(filepath.Join(mgr.cfg.Syzkaller, "bin", "syz-fuzzer"))
	if err != nil {
		logf(0, "failed to copy binary: %v", err)
		return false
	}
	executorBin, err := inst.Copy(filepath.Join(mgr.cfg.Syzkaller, "bin", "syz-executor"))
	if err != nil {
		logf(0, "failed to copy binary: %v", err)
		return false
	}

	// Run an aux command with best effort.
	runCommand := func(cmd string) {
		_, errc, err := inst.Run(10*time.Second, cmd)
		if err == nil {
			<-errc
		}
	}
	runCommand("echo -n 0 > /proc/sys/debug/exception-trace")

	// Leak detection significantly slows down fuzzing, so detect leaks only on the first instance.
	leak := first && mgr.cfg.Leak

	// Run the fuzzer binary.
	outc, errc, err := inst.Run(time.Hour, fmt.Sprintf(
		"%v -executor=%v -name=%v -manager=%v -output=%v -procs=%v -leak=%v -cover=%v -sandbox=%v -debug=%v -v=%d",
		fuzzerBin, executorBin, vmCfg.Name, fwdAddr, mgr.cfg.Output, mgr.cfg.Procs, leak, mgr.cfg.Cover, mgr.cfg.Sandbox, *flagDebug, *flagV))
	if err != nil {
		logf(0, "failed to run fuzzer: %v", err)
		return false
	}

	desc, text, output, crashed, timedout := vm.MonitorExecution(outc, errc, mgr.cfg.Type != "local", true)
	if timedout {
		// This is the only "OK" outcome.
		logf(0, "%v: running long enough, restarting", vmCfg.Name)
	} else {
		if !crashed {
			// syz-fuzzer exited, but it should not.
			desc = "lost connection to test machine"
		}
		mgr.saveCrasher(vmCfg, desc, text, output)
	}
	return true
}

func (mgr *Manager) saveCrasher(vmCfg *vm.Config, desc string, text, output []byte) {
	if atomic.LoadUint32(&mgr.shutdown) != 0 {
		// qemu crashes with "qemu: terminating on signal 2",
		// which we detect as "lost connection".
		return
	}
	for _, re := range mgr.suppressions {
		if re.Match(output) {
			logf(1, "%v: suppressing '%v' with '%v'", vmCfg.Name, desc, re.String())
			mgr.mu.Lock()
			mgr.stats["suppressed"]++
			mgr.mu.Unlock()
			return
		}
	}

	logf(0, "%v: crash: %v", vmCfg.Name, desc)
	mgr.mu.Lock()
	mgr.stats["crashes"]++
	mgr.mu.Unlock()

	h := hash([]byte(desc))
	id := hex.EncodeToString(h[:])
	dir := filepath.Join(mgr.crashdir, id)
	os.MkdirAll(dir, 0700)
	if err := ioutil.WriteFile(filepath.Join(dir, "description"), []byte(desc+"\n"), 0660); err != nil {
		logf(0, "failed to write crash: %v", err)
	}
	const maxReports = 100 // save up to 100 reports
	if matches, _ := filepath.Glob(filepath.Join(dir, "log*")); len(matches) >= maxReports {
		return
	}
	for i := 0; i < maxReports; i++ {
		fn := filepath.Join(dir, fmt.Sprintf("log%v", i))
		if _, err := os.Stat(fn); err == nil {
			continue
		}
		if err := ioutil.WriteFile(fn, output, 0660); err != nil {
			continue
		}
		if len(text) > 0 {
			symbolized, err := report.Symbolize(mgr.cfg.Vmlinux, text)
			if err != nil {
				logf(0, "failed to symbolize crash: %v", err)
			} else {
				text = symbolized
			}
			ioutil.WriteFile(filepath.Join(dir, fmt.Sprintf("report%v", i)), []byte(text), 0660)
		}
		break
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
		logf(1, "minimized corpus: %v -> %v", len(mgr.corpus), len(newCorpus))
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
			h := hash(inp.Prog)
			hashes[hex.EncodeToString(h[:])] = true
		}
		for _, h := range mgr.disabledHashes {
			hashes[h] = true
		}
		mgr.persistentCorpus.minimize(hashes)
	}
}

func (mgr *Manager) Connect(a *ConnectArgs, r *ConnectRes) error {
	logf(1, "fuzzer %v connected", a.Name)
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	if mgr.firstConnect.IsZero() {
		mgr.firstConnect = time.Now()
	}

	mgr.stats["vm restarts"]++
	mgr.minimizeCorpus()
	mgr.fuzzers[a.Name] = &Fuzzer{
		name:  a.Name,
		input: 0,
	}
	r.Prios = mgr.prios
	r.EnabledCalls = mgr.enabledSyscalls

	return nil
}

func (mgr *Manager) NewInput(a *NewInputArgs, r *int) error {
	logf(2, "new input from %v for syscall %v", a.Name, a.Call)
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	call := sys.CallID[a.Call]
	if len(cover.Difference(a.Cover, mgr.corpusCover[call])) == 0 {
		return nil
	}
	mgr.corpusCover[call] = cover.Union(mgr.corpusCover[call], a.Cover)
	mgr.corpus = append(mgr.corpus, a.RpcInput)
	mgr.stats["manager new inputs"]++
	mgr.persistentCorpus.add(a.RpcInput.Prog)
	return nil
}

func (mgr *Manager) Poll(a *PollArgs, r *PollRes) error {
	logf(2, "poll from %v", a.Name)
	mgr.mu.Lock()
	defer mgr.mu.Unlock()

	for k, v := range a.Stats {
		mgr.stats[k] += v
	}

	f := mgr.fuzzers[a.Name]
	if f == nil {
		fatalf("fuzzer %v is not connected", a.Name)
	}

	for i := 0; i < 100 && f.input < len(mgr.corpus); i++ {
		r.NewInputs = append(r.NewInputs, mgr.corpus[f.input])
		f.input++
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

func logf(v int, msg string, args ...interface{}) {
	if *flagV >= v {
		log.Printf(msg, args...)
	}
}

func fatalf(msg string, args ...interface{}) {
	log.Fatalf(msg, args...)
}
