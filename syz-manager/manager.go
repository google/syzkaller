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
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/google/syzkaller/config"
	"github.com/google/syzkaller/cover"
	"github.com/google/syzkaller/prog"
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
	stats            map[string]uint64

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
	os.MkdirAll(crashdir, 0700)

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
	ln, err := net.Listen("tcp", "localhost:0")
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

	for i := 0; i < cfg.Count; i++ {
		first := i == 0
		go func() {
			for {
				vmCfg, err := config.CreateVMConfig(cfg)
				if err != nil {
					fatalf("failed to create VM config: %v", err)
				}
				if !mgr.runInstance(vmCfg, first) {
					time.Sleep(10 * time.Second)
				}
			}
		}()
	}
	select {}
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

	// TODO: this should be present in the image.
	_, errc, err := inst.Run(10*time.Second, "echo -n 0 > /proc/sys/debug/exception-trace")
	if err == nil {
		<-errc
	}

	// Run the fuzzer binary.
	cover := ""
	if mgr.cfg.NoCover {
		cover = "-nocover=1"
	}
	dropprivs := ""
	if mgr.cfg.NoDropPrivs {
		dropprivs = "-dropprivs=0"
	}
	// Leak detection significantly slows down fuzzing, so detect leaks only on the first instance.
	leak := first && mgr.cfg.Leak

	outputC, errorC, err := inst.Run(time.Hour, fmt.Sprintf("%v -executor %v -name %v -manager %v -output=%v -procs %v -leak=%v %v %v",
		fuzzerBin, executorBin, vmCfg.Name, fwdAddr, mgr.cfg.Output, mgr.cfg.Procs, leak, cover, dropprivs))
	if err != nil {
		logf(0, "failed to run fuzzer: %v", err)
		return false
	}
	var output []byte
	matchPos := 0
	const (
		beforeContext = 256 << 10
		afterContext  = 128 << 10
	)
	lastExecuteTime := time.Now()
	ticker := time.NewTimer(time.Minute)
	for {
		if !ticker.Reset(time.Minute) {
			<-ticker.C
		}
		select {
		case err := <-errorC:
			switch err {
			case vm.TimeoutErr:
				logf(0, "%v: running long enough, restarting", vmCfg.Name)
				return true
			default:
				logf(0, "%v: lost connection: %v", vmCfg.Name, err)
				mgr.saveCrasher(vmCfg.Name, "lost connection", output)
				return true
			}
		case out := <-outputC:
			output = append(output, out...)
			if bytes.Index(output[matchPos:], []byte("executing program")) != -1 {
				lastExecuteTime = time.Now()
			}
			if _, _, _, found := vm.FindCrash(output[matchPos:]); found {
				// Give it some time to finish writing the error message.
				timer := time.NewTimer(10 * time.Second).C
			loop:
				for {
					select {
					case out = <-outputC:
						output = append(output, out...)
					case <-timer:
						break loop
					}
				}
				desc, start, end, _ := vm.FindCrash(output[matchPos:])
				start = start + matchPos - beforeContext
				if start < 0 {
					start = 0
				}
				end = end + matchPos + afterContext
				if end > len(output) {
					end = len(output)
				}
				mgr.saveCrasher(vmCfg.Name, desc, output[start:end])
			}
			if len(output) > 2*beforeContext {
				copy(output, output[len(output)-beforeContext:])
				output = output[:beforeContext]
			}
			matchPos = len(output) - 128
			if matchPos < 0 {
				matchPos = 0
			}
			// In some cases kernel constantly prints something to console,
			// but fuzzer is not actually executing programs.
			if time.Since(lastExecuteTime) > 3*time.Minute {
				mgr.saveCrasher(vmCfg.Name, "not executing programs", output)
				return true
			}
		case <-ticker.C:
			mgr.saveCrasher(vmCfg.Name, "no output", output)
			return true
		}
	}
}

func (mgr *Manager) saveCrasher(name, what string, output []byte) {
	for _, re := range mgr.suppressions {
		if re.Match(output) {
			logf(1, "%v: suppressing '%v' with '%v'", name, what, re.String())
			return
		}
	}
	output = append(output, '\n')
	output = append(output, what...)
	output = append(output, '\n')
	filename := fmt.Sprintf("crash-%v-%v", name, time.Now().UnixNano())
	logf(0, "%v: saving crash '%v' to %v", name, what, filename)
	ioutil.WriteFile(filepath.Join(mgr.crashdir, filename), output, 0660)
}

func (mgr *Manager) minimizeCorpus() {
	if !mgr.cfg.NoCover && len(mgr.corpus) != 0 {
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
