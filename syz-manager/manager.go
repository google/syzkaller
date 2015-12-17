// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"net"
	"net/rpc"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/syzkaller/cover"
	"github.com/google/syzkaller/prog"
	. "github.com/google/syzkaller/rpctype"
	"github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/vm"
)

type Manager struct {
	cfg              *Config
	persistentCorpus *PersistentSet
	instances        []vm.Instance
	startTime        time.Time
	stats            map[string]uint64

	mu       sync.Mutex
	syscalls map[int]bool

	candidates  [][]byte // untriaged inputs
	corpus      []RpcInput
	corpusCover []cover.Cover
	prios       [][]float32

	fuzzers map[string]*Fuzzer
}

type Fuzzer struct {
	name  string
	input int
}

func RunManager(cfg *Config, syscalls map[int]bool, instances []vm.Instance) {
	mgr := &Manager{
		cfg:         cfg,
		startTime:   time.Now(),
		stats:       make(map[string]uint64),
		instances:   instances,
		syscalls:    syscalls,
		corpusCover: make([]cover.Cover, sys.CallCount),
		fuzzers:     make(map[string]*Fuzzer),
	}

	logf(0, "loading corpus...")
	mgr.persistentCorpus = newPersistentSet(filepath.Join(cfg.Workdir, "corpus"), func(data []byte) bool {
		if _, err := prog.Deserialize(data); err != nil {
			logf(0, "deleting broken program: %v\n%s", err, data)
			return false
		}
		return true
	})
	for _, prog := range mgr.persistentCorpus.a {
		mgr.candidates = append(mgr.candidates, prog)
	}
	logf(0, "loaded %v programs", len(mgr.persistentCorpus.m))

	// Create HTTP server.
	mgr.initHttp()

	// Create RPC server for fuzzers.
	rpcAddr := fmt.Sprintf("localhost:%v", cfg.Port)
	ln, err := net.Listen("tcp", rpcAddr)
	if err != nil {
		fatalf("failed to listen on port %v: %v", cfg.Port, err)
	}
	logf(0, "serving rpc on tcp://%v", rpcAddr)
	s := rpc.NewServer()
	s.Register(mgr)
	go s.Accept(ln)

	for _, inst := range mgr.instances {
		go inst.Run()
	}
	select {}
}

func (mgr *Manager) minimizeCorpus() {
	if !mgr.cfg.Nocover && len(mgr.corpus) != 0 {
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
			hashes[string(h[:])] = true
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

	return nil
}

func (mgr *Manager) NewInput(a *NewInputArgs, r *int) error {
	logf(2, "new input from fuzzer %v", a.Name)
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

	return nil
}
