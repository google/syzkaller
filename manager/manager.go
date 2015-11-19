// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"crypto/sha1"
	"fmt"
	"net"
	"net/rpc"
	"sync"
	"time"

	"github.com/google/syzkaller/cover"
	"github.com/google/syzkaller/prog"
	. "github.com/google/syzkaller/rpctype"
	"github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/vm"
)

type Sig [sha1.Size]byte

func hash(data []byte) Sig {
	return Sig(sha1.Sum(data))
}

type Manager struct {
	cfg        *Config
	master     *rpc.Client
	masterHttp string
	instances  []vm.Instance
	startTime  time.Time
	stats      map[string]uint64

	mu           sync.Mutex
	masterCorpus [][]byte         // mirror of master corpus
	masterHashes map[Sig]struct{} // hashes of master corpus
	candidates   [][]byte         // new untriaged inputs from master
	syscalls     map[int]bool

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
	// Connect to master.
	master, err := rpc.Dial("tcp", cfg.Master)
	if err != nil {
		fatalf("failed to dial mastger: %v", err)
	}
	a := &MasterConnectArgs{cfg.Name, cfg.Http}
	r := &MasterConnectRes{}
	if err := master.Call("Master.Connect", a, r); err != nil {
		fatalf("failed to connect to master: %v", err)
	}
	logf(0, "connected to master at %v", cfg.Master)

	mgr := &Manager{
		cfg:          cfg,
		master:       master,
		masterHttp:   r.Http,
		startTime:    time.Now(),
		stats:        make(map[string]uint64),
		instances:    instances,
		masterHashes: make(map[Sig]struct{}),
		syscalls:     syscalls,
		corpusCover:  make([]cover.Cover, sys.CallCount),
		fuzzers:      make(map[string]*Fuzzer),
	}

	// Create HTTP server.
	mgr.initHttp()

	// Create RPC server for fuzzers.
	rpcAddr := fmt.Sprintf("localhost:%v", cfg.Port)
	ln, err := net.Listen("tcp", rpcAddr)
	if err != nil {
		fatalf("failed to listen on port %v: %v", cfg.Port, err)
	}
	s := rpc.NewServer()
	s.Register(mgr)
	go s.Accept(ln)
	logf(0, "serving rpc on tcp://%v", rpcAddr)

	mgr.run()
}

func (mgr *Manager) run() {
	mgr.pollMaster()
	for _, inst := range mgr.instances {
		go inst.Run()
	}
	pollTicker := time.NewTicker(10 * time.Second).C
	for {
		select {
		case <-pollTicker:
			mgr.mu.Lock()
			mgr.pollMaster()
			mgr.mu.Unlock()
		}
	}
}

func (mgr *Manager) pollMaster() {
	for {
		a := &MasterPollArgs{mgr.cfg.Name}
		r := &MasterPollRes{}
		if err := mgr.master.Call("Master.PollInputs", a, r); err != nil {
			fatalf("failed to poll master: %v", err)
		}
		logf(3, "polling master, got %v inputs", len(r.Inputs))
		if len(r.Inputs) == 0 {
			break
		}
	nextProg:
		for _, prg := range r.Inputs {
			p, err := prog.Deserialize(prg)
			if err != nil {
				logf(0, "failed to deserialize master program: %v", err)
				continue
			}
			if mgr.syscalls != nil {
				for _, c := range p.Calls {
					if !mgr.syscalls[c.Meta.ID] {
						continue nextProg
					}
				}
			}
			sig := hash(prg)
			if _, ok := mgr.masterHashes[sig]; ok {
				continue
			}
			mgr.masterHashes[sig] = struct{}{}
			mgr.masterCorpus = append(mgr.masterCorpus, prg)
			mgr.candidates = append(mgr.candidates, prg)
		}
	}
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
}

func (mgr *Manager) Connect(a *ManagerConnectArgs, r *ManagerConnectRes) error {
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

func (mgr *Manager) NewInput(a *NewManagerInputArgs, r *int) error {
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

	sig := hash(a.Prog)
	if _, ok := mgr.masterHashes[sig]; !ok {
		mgr.masterHashes[sig] = struct{}{}
		mgr.masterCorpus = append(mgr.masterCorpus, a.Prog)

		a1 := &NewMasterInputArgs{mgr.cfg.Name, a.Prog}
		if err := mgr.master.Call("Master.NewInput", a1, nil); err != nil {
			fatalf("call Master.NewInput failed: %v", err)
		}
	}

	return nil
}

func (mgr *Manager) Poll(a *ManagerPollArgs, r *ManagerPollRes) error {
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
