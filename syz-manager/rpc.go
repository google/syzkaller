// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"net"
	"sync"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys"
)

type RPCServer struct {
	mgr             RPCManagerView
	target          *prog.Target
	enabledSyscalls []int
	stats           *Stats
	batchSize       int

	mu           sync.Mutex
	fuzzers      map[string]*Fuzzer
	checkResult  *rpctype.CheckArgs
	maxSignal    signal.Signal
	corpusSignal signal.Signal
	corpusCover  cover.Cover
}

type Fuzzer struct {
	name         string
	inputs       []rpctype.RPCInput
	newMaxSignal signal.Signal
}

// RPCManagerView restricts interface between RPCServer and Manager.
type RPCManagerView interface {
	fuzzerConnect() ([]rpctype.RPCInput, [][]byte)
	machineChecked(result *rpctype.CheckArgs)
	newInput(inp rpctype.RPCInput, sign signal.Signal)
	candidateBatch(size int) []rpctype.RPCCandidate
}

func startRPCServer(mgr *Manager) (int, error) {
	serv := &RPCServer{
		mgr:             mgr,
		target:          mgr.target,
		enabledSyscalls: mgr.enabledSyscalls,
		stats:           mgr.stats,
		fuzzers:         make(map[string]*Fuzzer),
	}
	serv.batchSize = 5
	if serv.batchSize < mgr.cfg.Procs {
		serv.batchSize = mgr.cfg.Procs
	}
	s, err := rpctype.NewRPCServer(mgr.cfg.RPC, "Manager", serv)
	if err != nil {
		return 0, err
	}
	log.Logf(0, "serving rpc on tcp://%v", s.Addr())
	port := s.Addr().(*net.TCPAddr).Port
	go s.Serve()
	return port, nil
}

func (serv *RPCServer) Connect(a *rpctype.ConnectArgs, r *rpctype.ConnectRes) error {
	log.Logf(1, "fuzzer %v connected", a.Name)
	serv.stats.vmRestarts.inc()

	corpus, memoryLeakFrames := serv.mgr.fuzzerConnect()

	serv.mu.Lock()
	defer serv.mu.Unlock()

	serv.fuzzers[a.Name] = &Fuzzer{
		name:         a.Name,
		inputs:       corpus,
		newMaxSignal: serv.maxSignal.Copy(),
	}
	r.MemoryLeakFrames = memoryLeakFrames
	r.EnabledCalls = serv.enabledSyscalls
	r.CheckResult = serv.checkResult
	r.GitRevision = sys.GitRevision
	r.TargetRevision = serv.target.Revision
	return nil
}

func (serv *RPCServer) Check(a *rpctype.CheckArgs, r *int) error {
	serv.mu.Lock()
	defer serv.mu.Unlock()

	if serv.checkResult != nil {
		return nil
	}
	serv.mgr.machineChecked(a)
	a.DisabledCalls = nil
	serv.checkResult = a
	return nil
}

func (serv *RPCServer) NewInput(a *rpctype.NewInputArgs, r *int) error {
	inputSignal := a.Signal.Deserialize()
	log.Logf(4, "new input from %v for syscall %v (signal=%v, cover=%v)",
		a.Name, a.Call, inputSignal.Len(), len(a.Cover))
	if _, err := serv.target.Deserialize(a.RPCInput.Prog, prog.NonStrict); err != nil {
		// This should not happen, but we see such cases episodically, reason unknown.
		log.Logf(0, "failed to deserialize program from fuzzer: %v\n%s", err, a.RPCInput.Prog)
		return nil
	}
	serv.mu.Lock()
	defer serv.mu.Unlock()

	if serv.corpusSignal.Diff(inputSignal).Empty() {
		return nil
	}
	serv.mgr.newInput(a.RPCInput, inputSignal)

	serv.stats.newInputs.inc()
	serv.corpusSignal.Merge(inputSignal)
	serv.stats.corpusSignal.set(serv.corpusSignal.Len())
	serv.corpusCover.Merge(a.Cover)
	serv.stats.corpusCover.set(len(serv.corpusCover))

	a.RPCInput.Cover = nil // Don't send coverage back to all fuzzers.
	for _, f := range serv.fuzzers {
		if f.name == a.Name {
			continue
		}
		f.inputs = append(f.inputs, a.RPCInput)
	}
	return nil
}

func (serv *RPCServer) Poll(a *rpctype.PollArgs, r *rpctype.PollRes) error {
	serv.stats.mergeNamed(a.Stats)

	serv.mu.Lock()
	defer serv.mu.Unlock()

	f := serv.fuzzers[a.Name]
	if f == nil {
		log.Fatalf("fuzzer %v is not connected", a.Name)
	}
	newMaxSignal := serv.maxSignal.Diff(a.MaxSignal.Deserialize())
	if !newMaxSignal.Empty() {
		serv.maxSignal.Merge(newMaxSignal)
		for _, f1 := range serv.fuzzers {
			if f1 == f {
				continue
			}
			f1.newMaxSignal.Merge(newMaxSignal)
		}
	}
	r.MaxSignal = f.newMaxSignal.Split(500).Serialize()
	if a.NeedCandidates {
		r.Candidates = serv.mgr.candidateBatch(serv.batchSize)
	}
	if len(r.Candidates) == 0 {
		for i := 0; i < serv.batchSize && len(f.inputs) > 0; i++ {
			last := len(f.inputs) - 1
			r.NewInputs = append(r.NewInputs, f.inputs[last])
			f.inputs[last] = rpctype.RPCInput{}
			f.inputs = f.inputs[:last]
		}
		if len(f.inputs) == 0 {
			f.inputs = nil
		}
	}
	log.Logf(4, "poll from %v: candidates=%v inputs=%v maxsignal=%v",
		a.Name, len(r.Candidates), len(r.NewInputs), len(r.MaxSignal.Elems))
	return nil
}
