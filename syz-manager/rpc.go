// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
)

type RPCServer struct {
	mgr                   RPCManagerView
	cfg                   *mgrconfig.Config
	modules               []host.KernelModule
	port                  int
	targetEnabledSyscalls map[*prog.Syscall]bool
	coverFilter           map[uint32]uint32
	stats                 *Stats
	batchSize             int
	canonicalModules      *cover.Canonicalizer

	mu          sync.Mutex
	fuzzers     map[string]*Fuzzer
	checkResult *rpctype.CheckArgs

	// TODO: we don't really need these anymore, but there's not much sense
	// in rewriting the code that uses them -- most of that code will be dropped
	// once we move pkg/fuzzer to the host.
	maxSignal     signal.Signal
	corpusSignal  signal.Signal
	corpusCover   cover.Cover
	rnd           *rand.Rand
	checkFailures int
}

type Fuzzer struct {
	name         string
	inputs       []rpctype.Input
	newMaxSignal signal.Signal
	machineInfo  []byte
	instModules  *cover.CanonicalizerInstance
}

type BugFrames struct {
	memoryLeaks []string
	dataRaces   []string
}

// RPCManagerView restricts interface between RPCServer and Manager.
type RPCManagerView interface {
	fuzzerConnect([]host.KernelModule) (
		[]rpctype.Input, BugFrames, map[uint32]uint32, map[uint32]uint32, error)
	machineChecked(result *rpctype.CheckArgs, enabledSyscalls map[*prog.Syscall]bool)
	newInput(inp corpus.NewInput) bool
	candidateBatch(size int) []rpctype.Candidate
}

func startRPCServer(mgr *Manager) (*RPCServer, error) {
	serv := &RPCServer{
		mgr:     mgr,
		cfg:     mgr.cfg,
		stats:   mgr.stats,
		fuzzers: make(map[string]*Fuzzer),
		rnd:     rand.New(rand.NewSource(time.Now().UnixNano())),
	}
	serv.batchSize = 5
	if serv.batchSize < mgr.cfg.Procs {
		serv.batchSize = mgr.cfg.Procs
	}
	s, err := rpctype.NewRPCServer(mgr.cfg.RPC, "Manager", serv)
	if err != nil {
		return nil, err
	}
	log.Logf(0, "serving rpc on tcp://%v", s.Addr())
	serv.port = s.Addr().(*net.TCPAddr).Port
	go s.Serve()
	go func() {
		for {
			time.Sleep(time.Second)
			mgr.stats.rpcTraffic.add(int(s.TotalBytes.Swap(0)))
		}
	}()
	return serv, nil
}

func (serv *RPCServer) Connect(a *rpctype.ConnectArgs, r *rpctype.ConnectRes) error {
	log.Logf(1, "fuzzer %v connected", a.Name)
	serv.stats.vmRestarts.inc()

	if serv.canonicalModules == nil {
		serv.canonicalModules = cover.NewCanonicalizer(a.Modules, serv.cfg.Cover)
		serv.modules = a.Modules
	}
	corpus, bugFrames, coverFilter, execCoverFilter, err := serv.mgr.fuzzerConnect(serv.modules)
	if err != nil {
		return err
	}
	serv.coverFilter = coverFilter

	serv.mu.Lock()
	defer serv.mu.Unlock()

	f := &Fuzzer{
		name:        a.Name,
		machineInfo: a.MachineInfo,
		instModules: serv.canonicalModules.NewInstance(a.Modules),
	}
	serv.fuzzers[a.Name] = f
	r.MemoryLeakFrames = bugFrames.memoryLeaks
	r.DataRaceFrames = bugFrames.dataRaces

	instCoverFilter := f.instModules.DecanonicalizeFilter(execCoverFilter)
	r.CoverFilterBitmap = createCoverageBitmap(serv.cfg.SysTarget, instCoverFilter)
	r.EnabledCalls = serv.cfg.Syscalls
	r.NoMutateCalls = serv.cfg.NoMutateCalls
	r.GitRevision = prog.GitRevision
	r.TargetRevision = serv.cfg.Target.Revision
	r.CheckResult = serv.checkResult
	f.inputs = corpus
	f.newMaxSignal = serv.maxSignal.Copy()
	return nil
}

func (serv *RPCServer) Check(a *rpctype.CheckArgs, r *int) error {
	serv.mu.Lock()
	defer serv.mu.Unlock()

	if serv.checkResult != nil {
		return nil // another VM has already made the check
	}
	// Note: need to print disbled syscalls before failing due to an error.
	// This helps to debug "all system calls are disabled".
	if len(serv.cfg.EnabledSyscalls) != 0 && len(a.DisabledCalls[serv.cfg.Sandbox]) != 0 {
		disabled := make(map[string]string)
		for _, dc := range a.DisabledCalls[serv.cfg.Sandbox] {
			disabled[serv.cfg.Target.Syscalls[dc.ID].Name] = dc.Reason
		}
		for _, id := range serv.cfg.Syscalls {
			name := serv.cfg.Target.Syscalls[id].Name
			if reason := disabled[name]; reason != "" {
				log.Logf(0, "disabling %v: %v", name, reason)
			}
		}
	}
	if a.Error != "" {
		log.Logf(0, "machine check failed: %v", a.Error)
		serv.checkFailures++
		if serv.checkFailures == 10 {
			log.Fatalf("machine check failing")
		}
		return fmt.Errorf("machine check failed: %v", a.Error)
	}
	serv.targetEnabledSyscalls = make(map[*prog.Syscall]bool)
	for _, call := range a.EnabledCalls[serv.cfg.Sandbox] {
		serv.targetEnabledSyscalls[serv.cfg.Target.Syscalls[call]] = true
	}
	log.Logf(0, "machine check:")
	log.Logf(0, "%-24v: %v/%v", "syscalls", len(serv.targetEnabledSyscalls), len(serv.cfg.Target.Syscalls))
	for _, feat := range a.Features.Supported() {
		log.Logf(0, "%-24v: %v", feat.Name, feat.Reason)
	}
	serv.mgr.machineChecked(a, serv.targetEnabledSyscalls)
	a.DisabledCalls = nil
	serv.checkResult = a
	return nil
}

func (serv *RPCServer) NewInput(a *rpctype.NewInputArgs, r *int) error {
	p, disabled, bad := parseProgram(serv.cfg.Target, serv.targetEnabledSyscalls, a.Input.Prog)
	if bad != nil || disabled {
		log.Errorf("rejecting program from fuzzer (bad=%v, disabled=%v):\n%s", bad, disabled, a.Input.Prog)
		return nil
	}
	serv.mu.Lock()
	defer serv.mu.Unlock()

	f := serv.fuzzers[a.Name]
	// Note: f may be nil if we called shutdownInstance,
	// but this request is already in-flight.
	if f != nil {
		a.Cover, a.Signal = f.instModules.Canonicalize(a.Cover, a.Signal)
	}
	inputSignal := a.Signal.Deserialize()

	inp := corpus.NewInput{
		Prog:   p,
		Call:   a.Call,
		Signal: inputSignal,
		Cover:  a.Cover,
	}

	log.Logf(4, "new input from %v for syscall %v (signal=%v, cover=%v)",
		a.Name, inp.StringCall(), inputSignal.Len(), len(a.Cover))
	if serv.corpusSignal.Diff(inputSignal).Empty() {
		return nil
	}
	if !serv.mgr.newInput(inp) {
		return nil
	}

	diff := serv.corpusCover.MergeDiff(a.Cover)
	serv.stats.corpusCover.set(len(serv.corpusCover))
	if len(diff) != 0 && serv.coverFilter != nil {
		// Note: ReportGenerator is already initialized if coverFilter is enabled.
		rg, err := getReportGenerator(serv.cfg, serv.modules)
		if err != nil {
			return err
		}
		filtered := 0
		for _, pc := range diff {
			if serv.coverFilter[uint32(rg.RestorePC(pc))] != 0 {
				filtered++
			}
		}
		serv.stats.corpusCoverFiltered.add(filtered)
	}
	serv.stats.newInputs.inc()

	serv.corpusSignal.Merge(inputSignal)
	serv.stats.corpusSignal.set(serv.corpusSignal.Len())

	a.Input.Cover = nil // Don't send coverage back to all fuzzers.
	a.Input.RawCover = nil
	for _, other := range serv.fuzzers {
		if other == f {
			continue
		}
		other.inputs = append(other.inputs, a.Input)
	}
	return nil
}

func (serv *RPCServer) Poll(a *rpctype.PollArgs, r *rpctype.PollRes) error {
	serv.stats.mergeNamed(a.Stats)

	serv.mu.Lock()
	defer serv.mu.Unlock()

	f := serv.fuzzers[a.Name]
	if f == nil {
		// This is possible if we called shutdownInstance,
		// but already have a pending request from this instance in-flight.
		log.Logf(1, "poll: fuzzer %v is not connected", a.Name)
		return nil
	}
	newMaxSignal := serv.maxSignal.Diff(a.MaxSignal.Deserialize())
	if !newMaxSignal.Empty() {
		serv.maxSignal.Merge(newMaxSignal)
		serv.stats.maxSignal.set(len(serv.maxSignal))
		for _, f1 := range serv.fuzzers {
			if f1 == f {
				continue
			}
			f1.newMaxSignal.Merge(newMaxSignal)
		}
	}
	r.MaxSignal = f.newMaxSignal.Split(2000).Serialize()
	if a.NeedCandidates {
		r.Candidates = serv.mgr.candidateBatch(serv.batchSize)
	}
	if len(r.Candidates) == 0 {
		batchSize := serv.batchSize
		// When the fuzzer starts, it pumps the whole corpus.
		// If we do it using the final batchSize, it can be very slow
		// (batch of size 6 can take more than 10 mins for 50K corpus and slow kernel).
		// So use a larger batch initially (we use no stats as approximation of initial pump).
		const initialBatch = 50
		if len(a.Stats) == 0 && batchSize < initialBatch {
			batchSize = initialBatch
		}
		for i := 0; i < batchSize && len(f.inputs) > 0; i++ {
			last := len(f.inputs) - 1
			r.NewInputs = append(r.NewInputs, f.inputs[last])
			f.inputs[last] = rpctype.Input{}
			f.inputs = f.inputs[:last]
		}
		if len(f.inputs) == 0 {
			f.inputs = nil
		}
	}
	for _, inp := range r.NewInputs {
		inp.Cover, inp.Signal = f.instModules.Decanonicalize(inp.Cover, inp.Signal)
	}
	log.Logf(4, "poll from %v: candidates=%v inputs=%v maxsignal=%v",
		a.Name, len(r.Candidates), len(r.NewInputs), len(r.MaxSignal.Elems))
	return nil
}

func (serv *RPCServer) shutdownInstance(name string) []byte {
	serv.mu.Lock()
	defer serv.mu.Unlock()

	fuzzer := serv.fuzzers[name]
	if fuzzer == nil {
		return nil
	}
	delete(serv.fuzzers, name)
	return fuzzer.machineInfo
}

func (serv *RPCServer) LogMessage(m *rpctype.LogMessageReq, r *int) error {
	log.Logf(m.Level, "%s: %s", m.Name, m.Message)
	return nil
}
