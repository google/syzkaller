// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys"
)

type Fuzzer struct {
	name        string
	outputType  OutputType
	config      *ipc.Config
	execOpts    *ipc.ExecOpts
	procs       []*Proc
	gate        *ipc.Gate
	workQueue   *WorkQueue
	needPoll    chan struct{}
	choiceTable *prog.ChoiceTable
	stats       [StatCount]uint64
	manager     *rpctype.RPCClient
	target      *prog.Target

	faultInjectionEnabled    bool
	comparisonTracingEnabled bool
	coverageEnabled          bool
	leakCheckEnabled         bool
	leakCheckReady           uint32

	corpusMu     sync.RWMutex
	corpus       []*prog.Prog
	corpusHashes map[hash.Sig]struct{}

	signalMu     sync.RWMutex
	corpusSignal signal.Signal // signal of inputs in corpus
	maxSignal    signal.Signal // max signal ever observed including flakes
	newSignal    signal.Signal // diff of maxSignal since last sync with master

	logMu sync.Mutex
}

type Stat int

const (
	StatGenerate Stat = iota
	StatFuzz
	StatCandidate
	StatTriage
	StatMinimize
	StatSmash
	StatHint
	StatSeed
	StatCount
)

var statNames = [StatCount]string{
	StatGenerate:  "exec gen",
	StatFuzz:      "exec fuzz",
	StatCandidate: "exec candidate",
	StatTriage:    "exec triage",
	StatMinimize:  "exec minimize",
	StatSmash:     "exec smash",
	StatHint:      "exec hints",
	StatSeed:      "exec seeds",
}

type OutputType int

const (
	OutputNone OutputType = iota
	OutputStdout
	OutputDmesg
	OutputFile
)

func main() {
	debug.SetGCPercent(50)

	var (
		flagName    = flag.String("name", "test", "unique name for manager")
		flagArch    = flag.String("arch", runtime.GOARCH, "target arch")
		flagManager = flag.String("manager", "", "manager rpc address")
		flagProcs   = flag.Int("procs", 1, "number of parallel test processes")
		flagLeak    = flag.Bool("leak", false, "detect memory leaks")
		flagOutput  = flag.String("output", "stdout", "write programs to none/stdout/dmesg/file")
		flagPprof   = flag.String("pprof", "", "address to serve pprof profiles")
		flagTest    = flag.Bool("test", false, "enable image testing mode") // used by syz-ci
	)
	flag.Parse()
	var outputType OutputType
	switch *flagOutput {
	case "none":
		outputType = OutputNone
	case "stdout":
		outputType = OutputStdout
	case "dmesg":
		outputType = OutputDmesg
	case "file":
		outputType = OutputFile
	default:
		fmt.Fprintf(os.Stderr, "-output flag must be one of none/stdout/dmesg/file\n")
		os.Exit(1)
	}
	log.Logf(0, "fuzzer started")

	target, err := prog.GetTarget(runtime.GOOS, *flagArch)
	if err != nil {
		log.Fatalf("%v", err)
	}

	config, execOpts, err := ipc.DefaultConfig()
	if err != nil {
		panic(err)
	}
	sandbox := "none"
	if config.Flags&ipc.FlagSandboxSetuid != 0 {
		sandbox = "setuid"
	} else if config.Flags&ipc.FlagSandboxNamespace != 0 {
		sandbox = "namespace"
	}

	shutdown := make(chan struct{})
	osutil.HandleInterrupts(shutdown)
	go func() {
		// Handles graceful preemption on GCE.
		<-shutdown
		log.Logf(0, "SYZ-FUZZER: PREEMPTED")
		os.Exit(1)
	}()

	if *flagTest {
		testImage(*flagManager, target, sandbox)
		return
	}

	if *flagPprof != "" {
		go func() {
			err := http.ListenAndServe(*flagPprof, nil)
			log.Fatalf("failed to serve pprof profiles: %v", err)
		}()
	} else {
		runtime.MemProfileRate = 0
	}

	log.Logf(0, "dialing manager at %v", *flagManager)
	a := &rpctype.ConnectArgs{Name: *flagName}
	r := &rpctype.ConnectRes{}
	if err := rpctype.RPCCall(*flagManager, "Manager.Connect", a, r); err != nil {
		panic(err)
	}
	calls, disabled := buildCallList(target, r.EnabledCalls, sandbox)
	ct := target.BuildChoiceTable(r.Prios, calls)

	// This requires "fault-inject: support systematic fault injection" kernel commit.
	// TODO(dvykov): also need to check presence of /sys/kernel/debug/failslab/ignore-gfp-wait
	// and /sys/kernel/debug/fail_futex/ignore-private, they can be missing if
	// CONFIG_FAULT_INJECTION_DEBUG_FS is not enabled.
	// Also need to move this somewhere else (to linux-specific part).
	faultInjectionEnabled := false
	if fd, err := syscall.Open("/proc/self/fail-nth", syscall.O_RDWR, 0); err == nil {
		syscall.Close(fd)
		faultInjectionEnabled = true
	}

	if calls[target.SyscallMap["syz_emit_ethernet"]] ||
		calls[target.SyscallMap["syz_extract_tcp_res"]] {
		config.Flags |= ipc.FlagEnableTun
	}
	if faultInjectionEnabled {
		config.Flags |= ipc.FlagEnableFault
	}
	coverageEnabled := config.Flags&ipc.FlagSignal != 0

	kcov, comparisonTracingEnabled := checkCompsSupported()
	log.Logf(0, "kcov=%v, comps=%v", kcov, comparisonTracingEnabled)
	if r.NeedCheck {
		out, err := osutil.RunCmd(time.Minute, "", config.Executor, "version")
		if err != nil {
			panic(err)
		}
		vers := strings.Split(strings.TrimSpace(string(out)), " ")
		if len(vers) != 4 {
			panic(fmt.Sprintf("bad executor version: %q", string(out)))
		}
		a := &rpctype.CheckArgs{
			Name:           *flagName,
			UserNamespaces: osutil.IsExist("/proc/self/ns/user"),
			FuzzerGitRev:   sys.GitRevision,
			FuzzerSyzRev:   target.Revision,
			ExecutorGitRev: vers[3],
			ExecutorSyzRev: vers[2],
			ExecutorArch:   vers[1],
			DisabledCalls:  disabled,
		}
		a.Kcov = kcov
		if fd, err := syscall.Open("/sys/kernel/debug/kmemleak", syscall.O_RDWR, 0); err == nil {
			syscall.Close(fd)
			a.Leak = true
		}
		a.Fault = faultInjectionEnabled
		a.CompsSupported = comparisonTracingEnabled
		for c := range calls {
			a.Calls = append(a.Calls, c.Name)
		}
		if err := rpctype.RPCCall(*flagManager, "Manager.Check", a, nil); err != nil {
			panic(err)
		}
	}

	// Manager.Connect reply can ve very large and that memory will be permanently cached in the connection.
	// So we do the call on a transient connection, free all memory and reconnect.
	// The rest of rpc requests have bounded size.
	debug.FreeOSMemory()
	manager, err := rpctype.NewRPCClient(*flagManager)
	if err != nil {
		panic(err)
	}

	kmemleakInit(*flagLeak)

	needPoll := make(chan struct{}, 1)
	needPoll <- struct{}{}
	fuzzer := &Fuzzer{
		name:                     *flagName,
		outputType:               outputType,
		config:                   config,
		execOpts:                 execOpts,
		workQueue:                newWorkQueue(*flagProcs, needPoll),
		needPoll:                 needPoll,
		choiceTable:              ct,
		manager:                  manager,
		target:                   target,
		faultInjectionEnabled:    faultInjectionEnabled,
		comparisonTracingEnabled: comparisonTracingEnabled,
		coverageEnabled:          coverageEnabled,
		leakCheckEnabled:         *flagLeak,
		corpusHashes:             make(map[hash.Sig]struct{}),
	}
	fuzzer.gate = ipc.NewGate(2**flagProcs, fuzzer.leakCheckCallback)

	for _, inp := range r.Inputs {
		fuzzer.addInputFromAnotherFuzzer(inp)
	}
	fuzzer.addMaxSignal(r.MaxSignal.Deserialize())
	for _, candidate := range r.Candidates {
		p, err := fuzzer.target.Deserialize(candidate.Prog)
		if err != nil {
			panic(err)
		}
		if coverageEnabled {
			flags := ProgCandidate
			if candidate.Minimized {
				flags |= ProgMinimized
			}
			if candidate.Smashed {
				flags |= ProgSmashed
			}
			fuzzer.workQueue.enqueue(&WorkCandidate{
				p:     p,
				flags: flags,
			})
		} else {
			fuzzer.addInputToCorpus(p, nil, hash.Hash(candidate.Prog))
		}
	}

	for pid := 0; pid < *flagProcs; pid++ {
		proc, err := newProc(fuzzer, pid)
		if err != nil {
			log.Fatalf("failed to create proc: %v", err)
		}
		fuzzer.procs = append(fuzzer.procs, proc)
		go proc.loop()
	}

	fuzzer.pollLoop()
}

func (fuzzer *Fuzzer) pollLoop() {
	var execTotal uint64
	var lastPoll time.Time
	var lastPrint time.Time
	ticker := time.NewTicker(3 * time.Second).C
	for {
		poll := false
		select {
		case <-ticker:
		case <-fuzzer.needPoll:
			poll = true
		}
		if fuzzer.outputType != OutputStdout && time.Since(lastPrint) > 10*time.Second {
			// Keep-alive for manager.
			log.Logf(0, "alive, executed %v", execTotal)
			lastPrint = time.Now()
		}
		if poll || time.Since(lastPoll) > 10*time.Second {
			needCandidates := fuzzer.workQueue.wantCandidates()
			if poll && !needCandidates {
				continue
			}

			a := &rpctype.PollArgs{
				Name:           fuzzer.name,
				NeedCandidates: needCandidates,
				Stats:          make(map[string]uint64),
			}
			a.MaxSignal = fuzzer.grabNewSignal().Serialize()
			for _, proc := range fuzzer.procs {
				a.Stats["exec total"] += atomic.SwapUint64(&proc.env.StatExecs, 0)
				a.Stats["executor restarts"] += atomic.SwapUint64(&proc.env.StatRestarts, 0)
			}

			for stat := Stat(0); stat < StatCount; stat++ {
				v := atomic.SwapUint64(&fuzzer.stats[stat], 0)
				a.Stats[statNames[stat]] = v
				execTotal += v
			}

			r := &rpctype.PollRes{}
			if err := fuzzer.manager.Call("Manager.Poll", a, r); err != nil {
				panic(err)
			}
			maxSignal := r.MaxSignal.Deserialize()
			log.Logf(1, "poll: candidates=%v inputs=%v signal=%v",
				len(r.Candidates), len(r.NewInputs), maxSignal.Len())
			fuzzer.addMaxSignal(maxSignal)
			for _, inp := range r.NewInputs {
				fuzzer.addInputFromAnotherFuzzer(inp)
			}
			for _, candidate := range r.Candidates {
				p, err := fuzzer.target.Deserialize(candidate.Prog)
				if err != nil {
					panic(err)
				}
				if fuzzer.coverageEnabled {
					flags := ProgCandidate
					if candidate.Minimized {
						flags |= ProgMinimized
					}
					if candidate.Smashed {
						flags |= ProgSmashed
					}
					fuzzer.workQueue.enqueue(&WorkCandidate{
						p:     p,
						flags: flags,
					})
				} else {
					fuzzer.addInputToCorpus(p, nil, hash.Hash(candidate.Prog))
				}
			}
			if len(r.Candidates) == 0 && fuzzer.leakCheckEnabled &&
				atomic.LoadUint32(&fuzzer.leakCheckReady) == 0 {
				kmemleakScan(false) // ignore boot leaks
				atomic.StoreUint32(&fuzzer.leakCheckReady, 1)
			}
			if len(r.NewInputs) == 0 && len(r.Candidates) == 0 {
				lastPoll = time.Now()
			}
		}
	}
}

func buildCallList(target *prog.Target, enabledCalls []int, sandbox string) (
	map[*prog.Syscall]bool, []rpctype.SyscallReason) {
	calls := make(map[*prog.Syscall]bool)
	for _, n := range enabledCalls {
		if n >= len(target.Syscalls) {
			log.Fatalf("invalid enabled syscall: %v", n)
		}
		calls[target.Syscalls[n]] = true
	}

	var disabled []rpctype.SyscallReason
	_, unsupported, err := host.DetectSupportedSyscalls(target, sandbox)
	if err != nil {
		log.Fatalf("failed to detect host supported syscalls: %v", err)
	}
	for c := range calls {
		if reason, ok := unsupported[c]; ok {
			log.Logf(1, "unsupported syscall: %v: %v", c.Name, reason)
			disabled = append(disabled, rpctype.SyscallReason{
				Name:   c.Name,
				Reason: reason,
			})
			delete(calls, c)
		}
	}
	_, unsupported = target.TransitivelyEnabledCalls(calls)
	for c := range calls {
		if reason, ok := unsupported[c]; ok {
			log.Logf(1, "transitively unsupported: %v: %v", c.Name, reason)
			disabled = append(disabled, rpctype.SyscallReason{
				Name:   c.Name,
				Reason: reason,
			})
			delete(calls, c)
		}
	}
	return calls, disabled
}

func (fuzzer *Fuzzer) sendInputToManager(inp rpctype.RPCInput) {
	a := &rpctype.NewInputArgs{
		Name:     fuzzer.name,
		RPCInput: inp,
	}
	if err := fuzzer.manager.Call("Manager.NewInput", a, nil); err != nil {
		panic(err)
	}
}

func (fuzzer *Fuzzer) addInputFromAnotherFuzzer(inp rpctype.RPCInput) {
	if !fuzzer.coverageEnabled {
		panic("should not be called when coverage is disabled")
	}
	p, err := fuzzer.target.Deserialize(inp.Prog)
	if err != nil {
		panic(err)
	}
	sig := hash.Hash(inp.Prog)
	sign := inp.Signal.Deserialize()
	fuzzer.addInputToCorpus(p, sign, sig)
}

func (fuzzer *Fuzzer) addInputToCorpus(p *prog.Prog, sign signal.Signal, sig hash.Sig) {
	fuzzer.corpusMu.Lock()
	if _, ok := fuzzer.corpusHashes[sig]; !ok {
		fuzzer.corpus = append(fuzzer.corpus, p)
		fuzzer.corpusHashes[sig] = struct{}{}
	}
	fuzzer.corpusMu.Unlock()

	if !sign.Empty() {
		fuzzer.signalMu.Lock()
		fuzzer.corpusSignal.Merge(sign)
		fuzzer.maxSignal.Merge(sign)
		fuzzer.signalMu.Unlock()
	}
}

func (fuzzer *Fuzzer) corpusSnapshot() []*prog.Prog {
	fuzzer.corpusMu.RLock()
	defer fuzzer.corpusMu.RUnlock()
	return fuzzer.corpus
}

func (fuzzer *Fuzzer) addMaxSignal(sign signal.Signal) {
	if sign.Len() == 0 {
		return
	}
	fuzzer.signalMu.Lock()
	defer fuzzer.signalMu.Unlock()
	fuzzer.maxSignal.Merge(sign)
}

func (fuzzer *Fuzzer) grabNewSignal() signal.Signal {
	fuzzer.signalMu.Lock()
	defer fuzzer.signalMu.Unlock()
	sign := fuzzer.newSignal
	if sign.Empty() {
		return nil
	}
	fuzzer.newSignal = nil
	return sign
}

func (fuzzer *Fuzzer) corpusSignalDiff(sign signal.Signal) signal.Signal {
	fuzzer.signalMu.RLock()
	defer fuzzer.signalMu.RUnlock()
	return fuzzer.corpusSignal.Diff(sign)
}

func (fuzzer *Fuzzer) checkNewSignal(p *prog.Prog, info []ipc.CallInfo) (calls []int) {
	fuzzer.signalMu.RLock()
	defer fuzzer.signalMu.RUnlock()
	for i, inf := range info {
		diff := fuzzer.maxSignal.DiffRaw(inf.Signal, signalPrio(p.Target, p.Calls[i], &inf))
		if diff.Empty() {
			continue
		}
		calls = append(calls, i)
		fuzzer.signalMu.RUnlock()
		fuzzer.signalMu.Lock()
		fuzzer.maxSignal.Merge(diff)
		fuzzer.newSignal.Merge(diff)
		fuzzer.signalMu.Unlock()
		fuzzer.signalMu.RLock()
	}
	return
}

func signalPrio(target *prog.Target, c *prog.Call, ci *ipc.CallInfo) (prio uint8) {
	if ci.Errno == 0 {
		prio |= 1 << 1
	}
	if !target.CallContainsAny(c) {
		prio |= 1 << 0
	}
	return
}

func (fuzzer *Fuzzer) leakCheckCallback() {
	if atomic.LoadUint32(&fuzzer.leakCheckReady) != 0 {
		// Scan for leaks once in a while (it is damn slow).
		kmemleakScan(true)
	}
}
