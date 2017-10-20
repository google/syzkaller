// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/ipc"
	. "github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	. "github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys"
)

var (
	flagName     = flag.String("name", "", "unique name for manager")
	flagArch     = flag.String("arch", runtime.GOARCH, "target arch")
	flagExecutor = flag.String("executor", "", "path to executor binary")
	flagManager  = flag.String("manager", "", "manager rpc address")
	flagProcs    = flag.Int("procs", 1, "number of parallel test processes")
	flagLeak     = flag.Bool("leak", false, "detect memory leaks")
	flagOutput   = flag.String("output", "stdout", "write programs to none/stdout/dmesg/file")
	flagPprof    = flag.String("pprof", "", "address to serve pprof profiles")
)

const (
	programLength = 30
)

type Input struct {
	p         *prog.Prog
	call      int
	signal    []uint32
	minimized bool
}

type Candidate struct {
	p         *prog.Prog
	minimized bool
}

var (
	manager *RpcClient
	target  *prog.Target

	signalMu     sync.RWMutex
	corpusSignal map[uint32]struct{}
	maxSignal    map[uint32]struct{}
	newSignal    map[uint32]struct{}

	corpusMu     sync.RWMutex
	corpus       []*prog.Prog
	corpusHashes map[hash.Sig]struct{}

	triageMu        sync.RWMutex
	triage          []Input
	triageCandidate []Input
	candidates      []Candidate
	smashQueue      []Input

	gate *ipc.Gate

	statExecGen       uint64
	statExecFuzz      uint64
	statExecCandidate uint64
	statExecTriage    uint64
	statExecMinimize  uint64
	statExecSmash     uint64
	statNewInput      uint64
	statExecHints     uint64
	statExecHintSeeds uint64

	allTriaged            uint32
	noCover               bool
	faultInjectionEnabled bool
	compsSupported        bool
)

func main() {
	debug.SetGCPercent(50)
	flag.Parse()
	switch *flagOutput {
	case "none", "stdout", "dmesg", "file":
	default:
		fmt.Fprintf(os.Stderr, "-output flag must be one of none/stdout/dmesg/file\n")
		os.Exit(1)
	}
	Logf(0, "fuzzer started")

	var err error
	target, err = prog.GetTarget(runtime.GOOS, *flagArch)
	if err != nil {
		Fatalf("%v", err)
	}

	shutdown := make(chan struct{})
	osutil.HandleInterrupts(shutdown)
	go func() {
		// Handles graceful preemption on GCE.
		<-shutdown
		Logf(0, "SYZ-FUZZER: PREEMPTED")
		os.Exit(1)
	}()

	if *flagPprof != "" {
		go func() {
			err := http.ListenAndServe(*flagPprof, nil)
			Fatalf("failed to serve pprof profiles: %v", err)
		}()
	} else {
		runtime.MemProfileRate = 0
	}

	corpusSignal = make(map[uint32]struct{})
	maxSignal = make(map[uint32]struct{})
	newSignal = make(map[uint32]struct{})
	corpusHashes = make(map[hash.Sig]struct{})

	Logf(0, "dialing manager at %v", *flagManager)
	a := &ConnectArgs{*flagName}
	r := &ConnectRes{}
	if err := RpcCall(*flagManager, "Manager.Connect", a, r); err != nil {
		panic(err)
	}
	calls := buildCallList(target, r.EnabledCalls)
	ct := target.BuildChoiceTable(r.Prios, calls)
	for _, inp := range r.Inputs {
		addInput(inp)
	}
	for _, s := range r.MaxSignal {
		maxSignal[s] = struct{}{}
	}
	for _, candidate := range r.Candidates {
		p, err := target.Deserialize(candidate.Prog)
		if err != nil {
			panic(err)
		}
		if noCover {
			corpusMu.Lock()
			corpus = append(corpus, p)
			corpusMu.Unlock()
		} else {
			triageMu.Lock()
			candidates = append(candidates, Candidate{p, candidate.Minimized})
			triageMu.Unlock()
		}
	}

	// This requires "fault-inject: support systematic fault injection" kernel commit.
	if fd, err := syscall.Open("/proc/self/fail-nth", syscall.O_RDWR, 0); err == nil {
		syscall.Close(fd)
		faultInjectionEnabled = true
	}

	kcov := false
	kcov, compsSupported = checkCompsSupported()
	Logf(0, "kcov=%v, comps=%v", kcov, compsSupported)
	if r.NeedCheck {
		out, err := osutil.RunCmd(time.Minute, "", *flagExecutor, "version")
		if err != nil {
			panic(err)
		}
		vers := strings.Split(strings.TrimSpace(string(out)), " ")
		if len(vers) != 4 {
			panic(fmt.Sprintf("bad executor version: %q", string(out)))
		}
		a := &CheckArgs{
			Name:           *flagName,
			UserNamespaces: osutil.IsExist("/proc/self/ns/user"),
			FuzzerGitRev:   sys.GitRevision,
			FuzzerSyzRev:   target.Revision,
			ExecutorGitRev: vers[3],
			ExecutorSyzRev: vers[2],
			ExecutorArch:   vers[1],
		}
		a.Kcov = kcov
		if fd, err := syscall.Open("/sys/kernel/debug/kmemleak", syscall.O_RDWR, 0); err == nil {
			syscall.Close(fd)
			a.Leak = true
		}
		a.Fault = faultInjectionEnabled
		a.CompsSupported = compsSupported
		for c := range calls {
			a.Calls = append(a.Calls, c.Name)
		}
		if err := RpcCall(*flagManager, "Manager.Check", a, nil); err != nil {
			panic(err)
		}
	}

	// Manager.Connect reply can ve very large and that memory will be permanently cached in the connection.
	// So we do the call on a transient connection, free all memory and reconnect.
	// The rest of rpc requests have bounded size.
	debug.FreeOSMemory()
	if conn, err := NewRpcClient(*flagManager); err != nil {
		panic(err)
	} else {
		manager = conn
	}

	kmemleakInit()

	config, err := ipc.DefaultConfig()
	if err != nil {
		panic(err)
	}
	if _, ok := calls[target.SyscallMap["syz_emit_ethernet"]]; ok {
		config.Flags |= ipc.FlagEnableTun
	}
	if _, ok := calls[target.SyscallMap["syz_extract_tcp_res"]]; ok {
		config.Flags |= ipc.FlagEnableTun
	}
	if faultInjectionEnabled {
		config.Flags |= ipc.FlagEnableFault
	}
	noCover = config.Flags&ipc.FlagSignal == 0
	leakCallback := func() {
		if atomic.LoadUint32(&allTriaged) != 0 {
			// Scan for leaks once in a while (it is damn slow).
			kmemleakScan(true)
		}
	}
	if !*flagLeak {
		leakCallback = nil
	}
	gate = ipc.NewGate(2**flagProcs, leakCallback)
	needPoll := make(chan struct{}, 1)
	needPoll <- struct{}{}
	envs := make([]*ipc.Env, *flagProcs)
	for pid := 0; pid < *flagProcs; pid++ {
		env, err := ipc.MakeEnv(*flagExecutor, pid, config)
		if err != nil {
			panic(err)
		}
		envs[pid] = env

		pid := pid
		go func() {
			rs := rand.NewSource(time.Now().UnixNano() + int64(pid)*1e12)
			rnd := rand.New(rs)

			for i := 0; ; i++ {
				triageMu.RLock()
				Logf(1, "#%v: triageCandidate=%v candidates=%v triage=%v smashQueue=%v",
					pid, len(triageCandidate), len(candidates), len(triage),
					len(smashQueue))
				if len(triageCandidate) != 0 || len(candidates) != 0 || len(triage) != 0 || len(smashQueue) != 0 {
					triageMu.RUnlock()
					triageMu.Lock()
					if len(triageCandidate) != 0 {
						last := len(triageCandidate) - 1
						inp := triageCandidate[last]
						triageCandidate = triageCandidate[:last]
						triageMu.Unlock()
						Logf(1, "#%v: triaging candidate", pid)
						triageInput(pid, env, inp)
						continue
					} else if len(candidates) != 0 {
						last := len(candidates) - 1
						candidate := candidates[last]
						candidates = candidates[:last]
						wakePoll := len(candidates) < *flagProcs
						triageMu.Unlock()
						if wakePoll {
							select {
							case needPoll <- struct{}{}:
							default:
							}
						}
						Logf(1, "#%v: executing candidate", pid)
						execute(pid, env, candidate.p, false, false, candidate.minimized, true, &statExecCandidate)
						continue
					} else if len(triage) != 0 {
						last := len(triage) - 1
						inp := triage[last]
						triage = triage[:last]
						triageMu.Unlock()
						Logf(1, "#%v: triaging", pid)
						triageInput(pid, env, inp)
						continue
					} else if len(smashQueue) != 0 {
						last := len(smashQueue) - 1
						inp := smashQueue[last]
						smashQueue = smashQueue[:last]
						triageMu.Unlock()
						Logf(1, "#%v: smashing", pid)
						smashInput(pid, env, ct, rs, inp)
						continue
					} else {
						triageMu.Unlock()
					}
				} else {
					triageMu.RUnlock()
				}

				corpusMu.RLock()
				if len(corpus) == 0 || i%100 == 0 {
					// Generate a new prog.
					corpusMu.RUnlock()
					p := target.Generate(rnd, programLength, ct)
					Logf(1, "#%v: generated", pid)
					execute(pid, env, p, false, false, false, false, &statExecGen)
				} else {
					// Mutate an existing prog.
					p := corpus[rnd.Intn(len(corpus))].Clone()
					corpusMu.RUnlock()
					p.Mutate(rs, programLength, ct, corpus)
					Logf(1, "#%v: mutated", pid)
					execute(pid, env, p, false, false, false, false, &statExecFuzz)
				}
			}
		}()
	}

	var execTotal uint64
	var lastPoll time.Time
	var lastPrint time.Time
	ticker := time.NewTicker(3 * time.Second).C
	for {
		poll := false
		select {
		case <-ticker:
		case <-needPoll:
			poll = true
		}
		if *flagOutput != "stdout" && time.Since(lastPrint) > 10*time.Second {
			// Keep-alive for manager.
			Logf(0, "alive, executed %v", execTotal)
			lastPrint = time.Now()
		}
		if poll || time.Since(lastPoll) > 10*time.Second {
			triageMu.RLock()
			needCandidates := len(candidates) < *flagProcs
			triageMu.RUnlock()
			if !needCandidates && poll {
				continue
			}

			a := &PollArgs{
				Name:           *flagName,
				NeedCandidates: needCandidates,
				Stats:          make(map[string]uint64),
			}
			signalMu.Lock()
			a.MaxSignal = make([]uint32, 0, len(newSignal))
			for s := range newSignal {
				a.MaxSignal = append(a.MaxSignal, s)
			}
			newSignal = make(map[uint32]struct{})
			signalMu.Unlock()
			for _, env := range envs {
				a.Stats["exec total"] += atomic.SwapUint64(&env.StatExecs, 0)
				a.Stats["executor restarts"] += atomic.SwapUint64(&env.StatRestarts, 0)
			}
			stat := func(p *uint64, name string) {
				v := atomic.SwapUint64(p, 0)
				a.Stats[name] = v
				execTotal += v
			}
			stat(&statExecGen, "exec gen")
			stat(&statExecFuzz, "exec fuzz")
			stat(&statExecCandidate, "exec candidate")
			stat(&statExecTriage, "exec triage")
			stat(&statExecMinimize, "exec minimize")
			stat(&statExecSmash, "exec smash")
			stat(&statExecHints, "exec hints")
			stat(&statExecHintSeeds, "exec seeds")

			a.Stats["fuzzer new inputs"] = atomic.SwapUint64(&statNewInput, 0)
			r := &PollRes{}
			if err := manager.Call("Manager.Poll", a, r); err != nil {
				panic(err)
			}
			Logf(1, "poll: candidates=%v inputs=%v signal=%v",
				len(r.Candidates), len(r.NewInputs), len(r.MaxSignal))
			if len(r.MaxSignal) != 0 {
				signalMu.Lock()
				for _, s := range r.MaxSignal {
					maxSignal[s] = struct{}{}
				}
				signalMu.Unlock()
			}
			for _, inp := range r.NewInputs {
				addInput(inp)
			}
			for _, candidate := range r.Candidates {
				p, err := target.Deserialize(candidate.Prog)
				if err != nil {
					panic(err)
				}
				if noCover {
					corpusMu.Lock()
					corpus = append(corpus, p)
					corpusMu.Unlock()
				} else {
					triageMu.Lock()
					candidates = append(candidates, Candidate{p, candidate.Minimized})
					triageMu.Unlock()
				}
			}
			if len(r.Candidates) == 0 && atomic.LoadUint32(&allTriaged) == 0 {
				if *flagLeak {
					kmemleakScan(false)
				}
				atomic.StoreUint32(&allTriaged, 1)
			}
			if len(r.NewInputs) == 0 && len(r.Candidates) == 0 {
				lastPoll = time.Now()
			}
		}
	}
}

func buildCallList(target *prog.Target, enabledCalls string) map[*prog.Syscall]bool {
	calls := make(map[*prog.Syscall]bool)
	if enabledCalls != "" {
		for _, id := range strings.Split(enabledCalls, ",") {
			n, err := strconv.ParseUint(id, 10, 64)
			if err != nil || n >= uint64(len(target.Syscalls)) {
				panic(fmt.Sprintf("invalid syscall in -calls flag: %v", id))
			}
			calls[target.Syscalls[n]] = true
		}
	} else {
		for _, c := range target.Syscalls {
			calls[c] = true
		}
	}

	if supp, err := host.DetectSupportedSyscalls(target); err != nil {
		Logf(0, "failed to detect host supported syscalls: %v", err)
	} else {
		for c := range calls {
			if !supp[c] {
				Logf(1, "disabling unsupported syscall: %v", c.Name)
				delete(calls, c)
			}
		}
	}

	trans := target.TransitivelyEnabledCalls(calls)
	for c := range calls {
		if !trans[c] {
			Logf(1, "disabling transitively unsupported syscall: %v", c.Name)
			delete(calls, c)
		}
	}
	return calls
}

func addInput(inp RpcInput) {
	corpusMu.Lock()
	defer corpusMu.Unlock()
	signalMu.Lock()
	defer signalMu.Unlock()

	if noCover {
		panic("should not be called when coverage is disabled")
	}
	p, err := target.Deserialize(inp.Prog)
	if err != nil {
		panic(err)
	}
	sig := hash.Hash(inp.Prog)
	if _, ok := corpusHashes[sig]; !ok {
		corpus = append(corpus, p)
		corpusHashes[sig] = struct{}{}
	}
	if diff := cover.SignalDiff(maxSignal, inp.Signal); len(diff) != 0 {
		cover.SignalAdd(corpusSignal, diff)
		cover.SignalAdd(maxSignal, diff)
	}
}

func smashInput(pid int, env *ipc.Env, ct *prog.ChoiceTable, rs rand.Source, inp Input) {
	if faultInjectionEnabled {
		failCall(pid, env, inp.p, inp.call)
	}
	for i := 0; i < 100; i++ {
		p := inp.p.Clone()
		p.Mutate(rs, programLength, ct, corpus)
		Logf(1, "#%v: smash mutated", pid)
		execute(pid, env, p, false, false, false, false, &statExecSmash)
	}
	if compsSupported {
		executeHintSeed(pid, env, inp.p, inp.call)
	}
}

func failCall(pid int, env *ipc.Env, p *prog.Prog, call int) {
	for nth := 0; nth < 100; nth++ {
		Logf(1, "#%v: injecting fault into call %v/%v", pid, call, nth)
		opts := &ipc.ExecOpts{
			Flags:     ipc.FlagInjectFault,
			FaultCall: call,
			FaultNth:  nth,
		}
		info := execute1(pid, env, opts, p, &statExecSmash)
		if info != nil && len(info) > call && !info[call].FaultInjected {
			break
		}
	}
}

func triageInput(pid int, env *ipc.Env, inp Input) {
	if noCover {
		panic("should not be called when coverage is disabled")
	}

	signalMu.RLock()
	newSignal := cover.SignalDiff(corpusSignal, inp.signal)
	signalMu.RUnlock()
	if len(newSignal) == 0 {
		return
	}
	newSignal = cover.Canonicalize(newSignal)

	call := inp.p.Calls[inp.call].Meta
	data := inp.p.Serialize()
	sig := hash.Hash(data)

	Logf(3, "triaging input for %v (new signal=%v):\n%s", call.CallName, len(newSignal), data)
	var inputCover cover.Cover
	opts := &ipc.ExecOpts{
		Flags: ipc.FlagCollectCover,
	}
	if inp.minimized {
		// We just need to get input coverage.
		for i := 0; i < 3; i++ {
			info := execute1(pid, env, opts, inp.p, &statExecTriage)
			if len(info) == 0 || len(info[inp.call].Cover) == 0 {
				continue // The call was not executed. Happens sometimes.
			}
			inputCover = append([]uint32{}, info[inp.call].Cover...)
			break
		}
	} else {
		// We need to compute input coverage and non-flaky signal for minimization.
		notexecuted := false
		for i := 0; i < 3; i++ {
			info := execute1(pid, env, opts, inp.p, &statExecTriage)
			if len(info) == 0 || len(info[inp.call].Signal) == 0 {
				// The call was not executed. Happens sometimes.
				if notexecuted {
					return // if it happened twice, give up
				}
				notexecuted = true
				continue
			}
			inf := info[inp.call]
			newSignal = cover.Intersection(newSignal, cover.Canonicalize(inf.Signal))
			if len(newSignal) == 0 {
				return
			}
			if len(inputCover) == 0 {
				inputCover = append([]uint32{}, inf.Cover...)
			} else {
				inputCover = cover.Union(inputCover, inf.Cover)
			}
		}

		inp.p, inp.call = prog.Minimize(inp.p, inp.call, func(p1 *prog.Prog, call1 int) bool {
			info := execute(pid, env, p1, false, false, false, false, &statExecMinimize)
			if len(info) == 0 || len(info[call1].Signal) == 0 {
				return false // The call was not executed.
			}
			inf := info[call1]
			signal := cover.Canonicalize(inf.Signal)
			signalMu.RLock()
			defer signalMu.RUnlock()
			if len(cover.Intersection(newSignal, signal)) != len(newSignal) {
				return false
			}
			return true
		}, false)
	}

	atomic.AddUint64(&statNewInput, 1)
	Logf(2, "added new input for %v to corpus:\n%s", call.CallName, data)
	a := &NewInputArgs{
		Name: *flagName,
		RpcInput: RpcInput{
			Call:   call.CallName,
			Prog:   data,
			Signal: []uint32(cover.Canonicalize(inp.signal)),
			Cover:  []uint32(inputCover),
		},
	}
	if err := manager.Call("Manager.NewInput", a, nil); err != nil {
		panic(err)
	}

	signalMu.Lock()
	cover.SignalAdd(corpusSignal, inp.signal)
	signalMu.Unlock()

	corpusMu.Lock()
	if _, ok := corpusHashes[sig]; !ok {
		corpus = append(corpus, inp.p)
		corpusHashes[sig] = struct{}{}
	}
	corpusMu.Unlock()

	if !inp.minimized {
		triageMu.Lock()
		smashQueue = append(smashQueue, inp)
		triageMu.Unlock()
	}
}

func executeHintSeed(pid int, env *ipc.Env, p *prog.Prog, call int) {
	Logf(1, "#%v: collecting comparisons", pid)
	// First execute the original program to dump comparisons from KCOV.
	info := execute(pid, env, p, false, true, false, false, &statExecHintSeeds)
	if info == nil {
		return
	}

	// Then extract the comparisons data.
	compMaps := ipc.GetCompMaps(info)

	// Then mutate the initial program for every match between
	// a syscall argument and a comparison operand.
	// Execute each of such mutants to check if it gives new coverage.
	p.MutateWithHints(call, compMaps[call], func(p *prog.Prog) {
		Logf(1, "#%v: executing comparison hint", pid)
		execute(pid, env, p, false, false, false, false, &statExecHints)
	})
}

func execute(pid int, env *ipc.Env, p *prog.Prog, needCover, needComps, minimized, candidate bool, stat *uint64) []ipc.CallInfo {
	opts := &ipc.ExecOpts{}
	if needComps {
		if !compsSupported {
			panic("compsSupported==false and execute() called with needComps")
		}
		if needCover {
			// Currently KCOV is able to dump only the coverage data or only
			// the comparisons data. We can't enable both modes at same time.
			panic("only one of the needComps and needCover should be true")
		}
		opts.Flags |= ipc.FlagCollectComps
	}
	if needCover {
		opts.Flags |= ipc.FlagCollectCover
	}
	info := execute1(pid, env, opts, p, stat)
	signalMu.RLock()
	defer signalMu.RUnlock()

	for i, inf := range info {
		if !cover.SignalNew(maxSignal, inf.Signal) {
			continue
		}
		diff := cover.SignalDiff(maxSignal, inf.Signal)

		signalMu.RUnlock()
		signalMu.Lock()
		cover.SignalAdd(maxSignal, diff)
		cover.SignalAdd(newSignal, diff)
		signalMu.Unlock()
		signalMu.RLock()

		inp := Input{
			p:         p.Clone(),
			call:      i,
			signal:    append([]uint32{}, inf.Signal...),
			minimized: minimized,
		}
		triageMu.Lock()
		if candidate {
			triageCandidate = append(triageCandidate, inp)
		} else {
			triage = append(triage, inp)
		}
		triageMu.Unlock()
	}
	return info
}

var logMu sync.Mutex

func execute1(pid int, env *ipc.Env, opts *ipc.ExecOpts, p *prog.Prog, stat *uint64) []ipc.CallInfo {
	if false {
		// For debugging, this function must not be executed with locks held.
		corpusMu.Lock()
		corpusMu.Unlock()
		signalMu.Lock()
		signalMu.Unlock()
		triageMu.Lock()
		triageMu.Unlock()
	}

	opts.Flags |= ipc.FlagDedupCover

	// Limit concurrency window and do leak checking once in a while.
	idx := gate.Enter()
	defer gate.Leave(idx)

	strOpts := ""
	if opts.Flags&ipc.FlagInjectFault != 0 {
		strOpts = fmt.Sprintf(" (fault-call:%v fault-nth:%v)", opts.FaultCall, opts.FaultNth)
	}

	// The following output helps to understand what program crashed kernel.
	// It must not be intermixed.
	switch *flagOutput {
	case "none":
		// This case intentionally left blank.
	case "stdout":
		data := p.Serialize()
		logMu.Lock()
		Logf(0, "executing program %v%v:\n%s", pid, strOpts, data)
		logMu.Unlock()
	case "dmesg":
		fd, err := syscall.Open("/dev/kmsg", syscall.O_WRONLY, 0)
		if err == nil {
			buf := new(bytes.Buffer)
			fmt.Fprintf(buf, "syzkaller: executing program %v%v:\n%s", pid, strOpts, p.Serialize())
			syscall.Write(fd, buf.Bytes())
			syscall.Close(fd)
		}
	case "file":
		f, err := os.Create(fmt.Sprintf("%v-%v.prog", *flagName, pid))
		if err == nil {
			if strOpts != "" {
				fmt.Fprintf(f, "#%v\n", strOpts)
			}
			f.Write(p.Serialize())
			f.Close()
		}
	}

	try := 0
retry:
	atomic.AddUint64(stat, 1)
	output, info, failed, hanged, err := env.Exec(opts, p)
	if failed {
		// BUG in output should be recognized by manager.
		Logf(0, "BUG: executor-detected bug:\n%s", output)
		// Don't return any cover so that the input is not added to corpus.
		return nil
	}
	if err != nil {
		if _, ok := err.(ipc.ExecutorFailure); ok || try > 10 {
			panic(err)
		}
		try++
		Logf(4, "fuzzer detected executor failure='%v', retrying #%d\n", err, (try + 1))
		debug.FreeOSMemory()
		time.Sleep(time.Second)
		goto retry
	}
	Logf(2, "result failed=%v hanged=%v: %v\n", failed, hanged, string(output))
	return info
}
