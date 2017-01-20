// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

// TODO: implement some form of smashing of new inputs.
// E.g. alter arguments while the program still gives the new coverage,
// i.e. aim at cracking new branches and triggering bugs in that new piece of code.

import (
	"bytes"
	"crypto/sha1"
	"flag"
	"fmt"
	"math/rand"
	"net/rpc"
	"net/rpc/jsonrpc"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/syzkaller/cover"
	"github.com/google/syzkaller/host"
	"github.com/google/syzkaller/ipc"
	. "github.com/google/syzkaller/log"
	"github.com/google/syzkaller/prog"
	. "github.com/google/syzkaller/rpctype"
	"github.com/google/syzkaller/sys"
)

var (
	flagName     = flag.String("name", "", "unique name for manager")
	flagExecutor = flag.String("executor", "", "path to executor binary")
	flagManager  = flag.String("manager", "", "manager rpc address")
	flagProcs    = flag.Int("procs", 1, "number of parallel test processes")
	flagLeak     = flag.Bool("leak", false, "detect memory leaks")
	flagOutput   = flag.String("output", "stdout", "write programs to none/stdout/dmesg/file")
)

const (
	programLength = 30
)

type Sig [sha1.Size]byte

func hash(data []byte) Sig {
	return Sig(sha1.Sum(data))
}

type Input struct {
	p         *prog.Prog
	call      int
	cover     cover.Cover
	minimized bool
}

type Candidate struct {
	p         *prog.Prog
	minimized bool
}

var (
	manager *rpc.Client

	coverMu     sync.RWMutex
	corpusCover []cover.Cover
	maxCover    []cover.Cover
	flakes      cover.Cover

	corpusMu     sync.RWMutex
	corpus       []*prog.Prog
	corpusHashes map[Sig]struct{}

	triageMu   sync.RWMutex
	triage     []Input
	candidates []Candidate

	gate *ipc.Gate

	statExecGen       uint64
	statExecFuzz      uint64
	statExecCandidate uint64
	statExecTriage    uint64
	statExecMinimize  uint64
	statNewInput      uint64

	allTriaged uint32
	noCover    bool
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

	go func() {
		// Handles graceful preemption on GCE.
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
		<-c
		Logf(0, "SYZ-FUZZER: PREEMPTED")
		os.Exit(1)
	}()

	corpusCover = make([]cover.Cover, sys.CallCount)
	maxCover = make([]cover.Cover, sys.CallCount)
	corpusHashes = make(map[Sig]struct{})

	Logf(0, "dialing manager at %v", *flagManager)
	conn, err := jsonrpc.Dial("tcp", *flagManager)
	if err != nil {
		panic(err)
	}
	manager = conn
	a := &ConnectArgs{*flagName}
	r := &ConnectRes{}
	if err := manager.Call("Manager.Connect", a, r); err != nil {
		panic(err)
	}
	calls := buildCallList(r.EnabledCalls)
	ct := prog.BuildChoiceTable(r.Prios, calls)

	if r.NeedCheck {
		a := &CheckArgs{Name: *flagName}
		if fd, err := syscall.Open("/sys/kernel/debug/kcov", syscall.O_RDWR, 0); err == nil {
			syscall.Close(fd)
			a.Kcov = true
		}
		for c := range calls {
			a.Calls = append(a.Calls, c.Name)
		}
		if err := manager.Call("Manager.Check", a, nil); err != nil {
			panic(err)
		}
	}

	kmemleakInit()

	flags, timeout, err := ipc.DefaultFlags()
	if err != nil {
		panic(err)
	}
	if _, ok := calls[sys.CallMap["syz_emit_ethernet"]]; ok {
		flags |= ipc.FlagEnableTun
	}
	noCover = flags&ipc.FlagCover == 0
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
		env, err := ipc.MakeEnv(*flagExecutor, timeout, flags, pid)
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
				if len(triage) != 0 || len(candidates) != 0 {
					triageMu.RUnlock()
					triageMu.Lock()
					if len(triage) != 0 {
						last := len(triage) - 1
						inp := triage[last]
						triage = triage[:last]
						wakePoll := len(triage) < *flagProcs
						triageMu.Unlock()
						if wakePoll {
							select {
							case needPoll <- struct{}{}:
							default:
							}
						}
						Logf(1, "triaging : %s", inp.p)
						triageInput(pid, env, inp)
						continue
					} else if len(candidates) != 0 {
						last := len(candidates) - 1
						candidate := candidates[last]
						candidates = candidates[:last]
						triageMu.Unlock()
						execute(pid, env, candidate.p, candidate.minimized, &statExecCandidate)
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
					p := prog.Generate(rnd, programLength, ct)
					Logf(1, "#%v: generated: %s", i, p)
					execute(pid, env, p, false, &statExecGen)
				} else {
					// Mutate an existing prog.
					p0 := corpus[rnd.Intn(len(corpus))]
					p := p0.Clone()
					p.Mutate(rs, programLength, ct, corpus)
					corpusMu.RUnlock()
					Logf(1, "#%v: mutated: %s <- %s", i, p, p0)
					execute(pid, env, p, false, &statExecFuzz)
				}
			}
		}()
	}

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
			Logf(0, "alive")
			lastPrint = time.Now()
		}
		if poll || time.Since(lastPoll) > 10*time.Second {
			triageMu.RLock()
			if len(candidates) > *flagProcs {
				triageMu.RUnlock()
				continue
			}
			triageMu.RUnlock()

			a := &PollArgs{
				Name:  *flagName,
				Stats: make(map[string]uint64),
			}
			for _, env := range envs {
				a.Stats["exec total"] += atomic.SwapUint64(&env.StatExecs, 0)
				a.Stats["executor restarts"] += atomic.SwapUint64(&env.StatRestarts, 0)
			}
			a.Stats["exec gen"] = atomic.SwapUint64(&statExecGen, 0)
			a.Stats["exec fuzz"] = atomic.SwapUint64(&statExecFuzz, 0)
			a.Stats["exec candidate"] = atomic.SwapUint64(&statExecCandidate, 0)
			a.Stats["exec triage"] = atomic.SwapUint64(&statExecTriage, 0)
			a.Stats["exec minimize"] = atomic.SwapUint64(&statExecMinimize, 0)
			a.Stats["fuzzer new inputs"] = atomic.SwapUint64(&statNewInput, 0)
			r := &PollRes{}
			if err := manager.Call("Manager.Poll", a, r); err != nil {
				panic(err)
			}
			for _, inp := range r.NewInputs {
				addInput(inp)
			}
			for _, candidate := range r.Candidates {
				p, err := prog.Deserialize(candidate.Prog)
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

func buildCallList(enabledCalls string) map[*sys.Call]bool {
	calls := make(map[*sys.Call]bool)
	if enabledCalls != "" {
		for _, id := range strings.Split(enabledCalls, ",") {
			n, err := strconv.ParseUint(id, 10, 64)
			if err != nil || n >= uint64(len(sys.Calls)) {
				panic(fmt.Sprintf("invalid syscall in -calls flag: '%v", id))
			}
			calls[sys.Calls[n]] = true
		}
	} else {
		for _, c := range sys.Calls {
			calls[c] = true
		}
	}

	if supp, err := host.DetectSupportedSyscalls(); err != nil {
		Logf(0, "failed to detect host supported syscalls: %v", err)
	} else {
		for c := range calls {
			if !supp[c] {
				Logf(1, "disabling unsupported syscall: %v", c.Name)
				delete(calls, c)
			}
		}
	}

	trans := sys.TransitivelyEnabledCalls(calls)
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
	coverMu.Lock()
	defer coverMu.Unlock()

	if noCover {
		panic("should not be called when coverage is disabled")
	}
	p, err := prog.Deserialize(inp.Prog)
	if err != nil {
		panic(err)
	}
	if inp.CallIndex < 0 || inp.CallIndex >= len(p.Calls) {
		panic("bad call index")
	}
	call := p.Calls[inp.CallIndex].Meta
	sig := hash(inp.Prog)
	if _, ok := corpusHashes[sig]; ok {
		return
	}
	cov := cover.Canonicalize(inp.Cover)
	diff := cover.Difference(cov, maxCover[call.CallID])
	diff = cover.Difference(diff, flakes)
	if len(diff) == 0 {
		return
	}
	corpus = append(corpus, p)
	corpusCover[call.CallID] = cover.Union(corpusCover[call.CallID], cov)
	maxCover[call.CallID] = cover.Union(maxCover[call.CallID], cov)
	corpusHashes[hash(inp.Prog)] = struct{}{}
}

func triageInput(pid int, env *ipc.Env, inp Input) {
	if noCover {
		panic("should not be called when coverage is disabled")
	}

	call := inp.p.Calls[inp.call].Meta
	coverMu.RLock()
	newCover := cover.Difference(inp.cover, corpusCover[call.CallID])
	newCover = cover.Difference(newCover, flakes)
	coverMu.RUnlock()
	if len(newCover) == 0 {
		return
	}

	corpusMu.RLock()
	if _, ok := corpusHashes[hash(inp.p.Serialize())]; ok {
		corpusMu.RUnlock()
		return
	}
	corpusMu.RUnlock()

	notexecuted := false
	minCover := inp.cover
	for i := 0; i < 3; i++ {
		allCover := execute1(pid, env, inp.p, &statExecTriage)
		if len(allCover[inp.call]) == 0 {
			// The call was not executed. Happens sometimes, reason unknown.
			if notexecuted {
				return // if it happened twice, give up
			}
			notexecuted = true
			continue
		}
		coverMu.RLock()
		cov := allCover[inp.call]
		diff := cover.SymmetricDifference(inp.cover, cov)
		minCover = cover.Intersection(minCover, cov)
		updateFlakes := len(diff) != 0 && len(cover.Difference(diff, flakes)) != 0
		coverMu.RUnlock()
		if updateFlakes {
			coverMu.Lock()
			flakes = cover.Union(flakes, diff)
			coverMu.Unlock()
			newCover = cover.Intersection(newCover, minCover)
			if len(newCover) == 0 {
				break
			}
		}
	}
	newCover = cover.Intersection(newCover, minCover)
	if len(newCover) == 0 {
		return
	}

	if !inp.minimized {
		inp.p, inp.call = prog.Minimize(inp.p, inp.call, func(p1 *prog.Prog, call1 int) bool {
			allCover := execute(pid, env, p1, false, &statExecMinimize)
			coverMu.RLock()
			defer coverMu.RUnlock()

			if len(allCover[call1]) == 0 {
				return false // The call was not executed.
			}
			cov := allCover[call1]
			if len(cover.Intersection(newCover, cov)) != len(newCover) {
				return false
			}
			minCover = cover.Intersection(minCover, cov)
			return true
		}, false)
	}
	inp.cover = minCover

	atomic.AddUint64(&statNewInput, 1)
	data := inp.p.Serialize()
	Logf(2, "added new input for %v to corpus:\n%s", call.CallName, data)
	a := &NewInputArgs{*flagName, RpcInput{call.CallName, data, inp.call, []uint32(inp.cover)}}
	if err := manager.Call("Manager.NewInput", a, nil); err != nil {
		panic(err)
	}

	corpusMu.Lock()
	defer corpusMu.Unlock()
	coverMu.Lock()
	defer coverMu.Unlock()

	corpusCover[call.CallID] = cover.Union(corpusCover[call.CallID], minCover)
	corpus = append(corpus, inp.p)
	corpusHashes[hash(data)] = struct{}{}
}

func execute(pid int, env *ipc.Env, p *prog.Prog, minimized bool, stat *uint64) []cover.Cover {
	allCover := execute1(pid, env, p, stat)
	coverMu.RLock()
	defer coverMu.RUnlock()
	for i, cov := range allCover {
		if len(cov) == 0 {
			continue
		}
		c := p.Calls[i].Meta
		diff := cover.Difference(cov, maxCover[c.CallID])
		diff = cover.Difference(diff, flakes)
		if len(diff) != 0 {
			coverMu.RUnlock()
			coverMu.Lock()
			maxCover[c.CallID] = cover.Union(maxCover[c.CallID], diff)
			coverMu.Unlock()
			coverMu.RLock()

			inp := Input{
				p:         p.Clone(),
				call:      i,
				cover:     cover.Copy(cov),
				minimized: minimized,
			}
			triageMu.Lock()
			triage = append(triage, inp)
			triageMu.Unlock()
		}
	}
	return allCover
}

var logMu sync.Mutex

func execute1(pid int, env *ipc.Env, p *prog.Prog, stat *uint64) []cover.Cover {
	if false {
		// For debugging, this function must not be executed with locks held.
		corpusMu.Lock()
		corpusMu.Unlock()
		coverMu.Lock()
		coverMu.Unlock()
		triageMu.Lock()
		triageMu.Unlock()
	}

	// Limit concurrency window and do leak checking once in a while.
	idx := gate.Enter()
	defer gate.Leave(idx)

	// The following output helps to understand what program crashed kernel.
	// It must not be intermixed.
	switch *flagOutput {
	case "none":
		// This case intentionally left blank.
	case "stdout":
		data := p.Serialize()
		logMu.Lock()
		Logf(0, "executing program %v:\n%s", pid, data)
		logMu.Unlock()
	case "dmesg":
		fd, err := syscall.Open("/dev/kmsg", syscall.O_WRONLY, 0)
		if err == nil {
			buf := new(bytes.Buffer)
			fmt.Fprintf(buf, "syzkaller: executing program %v:\n%s", pid, p.Serialize())
			syscall.Write(fd, buf.Bytes())
			syscall.Close(fd)
		}
	case "file":
		f, err := os.Create(fmt.Sprintf("%v-%v.prog", *flagName, pid))
		if err == nil {
			f.Write(p.Serialize())
			f.Close()
		}
	}

	try := 0
retry:
	atomic.AddUint64(stat, 1)
	output, rawCover, errnos, failed, hanged, err := env.Exec(p)
	_ = errnos
	if failed {
		// BUG in output should be recognized by manager.
		Logf(0, "BUG: executor-detected bug:\n%s", output)
		// Don't return any cover so that the input is not added to corpus.
		return make([]cover.Cover, len(p.Calls))
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
	Logf(2, "result failed=%v hanged=%v:\n%v\n", failed, hanged, string(output))
	cov := make([]cover.Cover, len(p.Calls))
	for i, c := range rawCover {
		cov[i] = cover.Cover(c)
	}
	return cov
}

func kmemleakInit() {
	fd, err := syscall.Open("/sys/kernel/debug/kmemleak", syscall.O_RDWR, 0)
	if err != nil {
		if *flagLeak {
			Fatalf("BUG: /sys/kernel/debug/kmemleak is missing (%v). Enable CONFIG_KMEMLEAK and mount debugfs.", err)
		} else {
			return
		}
	}
	defer syscall.Close(fd)
	what := "scan=off"
	if !*flagLeak {
		what = "off"
	}
	if _, err := syscall.Write(fd, []byte(what)); err != nil {
		// kmemleak returns EBUSY when kmemleak is already turned off.
		if err != syscall.EBUSY {
			panic(err)
		}
	}
}

var kmemleakBuf []byte

func kmemleakScan(report bool) {
	fd, err := syscall.Open("/sys/kernel/debug/kmemleak", syscall.O_RDWR, 0)
	if err != nil {
		panic(err)
	}
	defer syscall.Close(fd)
	// Kmemleak has false positives. To mitigate most of them, it checksums
	// potentially leaked objects, and reports them only on the next scan
	// iff the checksum does not change. Because of that we do the following
	// intricate dance:
	// Scan, sleep, scan again. At this point we can get some leaks.
	// If there are leaks, we sleep and scan again, this can remove
	// false leaks. Then, read kmemleak again. If we get leaks now, then
	// hopefully these are true positives during the previous testing cycle.
	if _, err := syscall.Write(fd, []byte("scan")); err != nil {
		panic(err)
	}
	time.Sleep(time.Second)
	if _, err := syscall.Write(fd, []byte("scan")); err != nil {
		panic(err)
	}
	if report {
		if kmemleakBuf == nil {
			kmemleakBuf = make([]byte, 128<<10)
		}
		n, err := syscall.Read(fd, kmemleakBuf)
		if err != nil {
			panic(err)
		}
		if n != 0 {
			time.Sleep(time.Second)
			if _, err := syscall.Write(fd, []byte("scan")); err != nil {
				panic(err)
			}
			n, err := syscall.Read(fd, kmemleakBuf)
			if err != nil {
				panic(err)
			}
			if n != 0 {
				// BUG in output should be recognized by manager.
				Logf(0, "BUG: memory leak:\n%s\n", kmemleakBuf[:n])
			}
		}
	}
	if _, err := syscall.Write(fd, []byte("clear")); err != nil {
		panic(err)
	}
}
