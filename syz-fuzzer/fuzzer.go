// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

// TODO: implement some form of smashing of new inputs.
// E.g. alter arguments while the program still gives the new coverage,
// i.e. aim at cracking new branches and triggering bugs in that new piece of code.

import (
	"crypto/sha1"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net/rpc"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/syzkaller/cover"
	"github.com/google/syzkaller/ipc"
	"github.com/google/syzkaller/prog"
	. "github.com/google/syzkaller/rpctype"
	"github.com/google/syzkaller/sys"
)

var (
	flagName      = flag.String("name", "", "unique name for manager")
	flagExecutor  = flag.String("executor", "", "path to executor binary")
	flagManager   = flag.String("manager", "", "manager rpc address")
	flagStrace    = flag.Bool("strace", false, "run executor under strace")
	flagSaveProg  = flag.Bool("saveprog", false, "save programs into local file before executing")
	flagSyscalls  = flag.String("calls", "", "comma-delimited list of enabled syscall IDs (empty string for all syscalls)")
	flagNoCover   = flag.Bool("nocover", false, "disable coverage collection/handling")
	flagDropPrivs = flag.Bool("dropprivs", true, "impersonate into nobody")
	flagProcs     = flag.Int("procs", 1, "number of parallel test processes")
	flagLeak      = flag.Bool("leak", false, "detect memory leaks")
	flagV         = flag.Int("v", 0, "verbosity")
)

const (
	programLength = 30
)

type Sig [sha1.Size]byte

func hash(data []byte) Sig {
	return Sig(sha1.Sum(data))
}

type Input struct {
	p     *prog.Prog
	call  int
	cover cover.Cover
}

var (
	manager *rpc.Client

	coverMu     sync.RWMutex
	corpusCover []cover.Cover
	maxCover    []cover.Cover
	flakes      cover.Cover

	corpusMu     sync.RWMutex
	corpus       []Input
	corpusHashes map[Sig]struct{}

	triageMu   sync.RWMutex
	triage     []Input
	candidates []*prog.Prog

	gate *ipc.Gate

	statExecGen       uint64
	statExecFuzz      uint64
	statExecCandidate uint64
	statExecTriage    uint64
	statExecMinimize  uint64
	statNewInput      uint64

	allTriaged uint32
)

func main() {
	debug.SetGCPercent(50)
	flag.Parse()
	logf(0, "started")

	var calls []*sys.Call
	if *flagSyscalls != "" {
		for _, id := range strings.Split(*flagSyscalls, ",") {
			n, err := strconv.ParseUint(id, 10, 64)
			if err != nil || n >= uint64(len(sys.Calls)) {
				panic(fmt.Sprintf("invalid syscall in -calls flag: '%v", id))
			}
			calls = append(calls, sys.Calls[n])
		}
	}

	corpusCover = make([]cover.Cover, sys.CallCount)
	maxCover = make([]cover.Cover, sys.CallCount)
	corpusHashes = make(map[Sig]struct{})

	logf(0, "dialing manager at %v", *flagManager)
	conn, err := rpc.Dial("tcp", *flagManager)
	if err != nil {
		panic(err)
	}
	manager = conn
	a := &ConnectArgs{*flagName}
	r := &ConnectRes{}
	if err := manager.Call("Manager.Connect", a, r); err != nil {
		panic(err)
	}
	ct := prog.BuildChoiceTable(r.Prios, calls)

	kmemleakInit()

	flags := ipc.FlagThreaded | ipc.FlagCollide
	if *flagStrace {
		flags |= ipc.FlagStrace
	}
	if !*flagNoCover {
		flags |= ipc.FlagCover | ipc.FlagDedupCover
	}
	if *flagDropPrivs {
		flags |= ipc.FlagDropPrivs
	}
	if *flagProcs <= 0 {
		*flagProcs = 1
	}

	gate = ipc.NewGate(2 * *flagProcs)
	envs := make([]*ipc.Env, *flagProcs)
	for pid := 0; pid < *flagProcs; pid++ {
		env, err := ipc.MakeEnv(*flagExecutor, 10*time.Second, flags)
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
						triageMu.Unlock()
						logf(1, "triaging : %s", inp.p)
						triageInput(pid, env, inp)
						continue
					} else if len(candidates) != 0 {
						last := len(candidates) - 1
						p := candidates[last]
						candidates = candidates[:last]
						triageMu.Unlock()
						execute(pid, env, p, &statExecCandidate)
						continue
					} else {
						triageMu.Unlock()
					}
				} else {
					triageMu.RUnlock()
				}

				corpusMu.RLock()
				if len(corpus) == 0 || i%10 == 0 {
					corpusMu.RUnlock()
					p := prog.Generate(rnd, programLength, ct)
					logf(1, "#%v: generated: %s", i, p)
					execute(pid, env, p, &statExecGen)
					p.Mutate(rnd, programLength, ct)
					logf(1, "#%v: mutated: %s", i, p)
					execute(pid, env, p, &statExecFuzz)
				} else {
					inp := corpus[rnd.Intn(len(corpus))]
					corpusMu.RUnlock()
					p := inp.p.Clone()
					p.Mutate(rs, programLength, ct)
					logf(1, "#%v: mutated: %s <- %s", i, p, inp.p)
					execute(pid, env, p, &statExecFuzz)
				}
			}
		}()
	}

	var lastPoll time.Time
	var lastPrint time.Time
	for range time.NewTicker(3 * time.Second).C {
		if !*flagSaveProg && time.Since(lastPrint) > 10*time.Second {
			// Keep-alive for manager.
			logf(0, "alive")
			lastPrint = time.Now()
		}
		if time.Since(lastPoll) > 10*time.Second {
			triageMu.RLock()
			if len(candidates) != 0 {
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
			for _, data := range r.Candidates {
				p, err := prog.Deserialize(data)
				if err != nil {
					panic(err)
				}
				if *flagNoCover {
					inp := Input{p, 0, nil}
					corpusMu.Lock()
					corpus = append(corpus, inp)
					corpusMu.Unlock()
				} else {
					triageMu.Lock()
					candidates = append(candidates, p)
					triageMu.Unlock()
				}
			}
			if len(r.Candidates) == 0 {
				if atomic.LoadUint32(&allTriaged) == 0 {
					if *flagLeak {
						kmemleakScan(false)
					}
					atomic.StoreUint32(&allTriaged, 1)
				}
			}
			if len(r.NewInputs) == 0 && len(r.Candidates) == 0 {
				lastPoll = time.Now()
			}
		}
	}
}

func addInput(inp RpcInput) {
	corpusMu.Lock()
	defer corpusMu.Unlock()
	coverMu.Lock()
	defer coverMu.Unlock()

	if *flagNoCover {
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
	inp1 := Input{p, inp.CallIndex, cov}
	corpus = append(corpus, inp1)
	corpusCover[call.CallID] = cover.Union(corpusCover[call.CallID], cov)
	maxCover[call.CallID] = cover.Union(maxCover[call.CallID], cov)
	corpusHashes[hash(inp.Prog)] = struct{}{}
}

func triageInput(pid int, env *ipc.Env, inp Input) {
	if *flagNoCover {
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

	minCover := inp.cover
	for i := 0; i < 3; i++ {
		allCover := execute1(pid, env, inp.p, &statExecTriage)
		if len(allCover[inp.call]) == 0 {
			// The call was not executed. Happens sometimes, reason unknown.
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
		}
	}
	stableNewCover := cover.Intersection(newCover, minCover)
	if len(stableNewCover) == 0 {
		return
	}
	inp.p, inp.call = prog.Minimize(inp.p, inp.call, func(p1 *prog.Prog, call1 int) bool {
		allCover := execute1(pid, env, p1, &statExecMinimize)
		coverMu.RLock()
		defer coverMu.RUnlock()

		if len(allCover[call1]) == 0 {
			return false // The call was not executed.
		}
		cov := allCover[call1]
		if len(cover.Intersection(stableNewCover, cov)) != len(stableNewCover) {
			return false
		}
		minCover = cover.Intersection(minCover, cov)
		return true
	})
	inp.cover = minCover

	atomic.AddUint64(&statNewInput, 1)
	data := inp.p.Serialize()
	logf(2, "added new input for %v to corpus:\n%s", call.CallName, data)
	a := &NewInputArgs{*flagName, RpcInput{call.CallName, data, inp.call, []uint32(inp.cover)}}
	if err := manager.Call("Manager.NewInput", a, nil); err != nil {
		panic(err)
	}

	corpusMu.Lock()
	defer corpusMu.Unlock()
	coverMu.Lock()
	defer coverMu.Unlock()

	corpusCover[call.CallID] = cover.Union(corpusCover[call.CallID], minCover)
	corpus = append(corpus, inp)
	corpusHashes[hash(data)] = struct{}{}
}

func execute(pid int, env *ipc.Env, p *prog.Prog, stat *uint64) {
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

			inp := Input{p.Clone(), i, cover.Copy(cov)}
			triageMu.Lock()
			triage = append(triage, inp)
			triageMu.Unlock()
		}
	}
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
	defer gate.Leave(idx, func() {
		if idx == 0 && *flagLeak && atomic.LoadUint32(&allTriaged) != 0 {
			// Scan for leaks once in a while (it is damn slow).
			kmemleakScan(true)
		}
	})

	if *flagSaveProg {
		f, err := os.Create(fmt.Sprintf("%v-%v.prog", *flagName, pid))
		if err == nil {
			f.Write(p.Serialize())
			f.Close()
		}
	} else {
		// The following output helps to understand what program crashed kernel.
		// It must not be intermixed.
		data := p.Serialize()
		logMu.Lock()
		log.Printf("executing program %v:\n%s", pid, data)
		logMu.Unlock()
	}

	try := 0
retry:
	atomic.AddUint64(stat, 1)
	output, strace, rawCover, errnos, failed, hanged, err := env.Exec(p)
	_ = errnos
	if failed {
		// BUG in output should be recognized by manager.
		logf(0, "BUG: executor-detected bug:\n%s", output)
		// Don't return any cover so that the input is not added to corpus.
		return make([]cover.Cover, len(p.Calls))
	}
	if err != nil {
		if try > 10 {
			panic(err)
		}
		try++
		debug.FreeOSMemory()
		time.Sleep(time.Second)
		goto retry
	}
	logf(4, "result failed=%v hanged=%v:\n%v\n", failed, hanged, string(output))
	if len(strace) != 0 {
		logf(4, "strace:\n%s\n", strace)
	}
	cov := make([]cover.Cover, len(p.Calls))
	for i, c := range rawCover {
		cov[i] = cover.Cover(c)
	}
	return cov
}

func logf(v int, msg string, args ...interface{}) {
	if *flagV >= v {
		log.Printf(msg, args...)
	}
}

func kmemleakInit() {
	fd, err := syscall.Open("/sys/kernel/debug/kmemleak", syscall.O_RDWR, 0)
	if err != nil {
		if *flagLeak {
			panic(err)
		} else {
			return
		}
	}
	defer syscall.Close(fd)
	if _, err := syscall.Write(fd, []byte("scan=off")); err != nil {
		panic(err)
	}
}

var kmemleakBuf []byte

func kmemleakScan(report bool) {
	fd, err := syscall.Open("/sys/kernel/debug/kmemleak", syscall.O_RDWR, 0)
	if err != nil {
		panic(err)
	}
	defer syscall.Close(fd)
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
			// BUG in output should be recognized by manager.
			logf(0, "BUG: memory leak:\n%s\n", kmemleakBuf[:n])
		}
	}
	if _, err := syscall.Write(fd, []byte("clear")); err != nil {
		panic(err)
	}
}
