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

	flagV = flag.Int("v", 0, "verbosity")
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
	corpusCover  []cover.Cover
	maxCover     []cover.Cover
	flakes       cover.Cover
	corpus       []Input
	corpusHashes map[Sig]struct{}
	triage       []Input
	manager      *rpc.Client
	ct           *prog.ChoiceTable

	statExecGen       uint64
	statExecFuzz      uint64
	statExecCandidate uint64
	statExecTriage    uint64
	statExecMinimize  uint64
	statNewInput      uint64
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

	conn, err := rpc.Dial("tcp", *flagManager)
	if err != nil {
		panic(err)
	}
	manager = conn
	a := &ManagerConnectArgs{*flagName}
	r := &ManagerConnectRes{}
	if err := manager.Call("Manager.Connect", a, r); err != nil {
		panic(err)
	}
	ct = prog.BuildChoiceTable(r.Prios, calls)

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
	env, err := ipc.MakeEnv(*flagExecutor, 10*time.Second, flags)
	if err != nil {
		panic(err)
	}
	rs := rand.NewSource(time.Now().UnixNano())
	rnd := rand.New(rs)
	var lastPoll time.Time
	var lastPrint time.Time
	for i := 0; ; i++ {
		if !*flagSaveProg && time.Since(lastPrint) > 10*time.Second {
			// Keep-alive for manager.
			logf(0, "#%v: alive", i)
			lastPrint = time.Now()
		}
		if len(triage) != 0 {
			last := len(triage) - 1
			inp := triage[last]
			triage = triage[:last]
			logf(1, "#%v: triaging : %s", i, inp.p)
			triageInput(env, inp)
			continue
		}
		if time.Since(lastPoll) > 10*time.Second {
			a := &ManagerPollArgs{
				Name:  *flagName,
				Stats: make(map[string]uint64),
			}
			a.Stats["exec total"] = env.StatExecs
			env.StatExecs = 0
			a.Stats["executor restarts"] = env.StatRestarts
			env.StatRestarts = 0
			a.Stats["exec gen"] = statExecGen
			statExecGen = 0
			a.Stats["exec fuzz"] = statExecFuzz
			statExecFuzz = 0
			a.Stats["exec candidate"] = statExecCandidate
			statExecCandidate = 0
			a.Stats["exec triage"] = statExecTriage
			statExecTriage = 0
			a.Stats["exec minimize"] = statExecMinimize
			statExecMinimize = 0
			a.Stats["fuzzer new inputs"] = statNewInput
			statNewInput = 0
			r := &ManagerPollRes{}
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
					corpus = append(corpus, inp)
				} else {
					execute(env, p, &statExecCandidate)
				}
			}
			if len(r.NewInputs) == 0 && len(r.Candidates) == 0 {
				lastPoll = time.Now()
			}
			continue
		}
		if len(corpus) == 0 || i%10 == 0 {
			p := prog.Generate(rnd, programLength, ct)
			logf(1, "#%v: generated: %s", i, p)
			execute(env, p, &statExecGen)
			p.Mutate(rnd, programLength, ct)
			logf(1, "#%v: mutated: %s", i, p)
			execute(env, p, &statExecFuzz)
		} else {
			inp := corpus[rnd.Intn(len(corpus))]
			p := inp.p.Clone()
			p.Mutate(rs, programLength, ct)
			logf(1, "#%v: mutated: %s <- %s", i, p, inp.p)
			execute(env, p, &statExecFuzz)
		}
	}
}

func addInput(inp RpcInput) {
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

func triageInput(env *ipc.Env, inp Input) {
	if *flagNoCover {
		panic("should not be called when coverage is disabled")
	}
	call := inp.p.Calls[inp.call].Meta
	newCover := cover.Difference(inp.cover, corpusCover[call.CallID])
	newCover = cover.Difference(newCover, flakes)
	if len(newCover) == 0 {
		return
	}

	if _, ok := corpusHashes[hash(inp.p.Serialize())]; ok {
		return
	}

	minCover := inp.cover
	for i := 0; i < 3; i++ {
		allCover := execute1(env, inp.p, &statExecTriage)
		if len(allCover[inp.call]) == 0 {
			// The call was not executed. Happens sometimes, reason unknown.
			continue
		}
		cov := allCover[inp.call]
		diff := cover.SymmetricDifference(inp.cover, cov)
		if len(diff) != 0 {
			flakes = cover.Union(flakes, diff)
		}
		minCover = cover.Intersection(minCover, cov)
	}
	stableNewCover := cover.Intersection(newCover, minCover)
	if len(stableNewCover) == 0 {
		return
	}
	inp.p, inp.call = prog.Minimize(inp.p, inp.call, func(p1 *prog.Prog, call1 int) bool {
		allCover := execute1(env, p1, &statExecMinimize)
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
	corpusCover[call.CallID] = cover.Union(corpusCover[call.CallID], minCover)
	corpus = append(corpus, inp)
	data := inp.p.Serialize()
	corpusHashes[hash(data)] = struct{}{}

	logf(2, "added new input for %v to corpus:\n%s", call.CallName, data)

	statNewInput++
	a := &NewManagerInputArgs{*flagName, RpcInput{call.CallName, inp.p.Serialize(), inp.call, []uint32(inp.cover)}}
	if err := manager.Call("Manager.NewInput", a, nil); err != nil {
		panic(err)
	}
}

func execute(env *ipc.Env, p *prog.Prog, stat *uint64) {
	allCover := execute1(env, p, stat)
	for i, cov := range allCover {
		if len(cov) == 0 {
			continue
		}
		c := p.Calls[i].Meta
		diff := cover.Difference(cov, maxCover[c.CallID])
		diff = cover.Difference(diff, flakes)
		if len(diff) != 0 {
			triage = append(triage, Input{p.Clone(), i, cover.Copy(cov)})
		}
	}
}

var logMu sync.Mutex

func execute1(env *ipc.Env, p *prog.Prog, stat *uint64) []cover.Cover {
	if *flagSaveProg {
		f, err := os.Create(fmt.Sprintf("%v.prog", *flagName))
		if err == nil {
			f.Write(p.Serialize())
			f.Close()
		}
	} else {
		// The following output helps to understand what program crashed kernel.
		// It must not be intermixed.
		logMu.Lock()
		log.Printf("executing program:\n%s", p.Serialize())
		logMu.Unlock()
	}

	try := 0
retry:
	*stat++
	output, strace, rawCover, failed, hanged, err := env.Exec(p)
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
