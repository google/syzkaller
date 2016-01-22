// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"archive/zip"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"regexp"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/host"
	"github.com/google/syzkaller/ipc"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys"
)

var (
	flagCorpus   = flag.String("corpus", "", "corpus directory")
	flagExecutor = flag.String("executor", "", "path to executor binary")
	flagOutput   = flag.Bool("output", false, "print executor output to console")
	flagDebug    = flag.Bool("debug", false, "executor debug output")
	flagProcs    = flag.Int("procs", 2*runtime.NumCPU(), "number of parallel processes")
	flagThreaded = flag.Bool("threaded", true, "use threaded mode in executor")
	flagCollide  = flag.Bool("collide", true, "collide syscalls to provoke data races")
	flagNobody   = flag.Bool("nobody", true, "impersonate into nobody")
	flagTimeout  = flag.Duration("timeout", 10*time.Second, "executor timeout")
	flagLogProg  = flag.Bool("logprog", false, "print programs before execution")

	failedRe = regexp.MustCompile("runtime error: |panic: |Panic: ")

	statExec uint64
	gate     *ipc.Gate
)

const programLength = 30

func main() {
	flag.Parse()
	corpus := readCorpus()
	log.Printf("parsed %v programs", len(corpus))

	calls := buildCallList()
	prios := prog.CalculatePriorities(corpus)
	ct := prog.BuildChoiceTable(prios, calls)

	var flags uint64
	if *flagThreaded {
		flags |= ipc.FlagThreaded
	}
	if *flagCollide {
		flags |= ipc.FlagCollide
	}
	if *flagNobody {
		flags |= ipc.FlagDropPrivs
	}
	if *flagDebug {
		flags |= ipc.FlagDebug
	}

	gate = ipc.NewGate(2 * *flagProcs)
	for pid := 0; pid < *flagProcs; pid++ {
		pid := pid
		go func() {
			env, err := ipc.MakeEnv(*flagExecutor, *flagTimeout, flags)
			if err != nil {
				failf("failed to create execution environment: %v", err)
			}
			rs := rand.NewSource(time.Now().UnixNano() + int64(pid)*1e12)
			rnd := rand.New(rs)
			for i := 0; ; i++ {
				var p *prog.Prog
				if len(corpus) == 0 || i%4 != 0 {
					p = prog.Generate(rs, programLength, ct)
					execute(pid, env, p)
					p.Mutate(rs, programLength, ct)
					execute(pid, env, p)
				} else {
					p = corpus[rnd.Intn(len(corpus))].Clone()
					p.Mutate(rs, programLength, ct)
					execute(pid, env, p)
					p.Mutate(rs, programLength, ct)
					execute(pid, env, p)
				}
			}
		}()
	}
	for range time.NewTicker(5 * time.Second).C {
		log.Printf("executed %v programs", atomic.LoadUint64(&statExec))
	}
}

var outMu sync.Mutex

func execute(pid int, env *ipc.Env, p *prog.Prog) {
	if *flagExecutor == "" {
		return
	}
	atomic.AddUint64(&statExec, 1)
	if *flagLogProg {
		ticket := gate.Enter()
		defer gate.Leave(ticket, nil)
		outMu.Lock()
		fmt.Printf("executing program %v\n%s\n", pid, p.Serialize())
		outMu.Unlock()
	}

	output, _, _, _, _, _, err := env.Exec(p)
	if err != nil {
		fmt.Printf("failed to execute executor: %v\n", err)
	}
	failed := failedRe.Match(output)
	if failed {
		fmt.Printf("PROGRAM:\n%s\n", p.Serialize())
	}
	if failed || *flagOutput {
		os.Stdout.Write(output)
	}
}

func readCorpus() []*prog.Prog {
	if *flagCorpus == "" {
		return nil
	}
	zipr, err := zip.OpenReader(*flagCorpus)
	if err != nil {
		failf("failed to open bin file: %v", err)
	}
	var progs []*prog.Prog
	for _, zipf := range zipr.File {
		r, err := zipf.Open()
		if err != nil {
			failf("failed to uzip file from input archive: %v", err)
		}
		data, err := ioutil.ReadAll(r)
		if err != nil {
			failf("failed to read corpus file: %v", err)
		}
		p, err := prog.Deserialize(data)
		if err != nil {
			failf("failed to deserialize corpus program: %v", err)
		}
		progs = append(progs, p)
		r.Close()
	}
	zipr.Close()
	return progs
}

func buildCallList() map[*sys.Call]bool {
	calls, err := host.DetectSupportedSyscalls()
	if err != nil {
		log.Printf("failed to detect host supported syscalls: %v", err)
		for _, c := range sys.Calls {
			calls[c] = true
		}
	}
	for _, c := range sys.Calls {
		if !calls[c] {
			log.Printf("disabling unsupported syscall: %v", c.Name)
		}
	}
	trans := sys.TransitivelyEnabledCalls(calls)
	for c := range calls {
		if !trans[c] {
			log.Printf("disabling transitively unsupported syscall: %v", c.Name)
			delete(calls, c)
		}
	}
	return calls
}

func failf(msg string, args ...interface{}) {
	log.Fatalf(msg, args...)
}
