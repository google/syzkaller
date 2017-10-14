// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"math/rand"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/ipc"
	. "github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

var (
	flagOS       = flag.String("os", runtime.GOOS, "target os")
	flagArch     = flag.String("arch", runtime.GOARCH, "target arch")
	flagCorpus   = flag.String("corpus", "", "corpus database")
	flagExecutor = flag.String("executor", "./syz-executor", "path to executor binary")
	flagOutput   = flag.Bool("output", false, "print executor output to console")
	flagProcs    = flag.Int("procs", 2*runtime.NumCPU(), "number of parallel processes")
	flagLogProg  = flag.Bool("logprog", false, "print programs before execution")
	flagGenerate = flag.Bool("generate", true, "generate new programs, otherwise only mutate corpus")

	statExec uint64
	gate     *ipc.Gate
)

const programLength = 30

func main() {
	flag.Parse()
	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		Fatalf("%v", err)
	}
	corpus := readCorpus(target)
	Logf(0, "parsed %v programs", len(corpus))
	if !*flagGenerate && len(corpus) == 0 {
		Fatalf("nothing to mutate (-generate=false and no corpus)")
	}

	calls := buildCallList(target)
	prios := target.CalculatePriorities(corpus)
	ct := target.BuildChoiceTable(prios, calls)

	config, err := ipc.DefaultConfig()
	if err != nil {
		Fatalf("%v", err)
	}
	gate = ipc.NewGate(2**flagProcs, nil)
	for pid := 0; pid < *flagProcs; pid++ {
		pid := pid
		go func() {
			env, err := ipc.MakeEnv(*flagExecutor, pid, config)
			if err != nil {
				Fatalf("failed to create execution environment: %v", err)
			}
			rs := rand.NewSource(time.Now().UnixNano() + int64(pid)*1e12)
			rnd := rand.New(rs)
			for i := 0; ; i++ {
				var p *prog.Prog
				if *flagGenerate && len(corpus) == 0 || i%4 != 0 {
					p = target.Generate(rs, programLength, ct)
					execute(pid, env, p)
					p.Mutate(rs, programLength, ct, corpus)
					execute(pid, env, p)
				} else {
					p = corpus[rnd.Intn(len(corpus))].Clone()
					p.Mutate(rs, programLength, ct, corpus)
					execute(pid, env, p)
					p.Mutate(rs, programLength, ct, corpus)
					execute(pid, env, p)
				}
			}
		}()
	}
	for range time.NewTicker(5 * time.Second).C {
		Logf(0, "executed %v programs", atomic.LoadUint64(&statExec))
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
		defer gate.Leave(ticket)
		outMu.Lock()
		fmt.Printf("executing program %v\n%s\n", pid, p.Serialize())
		outMu.Unlock()
	}
	opts := &ipc.ExecOpts{}
	output, _, failed, hanged, err := env.Exec(opts, p)
	if err != nil {
		fmt.Printf("failed to execute executor: %v\n", err)
	}
	if failed || hanged || err != nil || *flagOutput {
		fmt.Printf("PROGRAM:\n%s\n", p.Serialize())
	}
	if failed || hanged || err != nil || *flagOutput {
		os.Stdout.Write(output)
	}
}

func readCorpus(target *prog.Target) []*prog.Prog {
	if *flagCorpus == "" {
		return nil
	}
	db, err := db.Open(*flagCorpus)
	if err != nil {
		Fatalf("failed to open corpus database: %v", err)
	}
	var progs []*prog.Prog
	for _, rec := range db.Records {
		p, err := target.Deserialize(rec.Val)
		if err != nil {
			Fatalf("failed to deserialize corpus program: %v", err)
		}
		progs = append(progs, p)
	}
	return progs
}

func buildCallList(target *prog.Target) map[*prog.Syscall]bool {
	if *flagOS != runtime.GOOS {
		// This is currently used on akaros, where syz-stress runs on host.
		calls := make(map[*prog.Syscall]bool)
		for _, c := range target.Syscalls {
			calls[c] = true
		}
		return calls
	}
	calls, err := host.DetectSupportedSyscalls(target)
	if err != nil {
		Logf(0, "failed to detect host supported syscalls: %v", err)
		calls = make(map[*prog.Syscall]bool)
		for _, c := range target.Syscalls {
			calls[c] = true
		}
	}
	for _, c := range target.Syscalls {
		if !calls[c] {
			Logf(0, "disabling unsupported syscall: %v", c.Name)
		}
	}
	trans := target.TransitivelyEnabledCalls(calls)
	for c := range calls {
		if !trans[c] {
			Logf(0, "disabling transitively unsupported syscall: %v", c.Name)
			delete(calls, c)
		}
	}
	return calls
}
