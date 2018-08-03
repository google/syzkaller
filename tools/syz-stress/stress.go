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
	"github.com/google/syzkaller/pkg/ipc/ipcconfig"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

var (
	flagOS       = flag.String("os", runtime.GOOS, "target os")
	flagArch     = flag.String("arch", runtime.GOARCH, "target arch")
	flagCorpus   = flag.String("corpus", "", "corpus database")
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
		log.Fatalf("%v", err)
	}
	corpus := readCorpus(target)
	log.Logf(0, "parsed %v programs", len(corpus))
	if !*flagGenerate && len(corpus) == 0 {
		log.Fatalf("nothing to mutate (-generate=false and no corpus)")
	}

	features, err := host.Check(target)
	if err != nil {
		log.Fatalf("%v", err)
	}
	if _, err = host.Setup(target, features); err != nil {
		log.Fatalf("%v", err)
	}

	calls := buildCallList(target)
	prios := target.CalculatePriorities(corpus)
	ct := target.BuildChoiceTable(prios, calls)

	config, execOpts, err := ipcconfig.Default(target)
	if err != nil {
		log.Fatalf("%v", err)
	}
	if features[host.FeatureNetworkInjection].Enabled {
		config.Flags |= ipc.FlagEnableTun
	}
	if features[host.FeatureNetworkDevices].Enabled {
		config.Flags |= ipc.FlagEnableNetDev
	}
	gate = ipc.NewGate(2**flagProcs, nil)
	for pid := 0; pid < *flagProcs; pid++ {
		pid := pid
		go func() {
			env, err := ipc.MakeEnv(config, pid)
			if err != nil {
				log.Fatalf("failed to create execution environment: %v", err)
			}
			rs := rand.NewSource(time.Now().UnixNano() + int64(pid)*1e12)
			rnd := rand.New(rs)
			for i := 0; ; i++ {
				var p *prog.Prog
				if *flagGenerate && len(corpus) == 0 || i%4 != 0 {
					p = target.Generate(rs, programLength, ct)
					execute(pid, env, execOpts, p)
					p.Mutate(rs, programLength, ct, corpus)
					execute(pid, env, execOpts, p)
				} else {
					p = corpus[rnd.Intn(len(corpus))].Clone()
					p.Mutate(rs, programLength, ct, corpus)
					execute(pid, env, execOpts, p)
					p.Mutate(rs, programLength, ct, corpus)
					execute(pid, env, execOpts, p)
				}
			}
		}()
	}
	for range time.NewTicker(5 * time.Second).C {
		log.Logf(0, "executed %v programs", atomic.LoadUint64(&statExec))
	}
}

var outMu sync.Mutex

func execute(pid int, env *ipc.Env, execOpts *ipc.ExecOpts, p *prog.Prog) {
	atomic.AddUint64(&statExec, 1)
	if *flagLogProg {
		ticket := gate.Enter()
		defer gate.Leave(ticket)
		outMu.Lock()
		fmt.Printf("executing program %v\n%s\n", pid, p.Serialize())
		outMu.Unlock()
	}
	output, _, failed, hanged, err := env.Exec(execOpts, p)
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
		log.Fatalf("failed to open corpus database: %v", err)
	}
	var progs []*prog.Prog
	for _, rec := range db.Records {
		p, err := target.Deserialize(rec.Val)
		if err != nil {
			log.Fatalf("failed to deserialize corpus program: %v", err)
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
	calls, disabled, err := host.DetectSupportedSyscalls(target, "none")
	if err != nil {
		log.Logf(0, "failed to detect host supported syscalls: %v", err)
		calls = make(map[*prog.Syscall]bool)
		for _, c := range target.Syscalls {
			calls[c] = true
		}
	}
	for c, reason := range disabled {
		log.Logf(0, "unsupported syscall: %v: %v", c.Name, reason)
	}
	calls, disabled = target.TransitivelyEnabledCalls(calls)
	for c, reason := range disabled {
		log.Logf(0, "transitively unsupported: %v: %v", c.Name, reason)
	}
	return calls
}
