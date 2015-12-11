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
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/ipc"
	"github.com/google/syzkaller/prog"
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

	failedRe = regexp.MustCompile("runtime error: |panic: |Panic: ")

	statExec uint64
)

const programLength = 30

func main() {
	flag.Parse()
	corpus := readCorpus()
	log.Printf("parsed %v programs", len(corpus))
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

	for p := 0; p < *flagProcs; p++ {
		p := p
		go func() {
			env, err := ipc.MakeEnv(*flagExecutor, *flagTimeout, flags)
			if err != nil {
				failf("failed to create execution environment: %v", err)
			}
			rs := rand.NewSource(time.Now().UnixNano() + int64(p)*1e12)
			rnd := rand.New(rs)
			for i := 0; ; i++ {
				var p *prog.Prog
				if len(corpus) == 0 || i%2 != 0 {
					p = prog.Generate(rs, programLength, nil)
					execute(env, p)
					p.Mutate(rs, programLength, nil)
					execute(env, p)
				} else {
					p = corpus[rnd.Intn(len(corpus))].Clone()
					p.Mutate(rs, programLength, nil)
					execute(env, p)
					p.Mutate(rs, programLength, nil)
					execute(env, p)
				}
			}
		}()
	}
	for range time.NewTicker(5 * time.Second).C {
		log.Printf("executed %v programs", atomic.LoadUint64(&statExec))
	}
}

func execute(env *ipc.Env, p *prog.Prog) {
	if *flagExecutor == "" {
		return
	}
	atomic.AddUint64(&statExec, 1)
	output, _, _, _, _, err := env.Exec(p)
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

func failf(msg string, args ...interface{}) {
	log.Fatalf(msg, args...)
}
