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
	"time"

	"github.com/google/syzkaller/ipc"
	"github.com/google/syzkaller/prog"
)

var (
	flagCorpus   = flag.String("corpus", "", "corpus directory")
	flagExecutor = flag.String("executor", "", "path to executor binary")
	flagOutput   = flag.Bool("output", false, "print executor output to console")
	flagDebug    = flag.Bool("debug", false, "executor debug output")
	flagProcs    = flag.Int("procs", runtime.NumCPU(), "number of parallel processes")

	failedRe = regexp.MustCompile("runtime error: |panic: |Panic: ")
)

func main() {
	flag.Parse()
	corpus := readCorpus()
	flags := ipc.FlagThreaded | ipc.FlagCollide | ipc.FlagDropPrivs
	if *flagDebug {
		flags |= ipc.FlagDebug
	}

	for p := 0; p < *flagProcs; p++ {
		go func() {
			env, err := ipc.MakeEnv(*flagExecutor, 4*time.Second, flags)
			if err != nil {
				failf("failed to create execution environment: %v", err)
			}
			rs := rand.NewSource(time.Now().UnixNano())
			rnd := rand.New(rs)
			for i := 0; ; i++ {
				var p *prog.Prog
				if len(corpus) == 0 || i%10 != 0 {
					p = prog.Generate(rs, 50, nil)
					execute(env, p)
					p.Mutate(rs, 50, nil)
					execute(env, p)
				} else {
					p = corpus[rnd.Intn(len(corpus))].Clone()
					p.Mutate(rs, 50, nil)
					execute(env, p)
				}
			}
		}()
	}
	select {}
}

func execute(env *ipc.Env, p *prog.Prog) {
	if *flagExecutor == "" {
		return
	}
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
