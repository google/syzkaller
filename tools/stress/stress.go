// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/google/syzkaller/ipc"
	"github.com/google/syzkaller/prog"
)

var (
	flagCorpus   = flag.String("corpus", "", "corpus directory")
	flagExecutor = flag.String("executor", "", "path to executor binary")
	flagOutput   = flag.Bool("output", false, "print executor output to console")
	flagDebug    = flag.Bool("debug", false, "executor debug output")

	failedRe = regexp.MustCompile("runtime error: |panic: |Panic: ")
)

func main() {
	flag.Parse()
	corpus := readCorpus()
	flags := ipc.FlagThreaded
	if *flagDebug {
		flags |= ipc.FlagDebug
	}
	env, err := ipc.MakeEnv(*flagExecutor, 5*time.Second, flags)
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
	files, err := ioutil.ReadDir(*flagCorpus)
	if err != nil {
		failf("failed to read corpus dir: %v", err)
	}
	var progs []*prog.Prog
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		data, err := ioutil.ReadFile(filepath.Join(*flagCorpus, f.Name()))
		if err != nil {
			failf("failed to read corpus file: %v", err)
		}
		p, err := prog.Deserialize(data)
		if err != nil {
			failf("failed to deserialize corpus program: %v", err)
		}
		progs = append(progs, p)
	}
	return progs
}

func failf(msg string, args ...interface{}) {
	log.Fatalf(msg, args...)
}
