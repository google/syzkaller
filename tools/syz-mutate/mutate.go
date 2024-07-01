// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// mutates mutates a given program and prints result.
package main

import (
	"flag"
	"fmt"
	"math/rand"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

var (
	flagOS       = flag.String("os", runtime.GOOS, "target os")
	flagArch     = flag.String("arch", runtime.GOARCH, "target arch")
	flagSeed     = flag.Int("seed", -1, "prng seed")
	flagLen      = flag.Int("len", prog.RecommendedCalls, "number of calls in programs")
	flagEnable   = flag.String("enable", "", "comma-separated list of enabled syscalls")
	flagCorpus   = flag.String("corpus", "", "name of the corpus file")
	flagHintCall = flag.Int("hint-call", -1, "mutate the specified call with hints in hint-src/cmp flags")
	flagHintSrc  = flag.Uint64("hint-src", 0, "compared value in the program")
	flagHintCmp  = flag.Uint64("hint-cmp", 0, "compare operand in the kernel")
	flagStrict   = flag.Bool("strict", true, "parse input program in strict mode")
)

func main() {
	flag.Parse()
	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	var syscalls map[*prog.Syscall]bool
	if *flagEnable != "" {
		enabled := strings.Split(*flagEnable, ",")
		syscallsIDs, err := mgrconfig.ParseEnabledSyscalls(target, enabled, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to parse enabled syscalls: %v\n", err)
			os.Exit(1)
		}
		syscalls = make(map[*prog.Syscall]bool)
		for _, id := range syscallsIDs {
			syscalls[target.Syscalls[id]] = true
		}
		var disabled map[*prog.Syscall]string
		syscalls, disabled = target.TransitivelyEnabledCalls(syscalls)
		for c, reason := range disabled {
			fmt.Fprintf(os.Stderr, "disabling %v: %v\n", c.Name, reason)
		}
	}
	seed := time.Now().UnixNano()
	if *flagSeed != -1 {
		seed = int64(*flagSeed)
	}
	corpus, err := db.ReadCorpus(*flagCorpus, target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read corpus: %v\n", err)
		os.Exit(1)
	}
	rs := rand.NewSource(seed)
	ct := target.BuildChoiceTable(corpus, syscalls)
	var p *prog.Prog
	if flag.NArg() == 0 {
		p = target.Generate(rs, *flagLen, ct)
	} else {
		data, err := os.ReadFile(flag.Arg(0))
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to read prog file: %v\n", err)
			os.Exit(1)
		}
		mode := prog.NonStrict
		if *flagStrict {
			mode = prog.Strict
		}
		p, err = target.Deserialize(data, mode)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to deserialize the program: %v\n", err)
			os.Exit(1)
		}
		if *flagHintCall != -1 {
			comps := make(prog.CompMap)
			comps.Add(0, *flagHintSrc, *flagHintCmp, true)
			p.MutateWithHints(*flagHintCall, comps, func(p *prog.Prog) bool {
				fmt.Printf("%s\n\n", p.Serialize())
				return true
			})
			return
		} else {
			p.Mutate(rs, *flagLen, ct, nil, corpus)
		}
	}
	fmt.Printf("%s\n", p.Serialize())
}
