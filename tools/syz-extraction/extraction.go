// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/stat"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

var (
	flagOS   = flag.String("os", runtime.GOOS, "target os")
	flagArch = flag.String("arch", runtime.GOARCH, "target arch")
	flagProg = flag.String("prog", "", "file with program to convert (required)")

	flagStrict = flag.Bool("strict", false, "parse input program in strict mode")
	flagDeserialize = flag.String("deserialize", "", "(Optional) directory to store deserialized programs")
	flagMinCalls    = flag.Int("minCalls", 10, "minimum number of remaining syscalls after minimization")
	flagTopCalls    = flag.Int("topCalls", 2, "number of most used usyscalls to be used for file name generation")
)

func help() {
	flag.Usage = func() {
		flag.PrintDefaults()
	}
	flag.Parse()
	if *flagProg == "" {
		flag.Usage()
		os.Exit(1)
	}
}

func readProg() (p *prog.Prog) {
	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	data, err := os.ReadFile(*flagProg)
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
	return
}

func predTrue(*prog.Prog, int, *stat.Val, string) bool {
	return true
}

func generateMinimizedProg(p *prog.Prog, callIndex0 int, processedCallsIn map[int]bool) (pOut *prog.Prog, processedCalls map[int]bool) {
	pOut, _, processedCalls = prog.RemoveUnrelatedCalls(p, callIndex0, predTrue, processedCallsIn)
	return
}

func generateAllProgs(p0 *prog.Prog) (pF *prog.Prog) {
	numCalls := len(p0.Calls)
	processedCalls := map[int]bool{numCalls - 1: false}
	p := p0.Clone()
	outPrefixesIdx := make(map[string]int)
	prefixLen := 2

	fmt.Fprintf(os.Stderr, "Number of syscalls before: %d\n", numCalls)
	for i := numCalls - 1; i > 0; {
		if i%1000 == 0 {
			fmt.Fprintf(os.Stderr, "(%d/%d) Finished.\n", i, numCalls)
		}
		if !processedCalls[i] {
			pF, processedCalls = generateMinimizedProg(p, i, processedCalls)
			if len(pF.Calls) >= *flagMinCalls {
				fmt.Fprintf(os.Stderr, "(%d/%d) Number of syscalls after: %d\n", i, len(p.Calls), len(pF.Calls))
				prefixLen = 2
				progBase := filepath.Base(*flagProg)
				splitBase := strings.Split(progBase, "_")
				if len(splitBase) > 1 && splitBase[0] == "thread" {
					progBase = strings.Join(splitBase[1:], "_")
					prefixLen = 1
				}

				scallHist := genSyscallHist(pF)
				topNames := topKNames(scallHist, *flagTopCalls)
				outPrefix := strings.Join(strings.Split(progBase, "_")[:prefixLen], "_") + "_" + strings.Join(topNames, "_")
				_, ok := outPrefixesIdx[outPrefix]
				if !ok {
					outPrefixesIdx[outPrefix]=0
				} else {
					outPrefixesIdx[outPrefix]++
				}

				saveProg2File(pF, outPrefix, outPrefixesIdx[outPrefix])
			}
		}
		p.RemoveCall(i)
		i--
	}
	return
}

func genSyscallHist(p *prog.Prog) map[string]int {
	hist := make(map[string]int)

	for _, call := range p.Calls {
		_, ok := hist[call.Meta.CallName]
		if !ok {
			hist[call.Meta.CallName] = 1
		} else {
			hist[call.Meta.CallName]++
		}
	}

	return hist
}

func topKNames(hist map[string]int, k int) []string {
	var names []string
	var counts []int

	if k > len(hist) {
		k = len(hist)
	}

	i := 0
	for i < k {
		names = append(names, "")
		counts = append(counts, 0)
		i++
	}

	for name, count := range hist {
		for idx, c := range counts {
			if count > c {
				names[idx] = name
				counts[idx] = count
				break
			}
		}
	}

	return names
}

func saveProg2File(p *prog.Prog, prefix string, index int) {
	outName := filepath.Join(*flagDeserialize, "min_"+prefix+"_"+strconv.Itoa(index)+".prog")
	if err := osutil.WriteFile(outName, p.Serialize()); err != nil {
		log.Fatalf("failed to output file: %v", err)
	}
	log.Logf(0, "Stored program %s", outName)
}

func filterProgram(p *prog.Prog) *prog.Prog {
	syscall_blacklist := []string{
		"futex",
		"accept",
		"execve",
		"recvfrom",
		"sendto",
		"exit",
		"clone",
		"clone3",
		"clock_nanosleep",
	}

	for i := len(p.Calls)-1; i >= 0; i-- {
		if slices.Contains(syscall_blacklist,p.Calls[i].Meta.CallName) {
			p.Calls = append(p.Calls[:i], p.Calls[i+1:]...)
		}
	}

	return p
}

func main() {
	help()

	p := readProg()

	p = filterProgram(p)

	generateAllProgs(p)
}
