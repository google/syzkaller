// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:build !codeanalysis

// syz-trace2syz converts strace traces to syzkaller programs.
//
// Simple usage:
//
//	strace -o trace -a 1 -s 65500 -v -xx -f -Xraw --raw=wait4 ./a.out
//	syz-trace2syz -file trace
//
// Intended for seed selection or debugging
package main

import (
	"flag"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/tools/syz-trace2syz/proggen"
)

var (
	flagFile        = flag.String("file", "", "file to parse")
	flagDir         = flag.String("dir", "", "directory to parse")
	flagDeserialize = flag.String("deserialize", "", "(Optional) directory to store deserialized programs")
	flagSkipCorpus = flag.Bool("nocorpus", false, "(Optional) skip generating corpus.db")
	flagTopCalls    = flag.Int("topCalls", 2, "number of most used usyscalls to be used for file name generation")
)

const (
	goos = targets.Linux // Target OS
	arch = targets.AMD64 // Target architecture
)

func main() {
	flag.Parse()
	target := initializeTarget(goos, arch)
	progs := parseTraces(target)
	if ! *flagSkipCorpus {
		log.Logf(0, "successfully converted traces; generating corpus.db")
		pack(progs)
	}
}

func initializeTarget(os, arch string) *prog.Target {
	target, err := prog.GetTarget(os, arch)
	if err != nil {
		log.Fatalf("failed to load target: %s", err)
	}
	target.ConstMap = make(map[string]uint64)
	for _, c := range target.Consts {
		target.ConstMap[c.Name] = c.Value
	}
	return target
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

func parseTraces(target *prog.Target) []*prog.Prog {
	var ret []*prog.Prog
	var names []string
	progPrefix := make(map[*prog.Prog]string)

	outPrefixesIdx := make(map[string]int)

	if *flagFile != "" {
		names = append(names, *flagFile)
	} else if *flagDir != "" {
		names = getTraceFiles(*flagDir)
	} else {
		log.Fatalf("-file or -dir must be specified")
	}

	deserializeDir := *flagDeserialize

	totalFiles := len(names)
	log.Logf(0, "parsing %v traces", totalFiles)
	for i, file := range names {
		log.Logf(1, "parsing file %v/%v: %v", i+1, totalFiles, filepath.Base(names[i]))
		progs, err := proggen.ParseFile(file, target)
		for _, p := range progs {
			progPrefix[p] = filepath.Base(names[i])[:5]
		}
		if err != nil {
			log.Fatalf("%v", err)
		}
		ret = append(ret, progs...)
	}

	i := 0
	for _, p := range ret {
		scallHist := genSyscallHist(p)
		topNames := topKNames(scallHist, *flagTopCalls)
		outPrefix := progPrefix[p] + "_" + strings.Join(topNames, "_")
		_, ok := outPrefixesIdx[outPrefix]
		if !ok {
			outPrefixesIdx[outPrefix]=0
		} else {
			outPrefixesIdx[outPrefix]++
		}
		progName := filepath.Join(deserializeDir, "thread_"+outPrefix+"_"+strconv.Itoa(outPrefixesIdx[outPrefix])+".prog")
		if err := osutil.WriteFile(progName, p.Serialize()); err != nil {
			log.Fatalf("failed to output file: %v", err)
		}
		log.Logf(0, "Stored program %s", progName);
		i++
	}
	return ret
}

func getTraceFiles(dir string) []string {
	infos, err := os.ReadDir(dir)
	if err != nil {
		log.Fatalf("%s", err)

	}
	var names []string
	for _, info := range infos {
		name := filepath.Join(dir, info.Name())
		names = append(names, name)
	}
	return names
}

func pack(progs []*prog.Prog) {
	var records []db.Record
	for _, prog := range progs {
		records = append(records, db.Record{Val: prog.Serialize()})
	}
	if err := db.Create("corpus.db", 0, records); err != nil {
		log.Fatalf("%v", err)
	}
	log.Logf(0, "finished!")
}
