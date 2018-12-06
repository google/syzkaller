// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-trace2syz converts strace traces to syzkaller programs.
//
// Simple usage:
//	strace -o trace -a 1 -s 65500 -v -xx -f -Xraw ./a.out
//	syz-trace2syz -file trace
// Intended for seed selection or debugging
package main

import (
	"flag"
	"io/ioutil"
	"path/filepath"
	"strconv"

	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/tools/syz-trace2syz/parser"
	"github.com/google/syzkaller/tools/syz-trace2syz/proggen"
)

var (
	flagFile        = flag.String("file", "", "file to parse")
	flagDir         = flag.String("dir", "", "directory to parse")
	flagDeserialize = flag.String("deserialize", "", "(Optional) directory to store deserialized programs")
	callSelector    = proggen.NewCallSelector()
)

const (
	goos = "linux" // Target OS
	arch = "amd64" // Target architecture
)

func main() {
	flag.Parse()
	target := initializeTarget(goos, arch)
	progs := parseTraces(target)
	log.Logf(0, "successfully converted traces; generating corpus.db")
	pack(progs)
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

func parseTraces(target *prog.Target) []*prog.Prog {
	var ret []*prog.Prog
	var names []string

	if *flagFile != "" {
		names = append(names, *flagFile)
	} else if *flagDir != "" {
		names = getTraceFiles(*flagDir)
	} else {
		log.Fatalf("-file or -dir must be specified")
	}

	deserializeDir := *flagDeserialize

	totalFiles := len(names)
	log.Logf(0, "parsing %d traces", totalFiles)
	for i, file := range names {
		log.Logf(1, "parsing File %d/%d: %s", i+1, totalFiles, filepath.Base(names[i]))
		tree := parser.Parse(file)
		if tree == nil {
			log.Logf(1, "file: %s is empty", filepath.Base(file))
			continue
		}
		ctxs := parseTree(tree, tree.RootPid, target)
		for i, ctx := range ctxs {
			ctx.Prog.Target = ctx.Target
			if err := ctx.FillOutMemory(); err != nil {
				log.Logf(1, "failed to fill out memory: %v, skipping this prog", err)
				continue
			}
			if err := ctx.Prog.Finalize(); err != nil {
				log.Fatalf("error validating program: %s", err)
			}
			if progIsTooLarge(ctx.Prog) {
				log.Logf(1, "prog is too large")
				continue
			}
			ret = append(ret, ctx.Prog)
			if deserializeDir == "" {
				continue
			}
			progName := filepath.Join(deserializeDir, filepath.Base(file)+strconv.Itoa(i))
			if err := ioutil.WriteFile(progName, ctx.Prog.Serialize(), 0640); err != nil {
				log.Fatalf("failed to output file: %v", err)
			}
		}

	}
	return ret
}

func progIsTooLarge(p *prog.Prog) bool {
	buff := make([]byte, prog.ExecBufferSize)
	if _, err := p.SerializeForExec(buff); err != nil {
		return true
	}
	return false
}

func getTraceFiles(dir string) []string {
	var names []string
	infos, err := ioutil.ReadDir(dir)
	if err != nil {
		log.Fatalf("%s", err)

	}
	for _, info := range infos {
		name := filepath.Join(dir, info.Name())
		names = append(names, name)
	}
	return names
}

// parseTree groups system calls in the trace by process id.
// The tree preserves process hierarchy i.e. parent->[]child
func parseTree(tree *parser.TraceTree, pid int64, target *prog.Target) []*proggen.Context {
	log.Logf(2, "parsing trace: %s", tree.Filename)
	var ctxs []*proggen.Context
	ctx := proggen.GenSyzProg(tree.TraceMap[pid], target, callSelector)

	ctxs = append(ctxs, ctx)
	for _, childPid := range tree.Ptree[pid] {
		if tree.TraceMap[childPid] != nil {
			ctxs = append(ctxs, parseTree(tree, childPid, target)...)
		}
	}
	return ctxs
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
