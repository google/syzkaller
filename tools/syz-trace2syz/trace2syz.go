// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build !codeanalysis

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
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/tools/syz-trace2syz/proggen"
)

var (
	flagFile        = flag.String("file", "", "file to parse")
	flagDir         = flag.String("dir", "", "directory to parse")
	flagDeserialize = flag.String("deserialize", "", "(Optional) directory to store deserialized programs")
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
	log.Logf(0, "parsing %v traces", totalFiles)
	for i, file := range names {
		log.Logf(1, "parsing file %v/%v: %v", i+1, totalFiles, filepath.Base(names[i]))
		progs, err := proggen.ParseFile(file, target)
		if err != nil {
			log.Fatalf("%v", err)
		}
		ret = append(ret, progs...)
		if deserializeDir != "" {
			for i, p := range progs {
				progName := filepath.Join(deserializeDir, filepath.Base(file)+strconv.Itoa(i))
				if err := osutil.WriteFile(progName, p.Serialize()); err != nil {
					log.Fatalf("failed to output file: %v", err)
				}
			}
		}
	}
	return ret
}

func getTraceFiles(dir string) []string {
	infos, err := ioutil.ReadDir(dir)
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
