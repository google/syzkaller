// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-base-commit is a tool for debugging the blob-based base commit detection functionality.

package main

import (
	"flag"
	"log"
	"os"

	"github.com/google/syzkaller/pkg/debugtracer"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/pkg/vcs"
)

var (
	flagRepo = flag.String("sourcedir", "", "path to the Linux kernel repository")
)

func main() {
	defer tool.Init()()
	args := flag.Args()
	if *flagRepo == "" || len(args) != 1 {
		tool.Failf("expected format: syz-base-commit --sourcedir ./linux-repo some-patch.diff")
	}
	log.Printf("note: the tool runs much faster after a `git commit-graph write --reachable`")
	diff, err := os.ReadFile(args[0])
	if err != nil {
		tool.Fail(err)
	}
	git := &vcs.Git{
		Dir: *flagRepo,
	}
	commits, err := git.BaseForDiff(diff, &debugtracer.GenericTracer{
		TraceWriter: os.Stderr,
	})
	if err != nil {
		tool.Fail(err)
	}
	if len(commits) == 0 {
		log.Printf("no suitable commits found!")
		os.Exit(0)
	}
	log.Printf("found %d candidates:", len(commits))
	for _, commit := range commits {
		log.Printf("%+v", commit)
	}
}
