// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/google/syzkaller/pkg/covermerger"
)

func main() {
	flagWorkdir := flag.String("workdir", "workdir-cover-aggregation",
		"[optional] used to clone repos")
	flagCleanWorkdir := flag.Bool("clean-workdir", false,
		"[optional] cleans workdir before start")
	flagRepo := flag.String("repo", "", "[required] repo to be used as an aggregation point")
	flagBranch := flag.String("branch", "", "[required] branch to be used as an aggregation point")
	flagCommit := flag.String("commit", "", "[required] commit hash to be used as an aggregation point")
	flag.Parse()

	config := &covermerger.Config{
		Workdir: *flagWorkdir,
	}
	if *flagRepo == "" || *flagBranch == "" || *flagCommit == "" {
		log.Print("-repo -branch and -commit flags are required")
		return
	}
	if *flagCleanWorkdir {
		if err := os.RemoveAll(config.Workdir); err != nil {
			panic("failed to clean workdir " + config.Workdir)
		}
	}
	mergedCoverage, err := covermerger.AggregateStreamData(
		config,
		os.Stdin,
		covermerger.RepoBranchCommit{
			Repo:   *flagRepo,
			Branch: *flagBranch,
			Commit: *flagCommit,
		})
	if err != nil {
		panic(err)
	}
	for fileName, lineStat := range mergedCoverage {
		totalInstrumentedLines := 0
		totalCoveredLines := 0
		if !lineStat.FileExists {
			continue
		}

		for _, lineHitCount := range lineStat.HitCounts {
			totalInstrumentedLines++
			if lineHitCount > 0 {
				totalCoveredLines++
			}
		}
		coverage := 0.0
		if totalInstrumentedLines != 0 {
			coverage = float64(totalCoveredLines) / float64(totalInstrumentedLines)
		}
		fmt.Printf("%s: %.2f%%", fileName, coverage*100)
	}
}
