// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"sort"

	"cloud.google.com/go/civil"
	"github.com/google/syzkaller/pkg/covermerger"
	"golang.org/x/exp/maps"
)

var (
	flagWorkdir = flag.String("workdir", "workdir-cover-aggregation",
		"[optional] used to clone repos")
	flagRepo          = flag.String("repo", "", "[required] repo to be used as an aggregation point")
	flagBranch        = flag.String("branch", "", "[required] branch to be used as an aggregation point")
	flagCommit        = flag.String("commit", "", "[required] commit hash to be used as an aggregation point")
	flagNamespace     = flag.String("namespace", "upstream", "[optional] target namespace")
	flagDuration      = flag.Int64("duration", 0, "[optional] used to mark DB records")
	flagDateTo        = flag.String("date-to", "", "[optional] used to mark DB records")
	flagSaveToSpanner = flag.String("save-to-spanner", "", "[optional] save aggregation to spanner")
	flagProjectID     = flag.String("project-id", "syzkaller", "[optional] target spanner db project")
	flagTotalRows     = flag.Int64("total-rows", 0, "[optional] source size, is used for version contol")
)

func main() {
	flag.Parse()
	config := &covermerger.Config{
		Jobs:    runtime.NumCPU(),
		Workdir: *flagWorkdir,
		Base: covermerger.RepoBranchCommit{
			Repo:   *flagRepo,
			Branch: *flagBranch,
			Commit: *flagCommit,
		},
		FileVersProvider: covermerger.MakeMonoRepo(*flagWorkdir),
	}
	mergeResult, err := covermerger.MergeCSVData(config, os.Stdin)
	if err != nil {
		panic(err)
	}
	printMergeResult(mergeResult)
	if *flagSaveToSpanner != "" {
		log.Print("saving to spanner")
		if *flagDuration == 0 || *flagDateTo == "" {
			panic("duration and date-to are required to store to DB")
		}
		var dateTo civil.Date
		if dateTo, err = civil.ParseDate(*flagDateTo); err != nil {
			panic(fmt.Sprintf("failed to parse time_to: %s", err.Error()))
		}
		coverage, _, _ := mergeResultsToCoverage(mergeResult)
		saveToSpanner(context.Background(), *flagProjectID, coverage,
			&DBRecord{
				Namespace: *flagNamespace,
				Repo:      *flagRepo,
				Commit:    *flagCommit,
				Duration:  *flagDuration,
				DateTo:    dateTo,
			},
			*flagTotalRows,
		)
	}
}

func printMergeResult(mergeResult map[string]*covermerger.MergeResult) {
	totalLostFrames := map[covermerger.RepoBranchCommit]int64{}
	coverage, totalInstrumentedLines, totalCoveredLines := mergeResultsToCoverage(mergeResult)
	keys := maps.Keys(coverage)
	sort.Strings(keys)
	for _, fileName := range keys {
		lineStat := mergeResult[fileName]
		for rbc, lostFrames := range lineStat.LostFrames {
			log.Printf("\t[warn] lost %d frames from rbc(%s, %s, %s)",
				lostFrames, rbc.Repo, rbc.Branch, rbc.Commit)
			totalLostFrames[rbc] += lostFrames
		}
		printCoverage(fileName, coverage[fileName].Instrumented, coverage[fileName].Covered)
	}
	printCoverage("total", totalInstrumentedLines, totalCoveredLines)
	for rbc, lostFrames := range totalLostFrames {
		log.Printf("\t[warn] lost %d frames from rbc(%s, %s, %s)",
			lostFrames, rbc.Repo, rbc.Branch, rbc.Commit)
		totalLostFrames[rbc] += lostFrames
	}
}

func printCoverage(target string, instrumented, covered int64) {
	coverage := 0.0
	if instrumented != 0 {
		coverage = float64(covered) / float64(instrumented)
	}
	fmt.Printf("%s,%d,%d,%.2f%%\n",
		target, instrumented, covered, coverage*100)
}

type Coverage struct {
	Instrumented int64
	Covered      int64
}

func mergeResultsToCoverage(mergedCoverage map[string]*covermerger.MergeResult,
) (map[string]*Coverage, int64, int64) {
	res := make(map[string]*Coverage)
	var totalInstrumented, totalCovered int64
	for fileName, lineStat := range mergedCoverage {
		if !lineStat.FileExists {
			continue
		}
		var instrumented, covered int64
		for _, lineHitCount := range lineStat.HitCounts {
			instrumented++
			if lineHitCount > 0 {
				covered++
			}
		}
		res[fileName] = &Coverage{
			Instrumented: instrumented,
			Covered:      covered,
		}
		totalInstrumented += instrumented
		totalCovered += covered
	}
	return res, totalInstrumented, totalCovered
}
