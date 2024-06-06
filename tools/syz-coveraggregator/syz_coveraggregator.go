// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"

	"cloud.google.com/go/civil"
	"github.com/google/syzkaller/pkg/covermerger"
	"golang.org/x/exp/maps"
)

func baseTypeFromString(name string) (int, error) {
	switch name {
	case "manual":
		return covermerger.BaseManual, nil
	case "lastupdated":
		return covermerger.BaseLastUpdated, nil
	default:
		return -1, fmt.Errorf("unexpected baseType(manual|lasupdated): %s", name)
	}
}

func BaseIsWellSpecifiedOrExit(flagBaseType, flagRepo, flagBranch, flagCommit *string) {
	baseType, err := baseTypeFromString(*flagBaseType)
	if err != nil {
		log.Print(err.Error())
		os.Exit(1)
	}
	switch baseType {
	case covermerger.BaseManual:
		if *flagRepo == "" || *flagBranch == "" || *flagCommit == "" {
			log.Print("-repo -branch and -commit flags are required by '-base-type manual'")
			os.Exit(1)
		}
	case covermerger.BaseLastUpdated:
		if *flagCommit != "" || *flagBranch != "" {
			log.Printf("[ERROR] '-base-type lastupdated can't be used with -branch or -commit")
			os.Exit(1)
		}
		if *flagRepo == "" {
			log.Printf("[WARNING] '-base-type lastupdated w/o '-repo' is very slow because do 'git log for every file'")
		}
	}
}

func main() {
	flagWorkdir := flag.String("workdir", "workdir-cover-aggregation",
		"[optional] used to clone repos")
	flagCleanWorkdir := flag.Bool("clean-workdir", false,
		"[optional] cleans workdir before start")
	flagBaseType := flag.String("base-type", "manual",
		"commit to be used as a base. Can be manual/lastupdated and works per fileF")
	flagRepo := flag.String("repo", "", "[required] repo to be used as an aggregation point")
	flagBranch := flag.String("branch", "", "[required] branch to be used as an aggregation point")
	flagCommit := flag.String("commit", "", "[required] commit hash to be used as an aggregation point")
	flagNamespace := flag.String("namespace", "upstream", "[optional] target namespace")
	flagDateFrom := flag.String("date-from", "", "[optional] used to mark DB records")
	flagDateTo := flag.String("date-to", "", "[optional] used to mark DB records")
	flagSaveToSpanner := flag.String("save-to-spanner", "", "[optional] save aggregation to spanner")

	flag.Parse()
	BaseIsWellSpecifiedOrExit(flagBaseType, flagRepo, flagBranch, flagCommit)

	baseType, _ := baseTypeFromString(*flagBaseType)
	config := &covermerger.Config{
		Workdir:  *flagWorkdir,
		BaseType: baseType,
		Base: covermerger.RepoBranchCommit{
			Repo:   *flagRepo,
			Branch: *flagBranch,
			Commit: *flagCommit,
		},
	}

	if *flagCleanWorkdir {
		if err := os.RemoveAll(*flagWorkdir); err != nil {
			panic("failed to clean workdir " + *flagWorkdir)
		}
	}

	mergeResult := commandProcessStdin(config, *flagRepo, *flagBranch, *flagCommit)
	printMergeResult(mergeResult)

	if *flagSaveToSpanner != "" {
		log.Print("saving to spanner")
		if *flagDateFrom == "" || *flagDateTo == "" {
			panic("date-from and date-to are required to store to DB")
		}
		var err error
		var dateFrom, dateTo civil.Date
		if dateFrom, err = civil.ParseDate(*flagDateFrom); err != nil {
			panic(fmt.Sprintf("failed to parse time_from: %s", err.Error()))
		}
		if dateTo, err = civil.ParseDate(*flagDateTo); err != nil {
			panic(fmt.Sprintf("failed to parse time_to: %s", err.Error()))
		}
		saveToSpanner(context.Background(), mergeResult, *flagRepo, *flagCommit, *flagNamespace, dateFrom, dateTo)
	}
}

func commandProcessStdin(config *covermerger.Config, flagRepo, flagBranch, flagCommit string,
) map[string]*covermerger.MergeResult {
	mergedCoverage, err := covermerger.MergeCSVData(config, os.Stdin)
	if err != nil {
		panic(err)
	}
	return mergedCoverage
}

func printMergeResult(mergedCoverage map[string]*covermerger.MergeResult) {
	totalInstrumentedLines := 0
	totalCoveredLines := 0
	keys := maps.Keys(mergedCoverage)
	sort.Strings(keys)
	for _, fileName := range keys {
		lineStat := mergedCoverage[fileName]
		instrumentedLines := 0
		coveredLines := 0
		if !lineStat.FileExists {
			continue
		}
		for _, lineHitCount := range lineStat.HitCounts {
			instrumentedLines++
			if lineHitCount > 0 {
				coveredLines++
			}
		}
		printCoverage(fileName, instrumentedLines, coveredLines)
		totalInstrumentedLines += instrumentedLines
		totalCoveredLines += coveredLines
	}
	printCoverage("total", totalInstrumentedLines, totalCoveredLines)
}

func printCoverage(target string, instrumented, covered int) {
	coverage := 0.0
	if instrumented != 0 {
		coverage = float64(covered) / float64(instrumented)
	}
	fmt.Printf("%s,%d,%d,%.2f%%\n",
		target, instrumented, covered, coverage*100)
}
