// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"flag"
	"fmt"
	"runtime"
	"slices"
	"sort"

	"cloud.google.com/go/civil"
	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/coveragedb"
	"github.com/google/syzkaller/pkg/covermerger"
	"github.com/google/syzkaller/pkg/log"
	_ "github.com/google/syzkaller/pkg/subsystem/lists"
	"golang.org/x/exp/maps"
)

var (
	flagWorkdir = flag.String("workdir", "workdir-cover-aggregation",
		"[optional] used to clone repos")
	flagRepo                = flag.String("repo", "", "[required] repo to be used as an aggregation point")
	flagCommit              = flag.String("commit", "", "[required] commit hash to be used as an aggregation point")
	flagNamespace           = flag.String("namespace", "upstream", "[optional] target namespace")
	flagDuration            = flag.Int64("duration", 0, "[optional] used to mark DB records")
	flagDateTo              = flag.String("date-to", "", "[optional] used to mark DB records")
	flagTotalRows           = flag.Int64("total-rows", 0, "[optional] source size, is used for version contol")
	flagToDashAPI           = flag.String("to-dashapi", "", "[optional] dashapi address")
	flagDashboardClientName = flag.String("dashboard-client-name", "coverage-merger", "[optional]")
	flagSrcProvider         = flag.String("provider", "git-clone", "[optional] git-clone or web-git")
	flagFilePathPrefix      = flag.String("file-path-prefix", "", "[optional] kernel file path prefix")
)

func makeProvider() covermerger.FileVersProvider {
	switch *flagSrcProvider {
	case "git-clone":
		return covermerger.MakeMonoRepo(*flagWorkdir)
	case "web-git":
		return covermerger.MakeWebGit(nil)
	default:
		panic(fmt.Sprintf("unknown provider %v", *flagSrcProvider))
	}
}

func main() {
	flag.Parse()
	config := &covermerger.Config{
		Jobs:    runtime.NumCPU(),
		Workdir: *flagWorkdir,
		Base: covermerger.RepoCommit{
			Repo:   *flagRepo,
			Commit: *flagCommit,
		},
		FileVersProvider: makeProvider(),
	}
	var dateFrom, dateTo civil.Date
	var err error
	if dateTo, err = civil.ParseDate(*flagDateTo); err != nil {
		panic(fmt.Sprintf("failed to parse time_to: %s", err.Error()))
	}
	dateFrom = dateTo.AddDays(-int(*flagDuration))
	dbReader := covermerger.MakeBQCSVReader()
	if err = dbReader.InitNsRecords(context.Background(),
		*flagNamespace,
		*flagFilePathPrefix,
		"",
		dateFrom,
		dateTo,
	); err != nil {
		panic(fmt.Sprintf("failed to dbReader.InitNsRecords: %v", err.Error()))
	}
	defer dbReader.Close()
	csvReader, errReader := dbReader.Reader()
	if errReader != nil {
		panic(fmt.Sprintf("failed to dbReader.Reader: %v", errReader.Error()))
	}
	mergeResult, errMerge := covermerger.MergeCSVData(config, csvReader)
	if errMerge != nil {
		panic(errMerge)
	}

	coverage, totalInstrumentedLines, totalCoveredLines := mergeResultsToCoverage(mergeResult)
	printCoverage(totalInstrumentedLines, totalCoveredLines)
	managers := maps.Keys(coverage)
	sort.Strings(managers)
	fmt.Printf("merged signals for the following managers: %v\n", managers)
	if *flagToDashAPI != "" {
		if rowsCreated, err := saveCoverage(*flagToDashAPI, *flagDashboardClientName, &dashapi.MergedCoverage{
			Namespace: *flagNamespace,
			Repo:      *flagRepo,
			Commit:    *flagCommit,
			Duration:  *flagDuration,
			DateTo:    dateTo,
			TotalRows: *flagTotalRows,
			FileData:  coverage,
		}); err != nil {
			log.Fatalf("failed to saveCoverage: %v", err)
		} else {
			fmt.Printf("created %d DB rows\n", rowsCreated)
		}
	}
}

func saveCoverage(dashboard, clientName string, d *dashapi.MergedCoverage) (int, error) {
	dash, err := dashapi.New(clientName, dashboard, "")
	if err != nil {
		return 0, fmt.Errorf("dashapi.New: %w", err)
	}
	return dash.SaveCoverage(&dashapi.SaveCoverageReq{
		Coverage: d,
	})
}

func printCoverage(instrumented, covered int64) {
	coverage := 0.0
	if instrumented != 0 {
		coverage = float64(covered) / float64(instrumented)
	}
	fmt.Printf("total instrumented(%d), covered(%d), %.2f%%\n",
		instrumented, covered, coverage*100)
}

const allManagers = "*"

// Returns per manager merge result, total instrumented and total covered lines.
func mergeResultsToCoverage(mergedCoverage map[string]*covermerger.MergeResult,
) (coveragedb.ManagersCoverage, int64, int64) {
	res := make(coveragedb.ManagersCoverage)
	res[allManagers] = make(coveragedb.ManagerCoverage)
	var totalInstrumented, totalCovered int64
	for fileName, lineStat := range mergedCoverage {
		if !lineStat.FileExists {
			continue
		}
		if _, ok := res[allManagers][fileName]; !ok {
			res[allManagers][fileName] = &coveragedb.Coverage{}
		}

		lines := maps.Keys(lineStat.HitCounts)
		slices.Sort(lines)

		for _, line := range lines {
			res[allManagers][fileName].AddLineHitCount(line, lineStat.HitCounts[line])
			managerHitCounts := map[string]int{}
			for _, lineDetail := range lineStat.LineDetails[line] {
				manager := lineDetail.Manager
				managerHitCounts[manager] += lineDetail.HitCount
			}
			for manager, managerHitCount := range managerHitCounts {
				if _, ok := res[manager]; !ok {
					res[manager] = make(coveragedb.ManagerCoverage)
				}
				if _, ok := res[manager][fileName]; !ok {
					res[manager][fileName] = &coveragedb.Coverage{}
				}
				res[manager][fileName].AddLineHitCount(line, managerHitCount)
			}
		}
		totalInstrumented += res[allManagers][fileName].Instrumented
		totalCovered += res[allManagers][fileName].Covered
	}
	return res, totalInstrumented, totalCovered
}
