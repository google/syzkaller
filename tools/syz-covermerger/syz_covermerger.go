// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"runtime"
	"strings"

	"cloud.google.com/go/civil"
	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/coveragedb"
	"github.com/google/syzkaller/pkg/covermerger"
	"github.com/google/syzkaller/pkg/gcs"
	"github.com/google/syzkaller/pkg/log"
	_ "github.com/google/syzkaller/pkg/subsystem/lists"
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
	flagToGCS               = flag.String("to-gcs", "", "[optional] gcs destination to save jsonl to")
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
	if err := do(); err != nil {
		log.Fatalf("failed to saveCoverage: %v", err.Error())
	}
}

func do() error {
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
	var wc io.WriteCloser
	url := *flagToGCS
	if *flagToDashAPI != "" {
		dash, err := dashapi.New(*flagDashboardClientName, *flagToDashAPI, "")
		if err != nil {
			return fmt.Errorf("dashapi.New: %w", err)
		}
		url, err = dash.CreateUploadURL()
		if err != nil {
			return fmt.Errorf("dash.CreateUploadURL: %w", err)
		}
	}
	if url != "" {
		gcsClient, err := gcs.NewClient(context.Background())
		if err != nil {
			return fmt.Errorf("gcs.NewClient: %w", err)
		}
		defer gcsClient.Close()
		wc, err = gcsClient.FileWriter(strings.TrimPrefix(url, "gs://"))
		if err != nil {
			return fmt.Errorf("gcsClient.FileWriter: %w", err)
		}
	}
	totalInstrumentedLines, totalCoveredLines, err := covermerger.MergeCSVWriteJSONL(
		config,
		&coveragedb.HistoryRecord{
			Namespace: *flagNamespace,
			Repo:      *flagRepo,
			Commit:    *flagCommit,
			Duration:  *flagDuration,
			DateTo:    dateTo,
			TotalRows: *flagTotalRows,
		},
		csvReader,
		wc)
	if err != nil {
		return fmt.Errorf("covermerger.MergeCSVWriteJSONL: %w", err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("wc.Close: %w", err)
	}

	printCoverage(totalInstrumentedLines, totalCoveredLines)
	if *flagToDashAPI != "" {
		// Merging may take hours. It is better to create new connection instead of reuse.
		dash, err := dashapi.New(*flagDashboardClientName, *flagToDashAPI, "")
		if err != nil {
			return fmt.Errorf("dashapi.New: %w", err)
		}
		if rowsCreated, err := dash.SaveCoverage(url); err != nil {
			return fmt.Errorf("dash.SaveCoverage: %w", err)
		} else {
			fmt.Printf("created %d DB rows\n", rowsCreated)
		}
	}
	return nil
}

func printCoverage(instrumented, covered int) {
	coverage := 0.0
	if instrumented != 0 {
		coverage = float64(covered) / float64(instrumented)
	}
	fmt.Printf("total instrumented(%d), covered(%d), %.2f%%\n",
		instrumented, covered, coverage*100)
}
