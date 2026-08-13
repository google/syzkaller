// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"cloud.google.com/go/civil"
	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/coveragedb"
	"github.com/google/syzkaller/pkg/covermerger"
	"github.com/google/syzkaller/pkg/gcs"
	"github.com/google/syzkaller/pkg/log"
	_ "github.com/google/syzkaller/pkg/subsystem/lists"
	"github.com/google/syzkaller/pkg/tool"
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
	flagDashboardKey        = flag.String("dashboard-key", "", "[optional] dashboard key for dashapi auth")
	flagSrcProvider         = flag.String("provider", "git-clone", "[optional] git-clone or web-git")
	flagFilePathPrefix      = flag.String("file-path-prefix", "", "[optional] kernel file path prefix")
	flagToGCS               = flag.String("to-gcs", "", "[optional] gcs destination to save jsonl to")
	flagRawCoverageDir      = flag.String("raw-coverage-dir", "",
		"[optional] directory containing local *.jsonl.gz raw coverage files")
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

func getGitHead(dir string) string {
	cmd := exec.Command("git", "-C", dir, "rev-parse", "HEAD")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func initLocalRecords(dir, repo, commit string) (io.ReadCloser, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.jsonl.gz"))
	if err != nil || len(files) == 0 {
		return nil, fmt.Errorf("no coverage files found in %s: %w", dir, err)
	}

	type recordKey struct {
		filePath string
		funcName string
		sl       int
		manager  string
	}

	hits := make(map[recordKey]int)

	type rawRecord struct {
		FilePath string `json:"file_path"`
		FuncName string `json:"func_name"`
		SL       int    `json:"sl"`
		HitCount int    `json:"hit_count"`
	}

	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			continue
		}
		gz, err := gzip.NewReader(f)
		if err != nil {
			f.Close()
			continue
		}

		manager := "syz-manager-0"
		base := filepath.Base(file)
		if _, rest, ok := strings.Cut(base, "-manager-"); ok {
			idxPart, _, _ := strings.Cut(rest, "-")
			manager = fmt.Sprintf("syz-manager-%s", idxPart)
		}

		dec := json.NewDecoder(gz)
		for {
			var r rawRecord
			if err := dec.Decode(&r); err != nil {
				break
			}
			if r.HitCount <= 0 {
				continue
			}
			cleanPath := r.FilePath
			if _, after, ok := strings.Cut(cleanPath, "tmp/kernel-build/kernel/"); ok {
				cleanPath = after
			} else if _, after, ok := strings.Cut(cleanPath, "/kernel/"); ok {
				cleanPath = after
			}
			key := recordKey{
				filePath: cleanPath,
				funcName: r.FuncName,
				sl:       r.SL,
				manager:  manager,
			}
			hits[key] += r.HitCount
		}
		gz.Close()
		f.Close()
	}

	fileKeys := make(map[string][]recordKey)
	for k := range hits {
		fileKeys[k.filePath] = append(fileKeys[k.filePath], k)
	}
	sortedFiles := slices.Sorted(maps.Keys(fileKeys))

	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		cw := csv.NewWriter(pw)
		defer cw.Flush()

		_ = cw.Write([]string{
			covermerger.KeyKernelRepo,
			covermerger.KeyKernelCommit,
			covermerger.KeyFilePath,
			covermerger.KeyFuncName,
			covermerger.KeyStartLine,
			covermerger.KeyHitCount,
			covermerger.KeyManager,
		})

		for _, file := range sortedFiles {
			for _, k := range fileKeys[file] {
				_ = cw.Write([]string{
					repo,
					commit,
					k.filePath,
					k.funcName,
					strconv.Itoa(k.sl),
					strconv.Itoa(hits[k]),
					k.manager,
				})
			}
		}
	}()

	return pr, nil
}

func do() error {
	defer tool.Init()()
	if *flagCommit == "HEAD" && *flagRepo != "" {
		if head := getGitHead(*flagRepo); head != "" {
			*flagCommit = head
		}
	}
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
	var csvReader io.ReadCloser
	if *flagRawCoverageDir != "" {
		csvReader, err = initLocalRecords(*flagRawCoverageDir, *flagRepo, *flagCommit)
		if err != nil {
			panic(fmt.Sprintf("failed to initLocalRecords: %v", err.Error()))
		}
	} else {
		csvReader, err = covermerger.InitNsRecords(context.Background(),
			*flagNamespace,
			*flagFilePathPrefix,
			"",
			dateFrom,
			dateTo,
		)
		if err != nil {
			panic(fmt.Sprintf("failed to dbReader.InitNsRecords: %v", err.Error()))
		}
	}
	defer csvReader.Close()
	var wc io.WriteCloser
	url := *flagToGCS
	if *flagToDashAPI != "" {
		dash, err := dashapi.New(*flagDashboardClientName, *flagToDashAPI, *flagDashboardKey)
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
		wc, err = gcsClient.FileWriter(strings.TrimPrefix(url, "gs://"), "", "")
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
	if wc != nil {
		if err := wc.Close(); err != nil {
			return fmt.Errorf("wc.Close: %w", err)
		}
	}
	printCoverage(totalInstrumentedLines, totalCoveredLines)
	if *flagToDashAPI != "" {
		// Merging may take hours. It is better to create new connection instead of reuse.
		dash, err := dashapi.New(*flagDashboardClientName, *flagToDashAPI, *flagDashboardKey)
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
