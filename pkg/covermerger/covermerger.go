// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package covermerger

import (
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"

	"github.com/google/syzkaller/pkg/coveragedb"
	"github.com/google/syzkaller/pkg/log"
	"golang.org/x/exp/maps"
	"golang.org/x/sync/errgroup"
)

const (
	KeyKernelRepo   = "kernel_repo"
	KeyKernelCommit = "kernel_commit"
	KeyFilePath     = "file_path"
	KeyFuncName     = "func_name"
	KeyStartLine    = "sl"
	KeyHitCount     = "hit_count"
	KeyManager      = "manager"
)

type FileRecord struct {
	FilePath string
	FuncName string
	RepoCommit
	StartLine int
	HitCount  int
	Manager   string
}

type RepoCommit struct {
	Repo   string
	Commit string
}

type MergeResult struct {
	HitCounts   map[int]int64
	FileExists  bool
	LineDetails map[int][]*FileRecord
}

type FileCoverageMerger interface {
	Add(record *FileRecord)
	Result() *MergeResult
}

// MergeCSVWriteJSONL mergers input CSV and generates JSONL records.
// The amount of lines generated is [count(managers)+1] * [count(kernel_files)].
// Returns (totalInstrumentedLines, totalCoveredLines, error).
func MergeCSVWriteJSONL(config *Config, descr *coveragedb.HistoryRecord, csvReader io.Reader, w io.Writer,
) (int, int, error) {
	eg, c := errgroup.WithContext(context.Background())
	mergeResults := make(chan *FileMergeResult)
	eg.Go(func() error {
		defer close(mergeResults)
		if err := MergeCSVData(c, config, csvReader, mergeResults); err != nil {
			return fmt.Errorf("covermerger.MergeCSVData: %w", err)
		}
		return nil
	})
	var totalInstrumentedLines, totalCoveredLines int
	eg.Go(func() error {
		var encoder *json.Encoder
		if w != nil {
			gzw := gzip.NewWriter(w)
			defer gzw.Close()
			encoder = json.NewEncoder(gzw)
		}
		if encoder != nil {
			if err := encoder.Encode(descr); err != nil {
				return fmt.Errorf("encoder.Encode(MergedCoverageDescription): %w", err)
			}
		}
		for fileMergeResult := range mergeResults {
			dashCoverageRecords, dashFuncLines := mergedCoverageRecords(fileMergeResult)
			if encoder != nil {
				for _, record := range dashFuncLines {
					if err := encoder.Encode(coveragedb.JSONLWrapper{FL: record}); err != nil {
						return fmt.Errorf("encoder.Encode(FuncLines): %w", err)
					}
				}
				for _, record := range dashCoverageRecords {
					if err := encoder.Encode(coveragedb.JSONLWrapper{MCR: record}); err != nil {
						return fmt.Errorf("encoder.Encode(MergedCoverageRecord): %w", err)
					}
				}
			}
			for _, hitCount := range fileMergeResult.HitCounts {
				totalInstrumentedLines++
				if hitCount > 0 {
					totalCoveredLines++
				}
			}
		}
		return nil
	})
	if err := eg.Wait(); err != nil {
		return 0, 0, fmt.Errorf("eg.Wait: %w", err)
	}
	return totalInstrumentedLines, totalCoveredLines, nil
}

const allManagers = "*"

func mergedCoverageRecords(fmr *FileMergeResult) ([]*coveragedb.MergedCoverageRecord, []*coveragedb.FuncLines) {
	if !fmr.FileExists {
		return nil, nil
	}
	lines := maps.Keys(fmr.HitCounts)
	slices.Sort(lines)
	mgrStat := make(map[string]*coveragedb.Coverage)
	mgrStat[allManagers] = &coveragedb.Coverage{}

	funcLines := map[string]*coveragedb.FuncLines{}
	for _, line := range lines {
		mgrStat[allManagers].AddLineHitCount(line, fmr.HitCounts[line])
		managerHitCounts := map[string]int64{}
		var srcFuncs []string
		for _, lineDetail := range fmr.LineDetails[line] {
			srcFuncs = append(srcFuncs, lineDetail.FuncName)
			manager := lineDetail.Manager
			managerHitCounts[manager] += int64(lineDetail.HitCount)
		}
		if funcName := bestFuncName(srcFuncs); funcName != "" {
			if _, ok := funcLines[funcName]; !ok {
				funcLines[funcName] = &coveragedb.FuncLines{
					FilePath: fmr.FilePath,
					FuncName: funcName,
				}
			}
			funcLines[funcName].Lines = append(funcLines[funcName].Lines, int64(line))
		}
		for manager, managerHitCount := range managerHitCounts {
			if _, ok := mgrStat[manager]; !ok {
				mgrStat[manager] = &coveragedb.Coverage{}
			}
			mgrStat[manager].AddLineHitCount(line, managerHitCount)
		}
	}

	res := []*coveragedb.MergedCoverageRecord{}
	for managerName, managerCoverage := range mgrStat {
		res = append(res, &coveragedb.MergedCoverageRecord{
			Manager:  managerName,
			FilePath: fmr.FilePath,
			FileData: managerCoverage,
		})
	}
	return res, maps.Values(funcLines)
}

// bestFuncName selects the most frequent function from the list of candidates.
// If a function was renamed during the collection period, we have to pick one name to display the coverage.
//
// The better alternative is to get the function name from the C code. But it looks more complex for now.
func bestFuncName(names []string) string {
	stat := map[string]int{}
	for _, name := range names {
		stat[name]++
	}
	bestName := ""
	bestCount := 0
	for name, count := range stat {
		if name != "" && count > bestCount {
			bestName = name
			bestCount = count
		}
	}
	return bestName
}

func batchFileData(c *Config, targetFilePath string, records []*FileRecord) (*MergeResult, error) {
	log.Logf(1, "processing %d records for %s", len(records), targetFilePath)
	repoCommitsMap := make(map[RepoCommit]bool)
	for _, record := range records {
		repoCommitsMap[record.RepoCommit] = true
	}
	repoCommitsMap[c.Base] = true
	repoCommits := maps.Keys(repoCommitsMap)
	fvs, err := c.FileVersProvider.GetFileVersions(targetFilePath, repoCommits...)
	if err != nil {
		return nil, fmt.Errorf("failed to getFileVersions: %w", err)
	}
	merger := makeFileLineCoverMerger(fvs, c.Base)
	for _, record := range records {
		merger.Add(record)
	}
	return merger.Result(), nil
}

func makeRecord(fields, schema []string) (*FileRecord, error) {
	if len(fields) != len(schema) {
		return nil, errors.New("fields size and schema size are not equal")
	}
	record := &FileRecord{}
	for i, val := range fields {
		key := schema[i]
		var err error
		switch key {
		case KeyFilePath:
			record.FilePath = val
		case KeyFuncName:
			record.FuncName = val
		case KeyKernelRepo:
			record.Repo = val
		case KeyKernelCommit:
			record.Commit = val
		case KeyStartLine:
			record.StartLine, err = readIntField(key, val)
		case KeyHitCount:
			record.HitCount, err = readIntField(key, val)
		case KeyManager:
			record.Manager = val
		}
		if err != nil {
			return nil, err
		}
	}
	return record, nil
}

func readIntField(field, val string) (int, error) {
	res, err := strconv.Atoi(val)
	if err != nil {
		return -1, fmt.Errorf("failed to Atoi(%s) %s: %w", val, field, err)
	}
	return res, nil
}

type Config struct {
	Jobs             int
	Workdir          string
	skipRepoClone    bool
	Base             RepoCommit
	FileVersProvider FileVersProvider
}

func isSchema(fields, schema []string) bool {
	if len(fields) != len(schema) {
		return false
	}
	for i := 0; i < len(fields); i++ {
		if fields[i] != schema[i] {
			return false
		}
	}
	return true
}

type FileMergeResult struct {
	FilePath string
	*MergeResult
}

func MergeCSVData(c context.Context, config *Config, reader io.Reader, results chan<- *FileMergeResult) error {
	var schema []string
	csvReader := csv.NewReader(reader)
	if fields, err := csvReader.Read(); err != nil {
		return fmt.Errorf("failed to read schema: %w", err)
	} else {
		schema = fields
	}
	errStreamChan := make(chan error, 2)
	recordsChan := make(chan *FileRecord)
	go func() {
		defer close(recordsChan)
		defer func() { errStreamChan <- nil }()
		for {
			fields, err := csvReader.Read()
			if err == io.EOF {
				break
			}
			if err != nil {
				errStreamChan <- fmt.Errorf("failed to read CSV line: %w", err)
				return
			}
			if isSchema(fields, schema) {
				// The input may be the merged CVS files with multiple schemas.
				continue
			}
			record, err := makeRecord(fields, schema)
			if err != nil {
				errStreamChan <- fmt.Errorf("makeRecord: %w", err)
				return
			}
			select {
			case <-c.Done():
				return
			case recordsChan <- record:
			}
		}
	}()
	errMerging := mergeChanData(c, config, recordsChan, results)
	errStream := <-errStreamChan
	if errMerging != nil || errStream != nil {
		return fmt.Errorf("errors merging stream data:\nmerger err: %w\nstream reader err: %w",
			errMerging, errStream)
	}
	return nil
}

type FileRecords struct {
	fileName string
	records  []*FileRecord
}

func mergeChanData(c context.Context, cfg *Config, recordChan <-chan *FileRecord, results chan<- *FileMergeResult,
) error {
	g := errgroup.Group{}
	frecordChan := groupFileRecords(recordChan, c)

	for i := 0; i < cfg.Jobs; i++ {
		g.Go(func() error {
			for frecord := range frecordChan {
				mr, err := batchFileData(cfg, frecord.fileName, frecord.records)
				if err != nil {
					return fmt.Errorf("failed to batchFileData(%s): %w", frecord.fileName, err)
				}
				select {
				case <-c.Done():
					return nil
				case results <- &FileMergeResult{
					FilePath:    frecord.fileName,
					MergeResult: mr}:
				}
			}
			return nil
		})
	}
	return g.Wait()
}

func groupFileRecords(recordChan <-chan *FileRecord, ctx context.Context) chan FileRecords {
	frecordChan := make(chan FileRecords)
	go func() {
		defer close(frecordChan)
		targetFile := ""
		var records []*FileRecord
		for record := range recordChan {
			select {
			case <-ctx.Done():
				return
			default:
			}
			curTargetFile := record.FilePath
			if targetFile == "" {
				targetFile = curTargetFile
			}
			if curTargetFile != targetFile {
				select {
				case <-ctx.Done():
					return
				case frecordChan <- FileRecords{
					fileName: targetFile,
					records:  records}:
				}
				records = nil
				targetFile = curTargetFile
			}
			records = append(records, record)
		}
		select {
		case <-ctx.Done():
		case frecordChan <- FileRecords{
			fileName: targetFile,
			records:  records}:
		}
	}()
	return frecordChan
}
