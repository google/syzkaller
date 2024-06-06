// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package covermerger

import (
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"strconv"

	"golang.org/x/exp/maps"
)

const (
	KeyKernelRepo   = "kernel_repo"
	KeyKernelBranch = "kernel_branch"
	KeyKernelCommit = "kernel_commit"
	KeyFilePath     = "file_path"
	KeyStartLine    = "sl"
	KeyHitCount     = "hit_count"
	KeyArch         = "arch"
)

type FileRecord map[string]string
type FileRecords []FileRecord
type RepoBranchCommit struct {
	Repo   string
	Branch string
	Commit string
}

func (fr FileRecord) RepoBranchCommit() RepoBranchCommit {
	return RepoBranchCommit{
		fr[KeyKernelRepo],
		fr[KeyKernelBranch],
		fr[KeyKernelCommit],
	}
}

type Frame struct {
	StartLine int
	StartCol  int
	EndLine   int
	EndCol    int
}

func (fr FileRecord) Frame() Frame {
	f := Frame{}
	var err error
	if f.StartLine, err = strconv.Atoi(fr[KeyStartLine]); err != nil {
		panic(fmt.Sprintf("failed to Atoi(%s)", fr[KeyStartLine]))
	}
	return f
}

func (fr FileRecord) HitCount() int {
	if hitCount, err := strconv.Atoi(fr[KeyHitCount]); err != nil {
		panic(fmt.Sprintf("failed to Atoi(%s)", fr[KeyHitCount]))
	} else {
		return hitCount
	}
}

func (fr FileRecord) Arch() string {
	return fr[KeyArch]
}

type MergeResult struct {
	HitCounts  map[int]int
	FileExists bool
}

type FileCoverageMerger interface {
	AddRecord(rbc RepoBranchCommit, arch string, f Frame, hitCount int)
	Result() *MergeResult
}

func batchFileData(c *Config, targetFilePath string, records FileRecords,
) (*MergeResult, error) {
	log.Printf("processing %d records for %s", len(records), targetFilePath)
	repoBranchCommitsMap := make(map[RepoBranchCommit]bool)
	for _, record := range records {
		repoBranchCommitsMap[record.RepoBranchCommit()] = true
	}
	if c.BaseType == BaseManual {
		repoBranchCommitsMap[c.Base] = true
	}
	repoBranchCommits := maps.Keys(repoBranchCommitsMap)
	fvs, err := getFileVersions(c, targetFilePath, repoBranchCommits)
	if err != nil {
		return nil, fmt.Errorf("failed to getFileVersions: %w", err)
	}
	base := getBaseRBC(c, targetFilePath, fvs)
	merger := makeFileLineCoverMerger(fvs, base)
	for _, record := range records {
		merger.AddRecord(
			record.RepoBranchCommit(),
			record.Arch(),
			record.Frame(),
			record.HitCount())
	}
	return merger.Result(), nil
}

// getBaseRBC is a base(target) file version selector.
// The easiest strategy is to use some specified commit.
// For the namespace level signals merging we'll select target dynamically.
func getBaseRBC(c *Config, targetFilePath string, fvs fileVersions) RepoBranchCommit {
	switch c.BaseType {
	case BaseManual:
		return c.Base
	case BaseLastUpdated:
		// If repo is not specifies use the much more expensive approach.
		// The base commit is the commit where non-empty target file was last modified.
		if res := freshestRBC(fvs); res != nil {
			return *res
		}
	}
	panic(fmt.Sprintf("failed searching best RBC for file %s", targetFilePath))
}

func makeRecord(fields, schema []string) FileRecord {
	record := make(FileRecord)
	if len(fields) != len(schema) {
		panic("fields size and schema size are not equal")
	}
	for i, v := range fields {
		k := schema[i]
		record[k] = v
	}
	return record
}

const (
	BaseManual = iota
	BaseLastUpdated
)

type Config struct {
	Workdir       string
	skipRepoClone bool
	BaseType      int              // BaseManual, BaseLastUpdated.
	Base          RepoBranchCommit // used by BaseManual
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

func MergeCSVData(config *Config, reader io.Reader) (map[string]*MergeResult, error) {
	var schema []string
	csvReader := csv.NewReader(reader)
	if fields, err := csvReader.Read(); err != nil {
		return nil, fmt.Errorf("failed to read schema: %w", err)
	} else {
		schema = fields
	}
	errStdinReadChan := make(chan error, 1)
	recordsChan := make(chan FileRecord)
	go func() {
		defer close(recordsChan)
		for {
			fields, err := csvReader.Read()
			if err == io.EOF {
				break
			}
			if err != nil {
				errStdinReadChan <- fmt.Errorf("failed to read CSV line: %w", err)
				return
			}
			if isSchema(fields, schema) {
				// The input may be the merged CVS files with multiple schemas.
				continue
			}
			recordsChan <- makeRecord(fields, schema)
		}
		errStdinReadChan <- nil
	}()
	mergeResult, errMerging := MergeChanData(config, recordsChan)
	errStdinRead := <-errStdinReadChan
	if errMerging != nil || errStdinRead != nil {
		return nil, fmt.Errorf("errors merging stdin data:\nmerger err: %w\nstdin reader err: %w",
			errMerging, errStdinRead)
	}
	return mergeResult, nil
}

func MergeChanData(c *Config, recordsChan <-chan FileRecord) (map[string]*MergeResult, error) {
	stat := make(map[string]*MergeResult)
	targetFile := ""
	var records []FileRecord
	for record := range recordsChan {
		curTargetFile := record[KeyFilePath]
		if targetFile == "" {
			targetFile = curTargetFile
		}
		if curTargetFile != targetFile {
			var err error
			if stat[targetFile], err = batchFileData(c, targetFile, records); err != nil {
				return nil, fmt.Errorf("failed to batchFileData(%s): %w", targetFile, err)
			}
			records = nil
			targetFile = curTargetFile
		}
		records = append(records, record)
	}
	if records != nil {
		var err error
		if stat[targetFile], err = batchFileData(c, targetFile, records); err != nil {
			return nil, fmt.Errorf("failed to batchFileData(%s): %w", targetFile, err)
		}
	}

	return stat, nil
}
