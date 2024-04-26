// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package covermerger

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"

	"golang.org/x/exp/maps"
)

const (
	keyKernelRepo   = "kernel_repo"
	keyKernelBranch = "kernel_branch"
	keyKernelCommit = "kernel_commit"
	keyFilePath     = "file_path"
	keyStartLine    = "sl"
	keyStartCol     = "sc"
	keyEndLine      = "el"
	keyEndCol       = "ec"
	keyHitCount     = "hit_count"
	keyArch         = "arch"
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
		fr[keyKernelRepo],
		fr[keyKernelBranch],
		fr[keyKernelCommit],
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
	if f.StartCol, err = strconv.Atoi(fr[keyStartCol]); err != nil {
		panic(fmt.Sprintf("failed to Atoi(%s)", fr[keyStartCol]))
	}
	if f.StartLine, err = strconv.Atoi(fr[keyStartLine]); err != nil {
		panic(fmt.Sprintf("failed to Atoi(%s)", fr[keyStartLine]))
	}
	if f.EndCol, err = strconv.Atoi(fr[keyEndCol]); err != nil {
		panic(fmt.Sprintf("failed to Atoi(%s)", fr[keyEndCol]))
	}
	if f.EndLine, err = strconv.Atoi(fr[keyEndLine]); err != nil {
		panic(fmt.Sprintf("failed to Atoi(%s)", fr[keyEndLine]))
	}
	return f
}

func (fr FileRecord) HitCount() int {
	if hitCount, err := strconv.Atoi(fr[keyHitCount]); err != nil {
		panic(fmt.Sprintf("failed to Atoi(%s)", fr[keyHitCount]))
	} else {
		return hitCount
	}
}

func (fr FileRecord) Arch() string {
	return fr[keyArch]
}

type MergeResult struct {
	HitCounts  map[int]int
	FileExists bool
}

type FileCoverageMerger interface {
	AddRecord(rbc RepoBranchCommit, arch string, f Frame, hitCount int)
	Result() *MergeResult
}

func batchFileData(c *Config, targetFilePath string, records FileRecords, base RepoBranchCommit,
) (*MergeResult, error) {
	repoBranchCommitsMap := make(map[RepoBranchCommit]bool)
	for _, record := range records {
		repoBranchCommitsMap[record.RepoBranchCommit()] = true
	}
	repoBranchCommitsMap[base] = true
	repoBranchCommits := maps.Keys(repoBranchCommitsMap)
	fileVersions, err := getFileVersions(c, targetFilePath, repoBranchCommits)
	if err != nil {
		return nil, fmt.Errorf("failed to getFileVersions: %w", err)
	}
	merger := makeFileLineCoverMerger(fileVersions, base)
	for _, record := range records {
		merger.AddRecord(
			record.RepoBranchCommit(),
			record.Arch(),
			record.Frame(),
			record.HitCount())
	}
	return merger.Result(), nil
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

type Config struct {
	Workdir       string
	skipRepoClone bool
}

func AggregateStreamData(c *Config, stream io.Reader, base RepoBranchCommit,
) (map[string]*MergeResult, error) {
	stat := make(map[string]*MergeResult)
	var schema []string
	targetFile := ""
	var records FileRecords
	csvReader := csv.NewReader(stream)
	if fields, err := csvReader.Read(); err != nil {
		return nil, fmt.Errorf("failed to read schema: %w", err)
	} else {
		schema = fields
	}
	for {
		fields, err := csvReader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read CSV line: %w", err)
		}
		record := makeRecord(fields, schema)
		curTargetFile := record[keyFilePath]
		if targetFile == "" {
			targetFile = curTargetFile
		}
		if curTargetFile != targetFile {
			if stat[targetFile], err = batchFileData(c, targetFile, records, base); err != nil {
				return nil, fmt.Errorf("failed to batchFileData(%s): %w", targetFile, err)
			}
			records = nil
			targetFile = curTargetFile
		}
		records = append(records, record)
	}
	if records != nil {
		var err error
		if stat[targetFile], err = batchFileData(c, targetFile, records, base); err != nil {
			return nil, fmt.Errorf("failed to batchFileData(%s): %w", targetFile, err)
		}
	}

	return stat, nil
}
