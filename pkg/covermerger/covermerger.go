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

func (fr FileRecord) Frame() (*Frame, error) {
	f := &Frame{}
	var err error
	if f.StartLine, err = strconv.Atoi(fr[KeyStartLine]); err != nil {
		return nil, fmt.Errorf("failed to Atoi(%s): %w", fr[KeyStartLine], err)
	}
	return f, nil
}

func (fr FileRecord) HitCount() (int, error) {
	if hitCount, err := strconv.Atoi(fr[KeyHitCount]); err != nil {
		return 0, fmt.Errorf("failed to Atoi(%s): %w", fr[KeyHitCount], err)
	} else {
		return hitCount, nil
	}
}

type MergeResult struct {
	HitCounts  map[int]int
	FileExists bool
	LostFrames map[RepoBranchCommit]int64
}

type FileCoverageMerger interface {
	AddRecord(rbc RepoBranchCommit, f *Frame, hitCount int)
	Result() *MergeResult
}

func batchFileData(c *Config, targetFilePath string, records FileRecords, processedFiles map[string]struct{},
) (*MergeResult, error) {
	log.Printf("processing %d records for %s", len(records), targetFilePath)
	if _, exists := processedFiles[targetFilePath]; exists {
		return nil, fmt.Errorf("file was already processed, check the input ordering")
	}
	processedFiles[targetFilePath] = struct{}{}
	repoBranchCommitsMap := make(map[RepoBranchCommit]bool)
	for _, record := range records {
		repoBranchCommitsMap[record.RepoBranchCommit()] = true
	}
	repoBranchCommitsMap[c.Base] = true
	repoBranchCommits := maps.Keys(repoBranchCommitsMap)
	getFiles := getFileVersions
	if c.getFileVersionsMock != nil {
		getFiles = c.getFileVersionsMock
	}
	fvs, err := getFiles(c, targetFilePath, repoBranchCommits)
	if err != nil {
		return nil, fmt.Errorf("failed to getFileVersions: %w", err)
	}
	merger := makeFileLineCoverMerger(fvs, c.Base)
	for _, record := range records {
		var f *Frame
		if f, err = record.Frame(); err != nil {
			return nil, fmt.Errorf("error parsing records: %w", err)
		}
		var hitCount int
		if hitCount, err = record.HitCount(); err != nil {
			return nil, fmt.Errorf("error parsing records: %w", err)
		}
		merger.AddRecord(
			record.RepoBranchCommit(),
			f,
			hitCount)
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
	Workdir             string
	skipRepoClone       bool
	Base                RepoBranchCommit
	getFileVersionsMock func(*Config, string, []RepoBranchCommit) (fileVersions, error)
	repoCache           repoCache
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
	mergeResult, errMerging := mergeChanData(config, recordsChan)
	errStdinRead := <-errStdinReadChan
	if errMerging != nil || errStdinRead != nil {
		return nil, fmt.Errorf("errors merging stdin data:\nmerger err: %w\nstdin reader err: %w",
			errMerging, errStdinRead)
	}
	return mergeResult, nil
}

func mergeChanData(c *Config, recordsChan <-chan FileRecord) (map[string]*MergeResult, error) {
	stat := make(map[string]*MergeResult)
	targetFile := ""
	var records []FileRecord
	processedFiles := map[string]struct{}{}
	for record := range recordsChan {
		curTargetFile := record[KeyFilePath]
		if targetFile == "" {
			targetFile = curTargetFile
		}
		if curTargetFile != targetFile {
			var err error
			if stat[targetFile], err = batchFileData(c, targetFile, records, processedFiles); err != nil {
				return nil, fmt.Errorf("failed to batchFileData(%s): %w", targetFile, err)
			}
			records = nil
			targetFile = curTargetFile
		}
		records = append(records, record)
	}
	if records != nil {
		var err error
		if stat[targetFile], err = batchFileData(c, targetFile, records, processedFiles); err != nil {
			return nil, fmt.Errorf("failed to batchFileData(%s): %w", targetFile, err)
		}
	}

	return stat, nil
}
