// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package covermerger

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"strconv"
	"sync"

	"golang.org/x/exp/maps"
	"golang.org/x/sync/errgroup"
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

func batchFileData(c *Config, targetFilePath string, records []FileRecord) (*MergeResult, error) {
	log.Printf("processing %d records for %s", len(records), targetFilePath)
	repoBranchCommitsMap := make(map[RepoBranchCommit]bool)
	for _, record := range records {
		repoBranchCommitsMap[record.RepoBranchCommit()] = true
	}
	repoBranchCommitsMap[c.Base] = true
	repoBranchCommits := maps.Keys(repoBranchCommitsMap)
	fvs, err := c.FileVersProvider.GetFileVersions(c, targetFilePath, repoBranchCommits)
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
	Jobs             int
	Workdir          string
	skipRepoClone    bool
	Base             RepoBranchCommit
	FileVersProvider fileVersProvider
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

type FileRecords struct {
	fileName string
	records  []FileRecord
}

func mergeChanData(c *Config, recordChan <-chan FileRecord) (map[string]*MergeResult, error) {
	g, ctx := errgroup.WithContext(context.Background())
	frecordChan := groupFileRecords(recordChan, ctx)
	stat := make(map[string]*MergeResult)
	var mu sync.Mutex
	for i := 0; i < c.Jobs; i++ {
		g.Go(func() error {
			for frecord := range frecordChan {
				if mr, err := batchFileData(c, frecord.fileName, frecord.records); err != nil {
					return fmt.Errorf("failed to batchFileData(%s): %w", frecord.fileName, err)
				} else {
					mu.Lock()
					if _, exist := stat[frecord.fileName]; exist {
						mu.Unlock()
						return fmt.Errorf("file %s was already processed", frecord.fileName)
					}
					stat[frecord.fileName] = mr
					mu.Unlock()
				}
			}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	return stat, nil
}

func groupFileRecords(recordChan <-chan FileRecord, ctx context.Context) chan FileRecords {
	frecordChan := make(chan FileRecords)
	go func() {
		defer close(frecordChan)
		targetFile := ""
		var records []FileRecord
		for record := range recordChan {
			select {
			case <-ctx.Done():
				return
			default:
			}
			curTargetFile := record[KeyFilePath]
			if targetFile == "" {
				targetFile = curTargetFile
			}
			if curTargetFile != targetFile {
				frecordChan <- FileRecords{
					fileName: targetFile,
					records:  records,
				}
				records = nil
				targetFile = curTargetFile
			}
			records = append(records, record)
		}
		frecordChan <- FileRecords{
			fileName: targetFile,
			records:  records,
		}
	}()
	return frecordChan
}
