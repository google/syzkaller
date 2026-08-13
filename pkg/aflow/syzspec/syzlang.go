// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzspec

import (
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"

	"github.com/google/syzkaller/pkg/osutil"
)

// CorpusProgramBucket holds a partition of serialized syzlang programs.
type CorpusProgramBucket struct {
	Programs map[string]string `json:"Programs"`
}

// CorpusData represents indexed syzlang corpus reachability mappings and bucket
// file references.
type CorpusData struct {
	FunctionMap  map[string][]string `json:"FunctionMap"`
	SyscallMap   map[string][]string `json:"SyscallMap"`
	ProgToBucket map[string]string   `json:"ProgToBucket"`
}

// ProgramsForFunction returns program hashes reaching the specified kernel function.
func (d CorpusData) ProgramsForFunction(funcName string) []string {
	return slices.Clone(d.FunctionMap[funcName])
}

// ProgramsForSyscall searches SyscallMap case-insensitively for matches, returning deduplicated, sorted hashes.
func (d CorpusData) ProgramsForSyscall(query string) []string {
	matchedHashes := make(map[string]bool)
	queryLower := strings.ToLower(query)
	for name, hList := range d.SyscallMap {
		if strings.Contains(strings.ToLower(name), queryLower) {
			for _, h := range hList {
				matchedHashes[h] = true
			}
		}
	}
	hashes := slices.Collect(maps.Keys(matchedHashes))
	slices.Sort(hashes)
	return hashes
}

// ReadPrograms loads programs matching requested hashes from bucket files in dir.
func (d CorpusData) ReadPrograms(dir string, hashes []string) (map[string]string, error) {
	bucketToHashes := make(map[string][]string)
	for _, h := range hashes {
		fileName, ok := d.ProgToBucket[h]
		if ok && fileName != "" {
			bucketToHashes[fileName] = append(bucketToHashes[fileName], h)
		}
	}

	programs := make(map[string]string)
	for fileName, bHashes := range bucketToHashes {
		bucket, err := osutil.ReadJSON[CorpusProgramBucket](filepath.Join(dir, fileName))
		if err != nil {
			return nil, fmt.Errorf("failed to read bucket file %q: %w", fileName, err)
		}
		for _, h := range bHashes {
			if p, ok := bucket.Programs[h]; ok {
				programs[h] = p
			}
		}
	}
	return programs, nil
}

// CorpusBucketFileName formats the filename for a program bucket with given index.
func CorpusBucketFileName(bucketIdx int) string {
	return fmt.Sprintf("bucket_%03d.json", bucketIdx)
}

// SaveCorpusBucket writes a partition of programs into a bucket JSON file inside dir.
func SaveCorpusBucket(dir string, bucketIdx int, progs map[string]string) (string, error) {
	fileName := CorpusBucketFileName(bucketIdx)
	err := osutil.WriteJSON(filepath.Join(dir, fileName), CorpusProgramBucket{
		Programs: progs,
	})
	if err != nil {
		return "", fmt.Errorf("failed to write bucket %s: %w", fileName, err)
	}
	return fileName, nil
}
