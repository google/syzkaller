// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package covermerger

import (
	"log"
	"time"
)

func makeFileLineCoverMerger(
	fvs fileVersions, base RepoBranchCommit) FileCoverageMerger {
	baseFile := ""
	baseFileExists := false
	for rbc, fv := range fvs {
		if rbc == base {
			baseFile = fv.content
			baseFileExists = true
			break
		}
	}
	if !baseFileExists {
		return &DeletedFileLineMerger{}
	}
	a := &FileLineCoverMerger{
		rbcToFile: fvs,
		baseFile:  baseFile,
		hitCounts: make(map[int]int),
		matchers:  make(map[RepoBranchCommit]*LineToLineMatcher),
	}
	for rbc, fv := range fvs {
		a.matchers[rbc] = makeLineToLineMatcher(fv.content, baseFile)
	}
	return a
}

// freshestRBC returns RepoBranchCommit with the last modified non-empty file.
func freshestRBC(fvs fileVersions) *RepoBranchCommit {
	var res *RepoBranchCommit
	var resLastUpdated time.Time
	for rbc, fv := range fvs {
		if fv.content == "" {
			continue
		}
		if res == nil || resLastUpdated.Before(fv.lastUpdated) {
			res = &rbc
			resLastUpdated = fv.lastUpdated
		}
	}
	return res
}

type FileLineCoverMerger struct {
	rbcToFile fileVersions
	baseFile  string
	hitCounts map[int]int
	matchers  map[RepoBranchCommit]*LineToLineMatcher
}

func (a *FileLineCoverMerger) AddRecord(rbc RepoBranchCommit, arch string, f Frame, hitCount int) {
	if a.matchers[rbc] == nil {
		log.Printf("[WARNING] rbc(%s, %s, %s)."+
			"We have signals from the file but the file itself doesn't exist? Corrupted cache?",
			rbc.Repo, rbc.Branch, rbc.Commit)
		return
	}
	if targetLine := a.matchers[rbc].SameLinePos(f.StartLine); targetLine != -1 {
		a.hitCounts[f.StartLine] += hitCount
	}
}

func (a *FileLineCoverMerger) Result() *MergeResult {
	return &MergeResult{
		HitCounts:  a.hitCounts,
		FileExists: true,
	}
}
