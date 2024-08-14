// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package covermerger

import "github.com/google/syzkaller/pkg/log"

func makeFileLineCoverMerger(
	fvs fileVersions, base RepoBranchCommit) FileCoverageMerger {
	baseFile := ""
	baseFileExists := false
	for rbc, fv := range fvs {
		if rbc == base {
			baseFile = fv
			baseFileExists = true
			break
		}
	}
	if !baseFileExists {
		return &DeletedFileLineMerger{}
	}
	a := &FileLineCoverMerger{
		rbcToFile:  fvs,
		baseFile:   baseFile,
		hitCounts:  make(map[int]int),
		matchers:   make(map[RepoBranchCommit]*LineToLineMatcher),
		lostFrames: map[RepoBranchCommit]int64{},
	}
	for rbc, fv := range fvs {
		a.matchers[rbc] = makeLineToLineMatcher(fv, baseFile)
	}
	return a
}

type FileLineCoverMerger struct {
	rbcToFile  fileVersions
	baseFile   string
	hitCounts  map[int]int
	matchers   map[RepoBranchCommit]*LineToLineMatcher
	lostFrames map[RepoBranchCommit]int64
}

func (a *FileLineCoverMerger) Add(record *FileRecord) {
	if a.matchers[record.RepoBranchCommit] == nil {
		if record.HitCount > 0 {
			a.lostFrames[record.RepoBranchCommit]++
		}
		return
	}
	if targetLine := a.matchers[record.RepoBranchCommit].SameLinePos(record.StartLine); targetLine != -1 {
		a.hitCounts[targetLine] += record.HitCount
	}
}

func (a *FileLineCoverMerger) Result() *MergeResult {
	for rbc, lostFrames := range a.lostFrames {
		log.Logf(1, "\t[warn] lost %d frames from rbc(%s, %s, %s)",
			lostFrames, rbc.Repo, rbc.Branch, rbc.Commit)
	}
	return &MergeResult{
		HitCounts:  a.hitCounts,
		FileExists: true,
	}
}
