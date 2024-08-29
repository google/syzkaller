// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package covermerger

import "github.com/google/syzkaller/pkg/log"

func makeFileLineCoverMerger(
	fvs fileVersions, base RepoCommit, storeDetails bool) FileCoverageMerger {
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
		MergeResult: &MergeResult{
			HitCounts:  make(map[int]int),
			FileExists: true,
		},
		rbcToFile:  fvs,
		baseFile:   baseFile,
		matchers:   make(map[RepoCommit]*LineToLineMatcher),
		lostFrames: map[RepoCommit]int64{},
	}
	if storeDetails {
		a.MergeResult.LineDetails = make(map[int][]*FileRecord)
	}
	for rbc, fv := range fvs {
		a.matchers[rbc] = makeLineToLineMatcher(fv, baseFile)
	}
	return a
}

type FileLineCoverMerger struct {
	*MergeResult
	rbcToFile  fileVersions
	baseFile   string
	matchers   map[RepoCommit]*LineToLineMatcher
	lostFrames map[RepoCommit]int64
}

func (a *FileLineCoverMerger) Add(record *FileRecord) {
	if a.matchers[record.RepoCommit] == nil {
		if record.HitCount > 0 {
			a.lostFrames[record.RepoCommit]++
		}
		return
	}
	if targetLine := a.matchers[record.RepoCommit].SameLinePos(record.StartLine); targetLine != -1 {
		a.HitCounts[targetLine] += record.HitCount
		if a.LineDetails != nil {
			a.LineDetails[targetLine] = append(a.LineDetails[targetLine], record)
		}
	}
}

func (a *FileLineCoverMerger) Result() *MergeResult {
	for rbc, lostFrames := range a.lostFrames {
		log.Logf(1, "\t[warn] lost %d frames from repoCommit(%s, %s)",
			lostFrames, rbc.Repo, rbc.Commit)
	}
	return a.MergeResult
}
