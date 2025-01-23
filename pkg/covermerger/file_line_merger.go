// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package covermerger

import "github.com/google/syzkaller/pkg/log"

func makeFileLineCoverMerger(fvs FileVersions, base RepoCommit) FileCoverageMerger {
	baseFile := ""
	baseFileExists := false
	for repoCommit, fv := range fvs {
		if repoCommit == base {
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
			HitCounts:   make(map[int]int64),
			FileExists:  true,
			LineDetails: make(map[int][]*FileRecord),
		},
		baseFile:   baseFile,
		matchers:   make(map[RepoCommit]*LineToLineMatcher),
		lostFrames: map[RepoCommit]int64{},
	}
	for repoBranch, fv := range fvs {
		a.matchers[repoBranch] = makeLineToLineMatcher(fv, baseFile)
	}
	return a
}

type FileLineCoverMerger struct {
	*MergeResult
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
		a.HitCounts[targetLine] += int64(record.HitCount)
		a.LineDetails[targetLine] = append(a.LineDetails[targetLine], record)
	}
}

func (a *FileLineCoverMerger) Result() *MergeResult {
	for repoBranch, lostFrames := range a.lostFrames {
		log.Logf(1, "\t[warn] lost %d frames from repoCommit(%s, %s)",
			lostFrames, repoBranch.Repo, repoBranch.Commit)
	}
	return a.MergeResult
}
