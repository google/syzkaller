// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package covermerger

func makeFileLineCoverMerger(
	fileVersions map[RepoBranchCommit]string, base RepoBranchCommit) FileCoverageMerger {
	baseFile := ""
	baseFileExists := false
	for rbc, fileContent := range fileVersions {
		if rbc == base {
			baseFile = fileContent
			baseFileExists = true
			break
		}
	}
	if !baseFileExists {
		return &DeletedFileLineMerger{}
	}
	a := &FileLineCoverMerger{
		rbcToFile: fileVersions,
		baseFile:  baseFile,
		hitCounts: make(map[int]int),
		matchers:  make(map[RepoBranchCommit]*LineToLineMatcher),
	}
	for rbc, fileVersion := range fileVersions {
		a.matchers[rbc] = makeLineToLineMatcher(fileVersion, baseFile)
	}
	return a
}

type FileLineCoverMerger struct {
	rbcToFile map[RepoBranchCommit]string
	baseFile  string
	hitCounts map[int]int
	matchers  map[RepoBranchCommit]*LineToLineMatcher
}

func (a *FileLineCoverMerger) AddRecord(rbc RepoBranchCommit, arch string, f Frame, hitCount int) {
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
