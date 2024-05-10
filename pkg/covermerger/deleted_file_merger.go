// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package covermerger

type DeletedFileLineMerger struct {
}

func (a *DeletedFileLineMerger) AddRecord(RepoBranchCommit, string, Frame, int) {
}

func (a *DeletedFileLineMerger) Result() *MergeResult {
	return &MergeResult{
		FileExists: false,
	}
}
