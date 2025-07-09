// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package triage

import (
	"path/filepath"

	"github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/syz-cluster/pkg/api"
)

// For now, follow the simplest strategy - just verify whether the series modifies only the files
// irrelevant for the kernel builds.

// There are many opportunities to make it smarter:
// 1. Some source files are not compiled.
// 2. Some source files are compiled but we have never been able to cover them during fuzzing.

const reasonNotAffectsBuild = "the series only modifies irrelevant files"

// NeedFuzzing returns an empty string if the series is worth of fuzzing,
// and otherwise it returns an explanation why it is not.
func NeedFuzzing(series *api.Series) string {
	for _, patch := range series.Patches {
		files := vcs.ParseGitDiff(patch.Body)
		for _, file := range files {
			if irrelevantPath[file] {
				continue
			}
			if irrelevantExt[filepath.Ext(file)] {
				continue
			}
			return ""
		}
	}
	return reasonNotAffectsBuild
}

var irrelevantExt = map[string]bool{
	".txt":  true,
	".rst":  true,
	".json": true,
	".py":   true,
}

var irrelevantPath = map[string]bool{
	"MAINTAINERS": true,
}
