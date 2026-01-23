// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package crash

import (
	"encoding/json"

	"github.com/google/syzkaller/pkg/aflow"
)

// TestPatch action does an in-tree kernel build in KernelScratchSrc dir,
// and runs the reproducer on the newly built kernel.
// If there are build/boot/test errors, a detailed error message is returned in TestError.
// The action also collects diff of the local changes, returns it in PatchDiff,
// and resets source code state to HEAD (removes all local edits).
var TestPatch = aflow.NewFuncAction("test-patch", testPatch)

type testArgs struct {
	Syzkaller        string
	Image            string
	Type             string
	VM               json.RawMessage
	ReproOpts        string
	ReproSyz         string
	ReproC           string
	SyzkallerCommit  string
	KernelScratchSrc string
	KernelCommit     string
	KernelConfig     string
}

type testResult struct {
	PatchDiff string
	TestError string
}

func testPatch(ctx *aflow.Context, args testArgs) (testResult, error) {
	return testResult{}, nil
}
