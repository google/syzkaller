// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package crash

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/kernel"
	"github.com/google/syzkaller/pkg/osutil"
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
	res := testResult{}
	defer undoChanges(args.KernelScratchSrc)

	diff, err := currentDiff(args.KernelScratchSrc)
	if err != nil {
		return res, err
	}
	res.PatchDiff = diff

	if err := kernel.BuildKernel(args.KernelScratchSrc, args.KernelScratchSrc, args.KernelConfig, false); err != nil {
		res.TestError = fmt.Sprintf("Building the kernel failed with %v", err)
		return res, nil
	}

	workdir, err := ctx.TempDir()
	if err != nil {
		return res, err
	}
	reproduceArgs := ReproduceArgs{
		Syzkaller:       args.Syzkaller,
		Image:           args.Image,
		Type:            args.Type,
		VM:              args.VM,
		ReproOpts:       args.ReproOpts,
		ReproSyz:        args.ReproSyz,
		ReproC:          args.ReproC,
		SyzkallerCommit: args.SyzkallerCommit,
		KernelSrc:       args.KernelScratchSrc,
		KernelObj:       args.KernelScratchSrc,
		KernelCommit:    args.KernelCommit,
		KernelConfig:    args.KernelConfig,
	}
	errorLog, reportLog, err := ReproduceCrash(reproduceArgs, workdir)
	if errorLog != "" {
		res.TestError = errorLog
	} else {
		res.TestError = reportLog
	}
	return res, err
}

func currentDiff(repo string) (string, error) {
	// Mark the "intent to add" on all files so git diff also shows currently untracked files.
	_, err := osutil.RunCmd(time.Minute, repo, "git", "add", "-N", ".")
	if err != nil {
		return "", err
	}
	diff, err := osutil.RunCmd(time.Minute, repo, "git", "diff")
	if err != nil {
		return "", err
	}
	return string(diff), nil
}

func undoChanges(repo string) error {
	// Unset the "intent to add", otherwise git clean doesn't remove these files.
	_, err := osutil.RunCmd(time.Minute, repo, "git", "reset")
	if err != nil {
		return err
	}
	_, err = osutil.RunCmd(time.Minute, repo, "git", "checkout", "--", ".")
	if err != nil {
		return err
	}
	// We do not use -fdx to keep object files around and make the next tool call faster.
	_, err = osutil.RunCmd(time.Minute, repo, "git", "clean", "-fd")
	return err
}
