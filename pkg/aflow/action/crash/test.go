// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package crash

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"time"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/kernel"
	"github.com/google/syzkaller/pkg/hash"
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
	if diff == "" {
		res.TestError = "No patch to test."
		return res, nil
	}
	res.PatchDiff = diff

	imageData, err := os.ReadFile(args.Image)
	if err != nil {
		return res, err
	}
	desc := fmt.Sprintf("kernel commit %v, kernel config hash %v, image hash %v,"+
		" vm %v, vm config hash %v, C repro hash %v, patch hash %v, version 1",
		args.KernelCommit, hash.String(args.KernelConfig), hash.String(imageData),
		args.Type, hash.String(args.VM), hash.String(args.ReproC), hash.String(diff))
	type Cached struct {
		TestError string
	}
	cached, err := aflow.CacheObject(ctx, "patch-test", desc, func() (Cached, error) {
		var res Cached
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
		rep, bootError, err := ReproduceCrash(reproduceArgs, workdir)
		if rep != nil {
			res.TestError = string(rep.Report)
		} else {
			res.TestError = bootError
		}
		return res, err
	})
	res.TestError = cached.TestError
	return res, err
}

func currentDiff(repo string) (string, error) {
	// Mark the "intent to add" on all files so git diff also shows currently untracked files.
	_, err := osutil.RunCmd(time.Minute, repo, "git", "add", "-N", ".")
	if err != nil {
		return "", err
	}
	diff, err := osutil.RunCmd(time.Minute, repo, "git", "diff", "-U0")
	if err != nil {
		return "", err
	}
	formatDiff, err := findClangFormatDiff()
	if err != nil {
		return "", err
	}
	cmd := exec.Command(formatDiff, "-p1", "-i", "-style=file")
	cmd.Stdin = bytes.NewReader(diff)
	cmd.Dir = repo
	if output, err := osutil.Run(10*time.Minute, cmd); err != nil {
		return "", fmt.Errorf("%w\n%s", err, output)
	}
	diff, err = osutil.RunCmd(time.Minute, repo, "git", "diff")
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

func findClangFormatDiff() (string, error) {
	// It may be installed at different paths, and there may or may not be the version number.
	paths := []string{
		"/usr/lib/clang-format*/clang-format-diff.py",
		"/usr/share/clang/clang-format*/clang-format-diff.py",
	}
	for _, path := range paths {
		files, _ := filepath.Glob(path)
		if len(files) == 0 {
			continue
		}
		// If there are version numbers, we want to find the latest one.
		slices.Sort(files)
		return files[len(files)-1], nil
	}
	return "", fmt.Errorf("can't find clang-format-diff.py, install clang-format package")
}
