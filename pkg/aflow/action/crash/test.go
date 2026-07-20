// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package crash

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/kernel"
	"github.com/google/syzkaller/pkg/aflow/tool/patchdiff"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/sys/targets"
)

// TestPatch action does an in-tree kernel build in KernelScratchSrc dir,
// and runs the reproducer on the newly built kernel.
// If there are build/boot/test errors, a detailed error message is returned in TestError.
// The action also collects diff of the local changes, returns it in PatchDiff,
// and resets source code state to HEAD (removes all local edits).
var TestPatch = aflow.NewFuncAction("test-patch", testPatch)

// TestPatchInplace is like TestPatch, but it leaves the local edits applied
// to the source tree instead of resetting it to HEAD.
var TestPatchInplace = aflow.NewFuncAction("test-patch-inplace", testPatchInplace)

type testArgs struct {
	AgentName        string
	TargetOS         string
	TargetArch       string
	Syzkaller        string
	Image            string
	Type             string
	VM               json.RawMessage
	ReproOpts        string
	ReproSyz         string
	ReproC           string
	KernelScratchSrc string
	KernelCommit     string
	KernelConfig     string
}

type testResult struct {
	PatchDiff string
	TestError string
}

func testPatch(ctx *aflow.Context, args testArgs) (testResult, error) {
	defer undoChanges(args.KernelScratchSrc)
	return testPatchInplace(ctx, args)
}

func testPatchInplace(ctx *aflow.Context, args testArgs) (testResult, error) {
	res := testResult{}

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
	cached, _, err := aflow.CacheObject(ctx, "patch-test", desc, func() (Cached, error) {
		for _, fn := range []func(ctx *aflow.Context, args testArgs) (string, error){
			testPatchBuild,
			testPatchRepro,
		} {
			testError, err := fn(ctx, args)
			if err != nil || testError != "" {
				return Cached{testError}, err
			}
		}
		return Cached{}, nil
	})
	res.TestError = cached.TestError
	return res, err
}

func testPatchBuild(ctx *aflow.Context, args testArgs) (string, error) {
	if err := kernel.BuildKernel(args.KernelScratchSrc, args.KernelScratchSrc,
		args.KernelConfig, args.TargetOS, args.TargetArch, false); err != nil {
		// TODO: should distinguish between infra errors, and patch compilation errors.
		return fmt.Sprintf("Building the kernel failed with: %v", err), nil
	}
	return "", nil
}

func testPatchRepro(ctx *aflow.Context, args testArgs) (string, error) {
	if args.TargetOS != targets.Linux {
		return "", aflow.FlowError(fmt.Errorf("can only run on the Linux kernel"))
	}
	workdir, err := ctx.TempDir()
	if err != nil {
		return "", err
	}
	reproduceArgs := ReproduceArgs{
		TargetConfig: TargetConfig{
			AgentName:    args.AgentName,
			TargetArch:   args.TargetArch,
			Syzkaller:    args.Syzkaller,
			Image:        args.Image,
			Type:         args.Type,
			VM:           args.VM,
			KernelSrc:    args.KernelScratchSrc,
			KernelObj:    args.KernelScratchSrc,
			KernelCommit: args.KernelCommit,
			KernelConfig: args.KernelConfig,
		},
		ReproOpts: args.ReproOpts,
		ReproSyz:  args.ReproSyz,
		ReproC:    args.ReproC,
	}
	testRes, err := RunTest(reproduceArgs, workdir, false)
	if err != nil {
		return "", err
	}
	if testRes.Report != nil {
		return string(testRes.Report.Report), nil
	}
	return testRes.BootError, nil
}

func currentDiff(repo string) (string, error) {
	// Mark the "intent to add" on all files so git diff also shows currently untracked files.
	_, err := osutil.RunCmd(time.Minute, repo, "git", "add", "-N", ".")
	if err != nil {
		return "", err
	}
	return patchdiff.Diff(repo)
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
