// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package kernel

import (
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/build"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/sys/targets"
)

var Build = aflow.NewFuncAction("kernel-builder", buildKernel)

type buildArgs struct {
	KernelSrc    string `json:"kernel-src"`
	KernelCommit string `json:"kernel-commit"`
	KernelConfig string `json:"kernel-config"`
}

type buildResult struct {
	// Directory with build artifacts.
	KernelObj string `json:"kernel-obj"`
}

var buildMu sync.Mutex

func buildKernel(ctx *aflow.Context, args buildArgs) (buildResult, error) {
	buildMu.Lock()
	defer buildMu.Unlock()

	buildID := hash.String(args.KernelCommit, args.KernelConfig)
	res := buildResult{
		KernelObj: filepath.Join(ctx.Workdir, "obj", buildID),
	}
	if osutil.IsExist(res.KernelObj) {
		return res, nil
	}

	tmpDir := res.KernelObj + ".tmp"
	if err := osutil.MkdirAll(tmpDir); err != nil {
		return res, err
	}
	if err := osutil.WriteFile(filepath.Join(tmpDir, ".config"), []byte(args.KernelConfig)); err != nil {
		return res, err
	}
	target := targets.List[targets.Linux][targets.AMD64]
	makeArgs := build.LinuxMakeArgs(target, targets.DefaultLLVMCompiler, targets.DefaultLLVMLinker, "ccache", tmpDir, runtime.NumCPU())
	if _, err := osutil.RunCmd(time.Hour, args.KernelSrc, "make", append(makeArgs, "bzImage")...); err != nil {
		return res, err
	}
	if err := os.Rename(tmpDir, res.KernelObj); err != nil {
		return res, err
	}
	return res, nil
}
