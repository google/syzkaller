// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package kernel

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"time"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/build"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/sys/targets"
)

// Build action builds the Linux kernel from the given sources,
// outputs directory with build artifacts.
var Build = aflow.NewFuncAction("kernel-builder", buildKernel)

type buildArgs struct {
	KernelSrc    string
	KernelCommit string
	KernelConfig string
}

type buildResult struct {
	KernelObj string // Directory with build artifacts.
}

func buildKernel(ctx *aflow.Context, args buildArgs) (buildResult, error) {
	desc := fmt.Sprintf("kernel commit %v, kernel config hash %v",
		args.KernelCommit, hash.String(args.KernelConfig))
	dir, err := ctx.Cache("build", desc, func(dir string) error {
		if err := osutil.WriteFile(filepath.Join(dir, ".config"), []byte(args.KernelConfig)); err != nil {
			return err
		}
		target := targets.List[targets.Linux][targets.AMD64]
		image := filepath.FromSlash(build.LinuxKernelImage(targets.AMD64))
		makeArgs := build.LinuxMakeArgs(target, targets.DefaultLLVMCompiler, targets.DefaultLLVMLinker,
			"ccache", dir, runtime.NumCPU())
		makeArgs = append(makeArgs, path.Base(image), "compile_commands.json")
		if _, err := osutil.RunCmd(time.Hour, args.KernelSrc, "make", makeArgs...); err != nil {
			return err
		}
		// Remove main intermediate build files, we don't need them anymore
		// and they take lots of space. Keep generated source files.
		keepExt := map[string]bool{"h": true, "c": true, "s": true, "S": true}
		keepFiles := map[string]bool{image: true}
		return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || keepFiles[path] || keepExt[filepath.Ext(d.Name())] {
				return err
			}
			return os.Remove(path)
		})
	})
	return buildResult{KernelObj: dir}, err
}
