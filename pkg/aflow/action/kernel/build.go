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
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/build"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/sys/targets"
)

var Build = aflow.NewFuncAction("kernel-builder", buildKernel)

type buildArgs struct {
	KernelSrc    string
	KernelCommit string
	KernelConfig string
}

type buildResult struct {
	// Directory with build artifacts.
	KernelObj string
}

func buildKernel(ctx *aflow.Context, args buildArgs) (buildResult, error) {
	desc := fmt.Sprintf("kernel commit %v, kernel config hash %v",
		args.KernelCommit, hash.String(args.KernelConfig))
	dir, err := ctx.Cache("build", desc, func(dir string) error {
		if err := osutil.WriteFile(filepath.Join(dir, ".config"), []byte(args.KernelConfig)); err != nil {
			return err
		}
		target := targets.List[targets.Linux][targets.AMD64]
		image := path.Base(build.LinuxKernelImage(targets.AMD64))
		makeArgs := build.LinuxMakeArgs(target, targets.DefaultLLVMCompiler, targets.DefaultLLVMLinker,
			"ccache", dir, runtime.NumCPU())
		makeArgs = append(makeArgs, image, "compile_commands.json")
		if _, err := osutil.RunCmd(time.Hour, args.KernelSrc, "make", makeArgs...); err != nil {
			return err
		}
		// Remove all .o files from the build dir.
		// We don't need them anymore and they take lots of space.
		return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && strings.HasSuffix(d.Name(), ".o") {
				return os.Remove(path)
			}
			return nil
		})
	})
	return buildResult{KernelObj: dir}, err
}
