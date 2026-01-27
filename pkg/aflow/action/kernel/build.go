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
	"github.com/google/syzkaller/pkg/codesearch"
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

func BuildKernel(buildDir, srcDir, cfg string, cleanup bool) error {
	if err := osutil.WriteFile(filepath.Join(buildDir, ".config"), []byte(cfg)); err != nil {
		return err
	}
	// We don't fuzz x32 arch, and it's not very interesting,
	// but building with this config and ld.lld fails with the following error:
	// ld.lld: error: arch/x86/entry/vdso/vgetrandom-x32.o:(.note.gnu.property+0x0): data is too short
	// ld.lld: error: arch/x86/entry/vdso/vgetcpu-x32.o:(.note.gnu.property+0x0): data is too short
	configScript := filepath.Join(srcDir, "scripts", "config")
	if _, err := osutil.RunCmd(time.Hour, buildDir, configScript, "-d", "X86_X32_ABI"); err != nil {
		return err
	}
	target := targets.List[targets.Linux][targets.AMD64]
	image := filepath.FromSlash(build.LinuxKernelImage(targets.AMD64))
	makeArgs := build.LinuxMakeArgs(target, targets.DefaultLLVMCompiler, targets.DefaultLLVMLinker,
		"ccache", buildDir, runtime.NumCPU())
	const compileCommands = "compile_commands.json"
	makeArgs = append(makeArgs, "-s", path.Base(image), compileCommands)
	if out, err := osutil.RunCmd(time.Hour, srcDir, "make", makeArgs...); err != nil {
		return aflow.FlowError(fmt.Errorf("make failed: %w\n%s", err, out))
	}
	if !cleanup {
		return nil
	}
	// Remove main intermediate build files, we don't need them anymore
	// and they take lots of space. But keep generated source files.
	keepFiles := map[string]bool{
		image:               true,
		target.KernelObject: true,
		compileCommands:     true,
	}
	return filepath.WalkDir(buildDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(buildDir, path)
		if err != nil {
			return err
		}
		if d.IsDir() || keepFiles[relative] || codesearch.IsSourceFile(relative) {
			return nil
		}
		return os.Remove(path)
	})
}

func buildKernel(ctx *aflow.Context, args buildArgs) (buildResult, error) {
	desc := fmt.Sprintf("kernel commit %v, kernel config hash %v",
		args.KernelCommit, hash.String(args.KernelConfig))
	dir, err := ctx.Cache("build", desc, func(dir string) error {
		return BuildKernel(dir, args.KernelSrc, args.KernelConfig, true)
	})
	return buildResult{KernelObj: dir}, err
}
