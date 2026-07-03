// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package kernel provides actions for checking out and building target kernel trees.
package kernel

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
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
	TargetOS     string
	TargetArch   string
	KernelSrc    string
	KernelCommit string
	KernelConfig string
}

type buildResult struct {
	KernelObj string // Directory with build artifacts.
}

var cmdlineRe = regexp.MustCompile(`(?m)^CONFIG_CMDLINE="(.*)"$`)

func BuildKernel(buildDir, srcDir, cfg, targetOS, targetArch string, cleanup bool) error {
	if err := osutil.WriteFile(filepath.Join(buildDir, ".config"), []byte(cfg)); err != nil {
		return err
	}
	configScript := filepath.Join(srcDir, "scripts", "config")
	configArgs := []string{"--set-str", "INITRAMFS_SOURCE", ""}
	switch targetArch {
	case targets.AMD64:
		// We don't fuzz x32 arch, and it's not very interesting,
		// but building with this config and ld.lld fails with the following error:
		// ld.lld: error: arch/x86/entry/vdso/vgetrandom-x32.o:(.note.gnu.property+0x0): data is too short
		// ld.lld: error: arch/x86/entry/vdso/vgetcpu-x32.o:(.note.gnu.property+0x0): data is too short
		// Also enforce gzip since lz4 is not present in the Docker container.
		configArgs = append(configArgs, "-d", "X86_X32_ABI", "-e", "KERNEL_GZIP", "-d", "KERNEL_LZ4")
	case targets.ARM64:
		// Necessary for booting on GCE.
		cmdline := "earlyprintk=serial net.ifnames=0 console=ttyAMA0 root=/dev/vda"
		if match := cmdlineRe.FindStringSubmatch(cfg); len(match) > 1 {
			cmdline = match[1] + " " + cmdline
		}
		configArgs = append(configArgs, "--set-str", "CMDLINE", cmdline)
	}
	if _, err := osutil.RunCmd(time.Hour, buildDir, configScript, configArgs...); err != nil {
		return err
	}
	target := targets.List[targetOS][targetArch]
	image := filepath.FromSlash(build.LinuxKernelImage(targetArch))
	makeArgs := build.LinuxMakeArgs(target, targets.DefaultLLVMCompiler, targets.DefaultLLVMLinker,
		"ccache", buildDir, runtime.NumCPU())
	const compileCommands = "compile_commands.json"
	makeArgs = append(makeArgs, "-s", path.Base(image), compileCommands)
	if _, err := osutil.RunCmd(time.Hour, srcDir, "make", makeArgs...); err != nil {
		buildErr := build.ExtractRootCause(err, targets.Linux, srcDir)
		if buildErr == err {
			return aflow.FlowError(err)
		}
		return aflow.FlowError(fmt.Errorf("%w\n\nRoot cause:\n%w", err, buildErr))
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
		return BuildKernel(dir, args.KernelSrc, args.KernelConfig, args.TargetOS, args.TargetArch, true)
	})
	return buildResult{KernelObj: dir}, err
}
