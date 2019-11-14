// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package build

import (
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/sys/targets"
)

type fuchsia struct{}

// syzRoot returns $GOPATH/src/github.com/google/syzkaller.
func syzRoot() (string, error) {
	_, selfPath, _, ok := runtime.Caller(0)
	if !ok {
		return "", errors.New("runtime.Caller failed")
	}

	return filepath.Abs(filepath.Join(filepath.Dir(selfPath), "../.."))
}

func (fu fuchsia) build(params *Params) error {
	syzDir, err := syzRoot()
	if err != nil {
		return err
	}

	sysTarget := targets.Get("fuchsia", params.TargetArch)
	if sysTarget == nil {
		return fmt.Errorf("unsupported fuchsia arch %v", params.TargetArch)
	}
	arch := sysTarget.KernelHeaderArch
	product := fmt.Sprintf("%s.%s", "core", arch)
	if _, err := runSandboxed(time.Hour, params.KernelDir,
		"scripts/fx", "--dir", "out/"+arch,
		"set", product,
		"--args", fmt.Sprintf(`syzkaller_dir="%s"`, syzDir),
		"--with-base", "//bundles:tools",
		"--with-base", "//src/testing/fuzzing/syzkaller",
	); err != nil {
		return err
	}
	if _, err := runSandboxed(time.Hour*2, params.KernelDir, "scripts/fx", "clean-build"); err != nil {
		return err
	}

	// Fuchsia images no longer include ssh keys. Manually append the ssh public key to the zbi.
	sshZBI := filepath.Join(params.KernelDir, "out", arch, "fuchsia-ssh.zbi")
	kernelZBI := filepath.Join(params.KernelDir, "out", arch, "fuchsia.zbi")
	authorizedKeys := fmt.Sprintf("data/ssh/authorized_keys=%s",
		filepath.Join(params.KernelDir, ".ssh", "authorized_keys"))
	if _, err := runSandboxed(time.Minute, params.KernelDir, "out/"+arch+".zircon/tools/zbi",
		"-o", sshZBI, kernelZBI, "--entry", authorizedKeys); err != nil {
		return err
	}

	for src, dst := range map[string]string{
		"out/" + arch + "/obj/build/images/fvm.blk": "image",
		".ssh/pkey": "key",
		"out/" + arch + ".zircon/kernel-" + arch + "-clang/obj/kernel/zircon.elf": "obj/zircon.elf",
		"out/" + arch + ".zircon/multiboot.bin":                                   "kernel",
		"out/" + arch + "/fuchsia-ssh.zbi":                                        "initrd",
	} {
		fullSrc := filepath.Join(params.KernelDir, filepath.FromSlash(src))
		fullDst := filepath.Join(params.OutputDir, filepath.FromSlash(dst))
		if err := osutil.CopyFile(fullSrc, fullDst); err != nil {
			return fmt.Errorf("failed to copy %v: %v", src, err)
		}
	}
	return nil
}

func (fu fuchsia) clean(kernelDir, targetArch string) error {
	// We always do clean build because incremental build is frequently broken.
	// So no need to clean separately.
	return nil
}

func runSandboxed(timeout time.Duration, dir, command string, arg ...string) ([]byte, error) {
	cmd := osutil.Command(command, arg...)
	cmd.Dir = dir
	if err := osutil.Sandbox(cmd, true, false); err != nil {
		return nil, err
	}
	return osutil.Run(timeout, cmd)
}
