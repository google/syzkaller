// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package build

import (
	"errors"
	"fmt"
	"os"
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

	sysTarget := targets.Get(targets.Fuchsia, params.TargetArch)
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
		"--variant", "kasan",
	); err != nil {
		return err
	}
	if _, err := runSandboxed(time.Hour*2, params.KernelDir, "scripts/fx", "clean-build"); err != nil {
		return err
	}

	// Add ssh keys to the zbi image so syzkaller can access the fuchsia vm.
	_, sshKeyPub, err := genSSHKeys(params.OutputDir)
	if err != nil {
		return err
	}

	sshZBI := filepath.Join(params.OutputDir, "initrd")
	kernelZBI := filepath.Join(params.KernelDir, "out", arch, "fuchsia.zbi")
	authorizedKeys := fmt.Sprintf("data/ssh/authorized_keys=%s", sshKeyPub)

	if _, err := osutil.RunCmd(time.Minute, params.KernelDir, "out/"+arch+"/host_x64/zbi",
		"-o", sshZBI, kernelZBI, "--entry", authorizedKeys); err != nil {
		return err
	}

	// Copy and extend the fvm.
	fvmTool := filepath.Join("out", arch, "host_x64", "fvm")
	fvmDst := filepath.Join(params.OutputDir, "image")
	fvmSrc := filepath.Join(params.KernelDir, "out", arch, "obj/build/images/fvm.blk")
	if err := osutil.CopyFile(fvmSrc, fvmDst); err != nil {
		return err
	}
	if _, err := osutil.RunCmd(time.Minute*5, params.KernelDir, fvmTool, fvmDst, "extend", "--length", "3G"); err != nil {
		return err
	}

	for src, dst := range map[string]string{
		"out/" + arch + ".zircon/kernel-" + arch + "-kasan/obj/kernel/zircon.elf": "obj/zircon.elf",
		"out/" + arch + "/multiboot.bin":                                          "kernel",
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

// genSSHKeys generates a pair of ssh keys inside the given directory, named key and key.pub.
// If both files already exist, this function does nothing.
// The function returns the path to both keys.
func genSSHKeys(dir string) (privKey, pubKey string, err error) {
	privKey = filepath.Join(dir, "key")
	pubKey = filepath.Join(dir, "key.pub")

	os.Remove(privKey)
	os.Remove(pubKey)

	if _, err := osutil.RunCmd(time.Minute*5, dir, "ssh-keygen", "-t", "rsa", "-b", "2048",
		"-N", "", "-C", "syzkaller-ssh", "-f", privKey); err != nil {
		return "", "", err
	}
	return privKey, pubKey, nil
}
