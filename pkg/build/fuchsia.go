// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package build

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/sys/targets"
)

type fuchsia struct{}

func (fu fuchsia) build(targetArch, vmType, kernelDir, outputDir, compiler, userspaceDir,
	cmdlineFile, sysctlFile string, config []byte) error {
	sysTarget := targets.Get("fuchsia", targetArch)
	if sysTarget == nil {
		return fmt.Errorf("unsupported fuchsia arch %v", targetArch)
	}
	arch := sysTarget.KernelHeaderArch
	product := fmt.Sprintf("%s.%s", "core", arch)
	if _, err := osutil.RunCmd(time.Hour, kernelDir, "scripts/fx", "--dir", "out/"+arch,
		"set", product, "--with-base", "//bundles:tools"); err != nil {
		return err
	}
	if _, err := osutil.RunCmd(time.Hour, kernelDir, "scripts/fx", "clean-build"); err != nil {
		return err
	}

	// Fuchsia images no longer include ssh keys. Manually append the ssh public key to the zbi.
	sshZBI := filepath.Join(kernelDir, "out", arch, "fuchsia-ssh.zbi")
	kernelZBI := filepath.Join(kernelDir, "out", arch, "fuchsia.zbi")
	authorizedKeys := fmt.Sprintf("data/ssh/authorized_keys=%s", filepath.Join(kernelDir, ".ssh", "authorized_keys"))
	if _, err := osutil.RunCmd(time.Minute, kernelDir, "out/"+arch+".zircon/tools/zbi",
		"-o", sshZBI, kernelZBI, "--entry", authorizedKeys); err != nil {
		return err
	}

	for src, dst := range map[string]string{
		"out/" + arch + "/obj/build/images/fvm.blk": "image",
		".ssh/pkey": "key",
		"out/" + arch + ".zircon/kernel-" + arch + "-gcc/obj/kernel/zircon.elf": "obj/zircon.elf",
		"out/" + arch + ".zircon/multiboot.bin":                                 "kernel",
		"out/" + arch + "/fuchsia-ssh.zbi":                                      "initrd",
	} {
		fullSrc := filepath.Join(kernelDir, filepath.FromSlash(src))
		fullDst := filepath.Join(outputDir, filepath.FromSlash(dst))
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
