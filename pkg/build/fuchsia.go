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
	if _, err := osutil.RunCmd(time.Hour, kernelDir, "scripts/fx", "clean-build", arch,
		"--args", `extra_authorized_keys_file="//.ssh/authorized_keys"`,
		"--packages", "garnet/packages/products/sshd", "--product", "garnet/products/default.gni"); err != nil {
		return err
	}
	for src, dst := range map[string]string{
		"out/" + arch + "/obj/build/images/fvm.blk": "image",
		".ssh/pkey": "key",
		"out/build-zircon/build-" + arch + "/zircon.elf":    "obj/zircon.elf",
		"out/build-zircon/build-" + arch + "/multiboot.bin": "kernel",
		"out/" + arch + "/fuchsia.zbi":                      "initrd",
	} {
		fullSrc := filepath.Join(kernelDir, filepath.FromSlash(src))
		fullDst := filepath.Join(outputDir, filepath.FromSlash(dst))
		if err := osutil.CopyFile(fullSrc, fullDst); err != nil {
			return fmt.Errorf("failed to copy %v: %v", src, err)
		}
	}
	return nil
}

func (fu fuchsia) clean(kernelDir string) error {
	// We always do clean build because incremental build is frequently broken.
	// So no need to clean separately.
	return nil
}
