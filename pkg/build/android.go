// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package build

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
)

const (
	kernelConfig = "common/build.config.gki_kasan.x86_64"
	moduleConfig = "common-modules/virtual-device/build.config.virtual_device_kasan.x86_64"
)

type android struct{}

func (a android) runBuild(kernelDir, buildConfig string) error {
	cmd := osutil.Command("build/build.sh")
	cmd.Dir = kernelDir
	cmd.Env = append(cmd.Env, "DIST_DIR=out/dist", fmt.Sprintf("BUILD_CONFIG=%s", buildConfig))

	_, err := osutil.Run(time.Hour, cmd)
	return err
}

func (a android) build(params Params) (ImageDetails, error) {
	var details ImageDetails

	if params.CmdlineFile != "" {
		return details, fmt.Errorf("cmdline file is not supported for android cuttlefish images")
	}
	if params.SysctlFile != "" {
		return details, fmt.Errorf("sysctl file is not supported for android cuttlefish images")
	}

	if err := a.runBuild(params.KernelDir, kernelConfig); err != nil {
		return details, fmt.Errorf("failed to build kernel: %s", err)
	}
	if err := a.runBuild(params.KernelDir, moduleConfig); err != nil {
		return details, fmt.Errorf("failed to build modules: %s", err)
	}

	buildOutDir := filepath.Join(params.KernelDir, "out/dist")
	bzImage := filepath.Join(buildOutDir, "bzImage")
	vmlinux := filepath.Join(buildOutDir, "vmlinux")
	initramfs := filepath.Join(buildOutDir, "initramfs.img")

	if err := buildCuttlefishImage(params, bzImage, vmlinux, initramfs); err != nil {
		return details, fmt.Errorf("failed to build image: %s", err)
	}

	if err := osutil.CopyFile(vmlinux, filepath.Join(params.OutputDir, "kernel")); err != nil {
		return details, err
	}
	if err := osutil.CopyFile(initramfs, filepath.Join(params.OutputDir, "initrd")); err != nil {
		return details, err
	}

	var err error
	details.Signature, err = elfBinarySignature(vmlinux)
	if err != nil {
		return details, fmt.Errorf("failed to generate signature: %s", err)
	}

	return details, nil
}

func (a android) clean(kernelDir, targetArch string) error {
	return osutil.RemoveAll(filepath.Join(kernelDir, "out"))
}
