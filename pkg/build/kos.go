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

type kos struct{}

// Path to the root directory
const SYSROOT = "/opt/KasperskyOS-Community-Edition-1.0.0.69/sysroot-arm-kos/"

// Path to the toolchain
const TOOLCHAIN = "/opt/KasperskyOS-Community-Edition-1.0.0.69/toolchain/"

// Path to the linker script required for the solution build
const LINKER_SCRIPT = "/opt/KasperskyOS-Community-Edition-1.0.0.69/libexec/arm-kos/"

// Path to the precompiled KOS kernel not containing romfs.
const IMG_SRC = "/opt/KasperskyOS-Community-Edition-1.0.0.69/libexec/arm-kos/"

func (ka kos) build(params Params) (ImageDetails, error) {
sysTarget := targets.Get(targets.KOS, params.TargetArch)
if sysTarget == nil {
return ImageDetails{}, fmt.Errorf("unsupported Kaspersky arch %v", params.TargetArch)
}
arch := sysTarget.KernelHeaderArch
kernelKOS := filepath.Join(params.KernelDir, "out", arch, "kos-image")
if _, err := runSandboxed(time.Hour, params.KernelDir,
"makeimg --target="+arch, "--sys-root="+SYSROOT,
"--with-toolchain="+TOOLCHAIN,
"--ldscript="+LINKER_SCRIPT,
"--img-src="+IMG_SRC,
"--img-dst="+kernelKOS,
); err != nil {
return ImageDetails{}, err
}
if _, err := runSandboxed(time.Hour*2, params.KernelDir, "scripts/fx", "clean-build"); err != nil {
return ImageDetails{}, err
}

// Add ssh keys to the zbi image so syzkaller can access the KOS vm.
_, sshKeyPub, err := genSSHKeys(params.OutputDir)
if err != nil {
return ImageDetails{}, err
}

sshKOS := filepath.Join(params.OutputDir, "initrd")

authorizedKeys := fmt.Sprintf("data/ssh/authorized_keys=%s", sshKeyPub)

if _, err := osutil.RunCmd(time.Minute, params.KernelDir, "out/"+arch+"/host_x64/kos",
"-o", sshKOS, kernelKOS, "--entry", authorizedKeys); err != nil {
return ImageDetails{}, err
}
return ImageDetails{}, nil
}

func runKOSSandboxed(timeout time.Duration, dir, command string, arg ...string) ([]byte, error) {
cmd := osutil.Command(command, arg...)
cmd.Dir = dir
if err := osutil.Sandbox(cmd, true, false); err != nil {
return nil, err
}
return osutil.Run(timeout, cmd)
}

func (ka kos) clean(kernelDir, targetArch string) error {
	// We always do clean build because incremental build is frequently broken.
	// So no need to clean separately.
	return nil
}