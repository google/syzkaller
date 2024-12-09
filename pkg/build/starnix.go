// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package build

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/sys/targets"
	starnixVM "github.com/google/syzkaller/vm/starnix"
)

type starnix struct{}

// The location of the default ffx build config (a Fuchsia implementation detail),
// relative to the kernel build dir. Contains default relative paths of build
// artifacts.
const ffxBuildConfig = "ffx-config.json"

// The name of the Fuchsia assembly override defined in `overrideRule`.
const overrideName = "syzkaller_starnix"

// A Fuchsia assembly override definition adding a package containing fuzzing dependencies.
var overrideRule = fmt.Sprintf(`import("//build/assembly/developer_overrides.gni")

assembly_developer_overrides("%s") {
    testonly = true
    base_packages = [
        "//src/testing/fuzzing/syzkaller/starnix:syzkaller_starnix",
    ]
}
`, overrideName)

func (st starnix) build(params Params) (ImageDetails, error) {
	sysTarget := targets.Get(targets.Linux, params.TargetArch)
	arch := sysTarget.KernelArch
	if arch != "x86_64" {
		return ImageDetails{}, fmt.Errorf("unsupported starnix arch %v", arch)
	}
	arch = "x64"
	product := fmt.Sprintf("%s.%s", "workbench_eng", arch)

	localDir := filepath.Join(params.KernelDir, "local")
	if err := os.MkdirAll(filepath.Join(params.KernelDir, "local"), 0755); err != nil {
		return ImageDetails{}, err
	}
	overridePath := filepath.Join(localDir, "BUILD.gn")
	if err := os.WriteFile(overridePath, []byte(overrideRule), 0660); err != nil {
		return ImageDetails{}, err
	}
	if err := osutil.SandboxChown(overridePath); err != nil {
		return ImageDetails{}, err
	}
	if err := osutil.SandboxChown(localDir); err != nil {
		return ImageDetails{}, err
	}
	buildSubdir := "out/" + arch
	if _, err := runSandboxed(
		time.Hour,
		params.KernelDir,
		"scripts/fx", "--dir", buildSubdir,
		"set", product,
		"--assembly-override", fmt.Sprintf("//products/workbench/*=//local:%s", overrideName),
	); err != nil {
		return ImageDetails{}, err
	}

	if _, err := runSandboxed(time.Hour*2, params.KernelDir, "scripts/fx", "build"); err != nil {
		return ImageDetails{}, err
	}
	ffxBinary, err := starnixVM.GetToolPath(params.KernelDir, "ffx")
	if err != nil {
		return ImageDetails{}, err
	}
	productBundlePathRaw, err := runSandboxed(
		30*time.Second,
		params.KernelDir,
		ffxBinary,
		"--no-environment",
		"-c", filepath.Join(params.KernelDir, buildSubdir, ffxBuildConfig),
		"-c", "log.enabled=false,ffx.analytics.disabled=true,daemon.autostart=false",
		"config", "get", "product.path",
	)
	if err != nil {
		return ImageDetails{}, err
	}
	productBundlePath := strings.Trim(string(productBundlePathRaw), "\"\n")
	fxfsPathRaw, err := runSandboxed(
		30*time.Second,
		params.KernelDir,
		ffxBinary,
		"--no-environment",
		"-c", "log.enabled=false,ffx.analytics.disabled=true,daemon.autostart=false",
		"product", "get-image-path", productBundlePath,
		"--slot", "a",
		"--image-type", "fxfs",
	)
	if err != nil {
		return ImageDetails{}, err
	}
	fxfsPath := strings.Trim(string(fxfsPathRaw), "\"\n")
	if err := osutil.CopyFile(fxfsPath, filepath.Join(params.OutputDir, "image")); err != nil {
		return ImageDetails{}, err
	}
	kernelObjPath := filepath.Join(params.KernelDir, "out", arch, "exe.unstripped", "starnix_kernel")
	if err := osutil.CopyFile(kernelObjPath, filepath.Join(params.OutputDir, "obj", "vmlinux")); err != nil {
		return ImageDetails{}, err
	}
	return ImageDetails{}, nil
}

func (st starnix) clean(params Params) error {
	_, err := runSandboxed(
		time.Hour,
		params.KernelDir,
		"scripts/fx", "--dir", "out/"+params.TargetArch,
		"clean",
	)
	return err
}
