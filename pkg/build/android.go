// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package build

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
)

const (
	kernelConfig = "common/build.config.gki_kasan.x86_64"
	moduleConfig = "common-modules/virtual-device/build.config.virtual_device_kasan.x86_64"
	bazelTarget  = "//common-modules/virtual-device:virtual_device_x86_64_dist"
)

type android struct{}

func (a android) runBuild(kernelDir, buildConfig string) error {
	cmd := osutil.Command("build/build.sh")
	cmd.Dir = kernelDir
	cmd.Env = append(cmd.Env, "OUT_DIR=out", "DIST_DIR=dist", fmt.Sprintf("BUILD_CONFIG=%s", buildConfig))

	_, err := osutil.Run(time.Hour, cmd)
	return err
}

func (a android) runBazel(kernelDir, buildConfig string) error {
	cmd := osutil.Command("tools/bazel", "run", "--kasan", bazelTarget, "--", "--dist_dir=dist")
	cmd.Dir = kernelDir
	_, err := osutil.Run(time.Hour, cmd)
	return err
}

func (a android) readCompiler(archivePath string) (string, error) {
	f, err := os.Open(archivePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	gr, err := gzip.NewReader(f)
	if err != nil {
		return "", err
	}
	defer gr.Close()

	tr := tar.NewReader(gr)

	h, err := tr.Next()
	for ; err == nil; h, err = tr.Next() {
		if filepath.Base(h.Name) == "compile.h" {
			bytes, err := ioutil.ReadAll(tr)
			if err != nil {
				return "", err
			}
			result := linuxCompilerRegexp.FindSubmatch(bytes)
			if result == nil {
				return "", fmt.Errorf("include/generated/compile.h does not contain build information")
			}

			return string(result[1]), nil
		}
	}

	return "", fmt.Errorf("archive %s doesn't contain include/generated/compile.h", archivePath)
}

func (a android) build(params Params) (ImageDetails, error) {
	var details ImageDetails

	if params.CmdlineFile != "" {
		return details, fmt.Errorf("cmdline file is not supported for android cuttlefish images")
	}
	if params.SysctlFile != "" {
		return details, fmt.Errorf("sysctl file is not supported for android cuttlefish images")
	}

	var config string
	var err error
	// Default to build.sh if compiler is not specified.
	if params.Compiler == "bazel" {
		if err := a.runBazel(params.KernelDir, bazelTarget); err != nil {
			return details, fmt.Errorf("failed to build kernel: %s", err)
		}
		// Find the .config file; it is placed in a temporary output directory during the build.
		cmd := osutil.Command("find", ".", "-wholename", "*virtual_device_x86_64_config/out_dir/.config")
		cmd.Dir = params.KernelDir
		configBytes, err := osutil.Run(time.Minute, cmd)
		if err != nil {
			return details, fmt.Errorf("failed to find build config: %v", err)
		}
		config = filepath.Join(params.KernelDir, strings.TrimSpace(string(configBytes)))
	} else {
		if err := a.runBuild(params.KernelDir, kernelConfig); err != nil {
			return details, fmt.Errorf("failed to build kernel: %s", err)
		}
		if err := a.runBuild(params.KernelDir, moduleConfig); err != nil {
			return details, fmt.Errorf("failed to build modules: %s", err)
		}
		config = filepath.Join(params.KernelDir, "out", "common", ".config")
	}

	buildDistDir := filepath.Join(params.KernelDir, "dist")
	bzImage := filepath.Join(buildDistDir, "bzImage")
	vmlinux := filepath.Join(buildDistDir, "vmlinux")
	initramfs := filepath.Join(buildDistDir, "initramfs.img")

	details.CompilerID, err = a.readCompiler(filepath.Join(buildDistDir, "kernel-headers.tar.gz"))
	if err != nil {
		return details, err
	}

	if err := embedFiles(params, func(mountDir string) error {
		homeDir := filepath.Join(mountDir, "root")

		if err := osutil.CopyFile(bzImage, filepath.Join(homeDir, "bzImage")); err != nil {
			return err
		}
		if err := osutil.CopyFile(vmlinux, filepath.Join(homeDir, "vmlinux")); err != nil {
			return err
		}
		if err := osutil.CopyFile(initramfs, filepath.Join(homeDir, "initramfs.img")); err != nil {
			return err
		}

		return nil
	}); err != nil {
		return details, err
	}

	if err := osutil.CopyFile(vmlinux, filepath.Join(params.OutputDir, "obj", "vmlinux")); err != nil {
		return details, err
	}
	if err := osutil.CopyFile(initramfs, filepath.Join(params.OutputDir, "obj", "initrd")); err != nil {
		return details, err
	}
	if err := osutil.CopyFile(config, filepath.Join(params.OutputDir, "kernel.config")); err != nil {
		return details, err
	}

	details.Signature, err = elfBinarySignature(vmlinux, params.Tracer)
	if err != nil {
		return details, fmt.Errorf("failed to generate signature: %s", err)
	}

	return details, nil
}

func (a android) clean(kernelDir, targetArch string) error {
	return osutil.RemoveAll(filepath.Join(kernelDir, "out"))
}
