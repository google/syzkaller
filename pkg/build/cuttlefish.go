// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package build

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
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

type cuttlefish struct{}

func (c cuttlefish) runBuild(kernelDir, buildConfig string) error {
	cmd := osutil.Command("build/build.sh")
	cmd.Dir = kernelDir
	cmd.Env = append(cmd.Env, "OUT_DIR=out", "DIST_DIR=dist", fmt.Sprintf("BUILD_CONFIG=%s", buildConfig))

	_, err := osutil.Run(time.Hour, cmd)
	return err
}

func (c cuttlefish) runBazel(kernelDir string) error {
	cmd := osutil.Command("tools/bazel", "run", bazelTarget, "--", "--dist_dir=dist")
	if err := osutil.Sandbox(cmd, true, false); err != nil {
		return fmt.Errorf("failed to sandbox build command: %w", err)
	}
	cmd.Dir = kernelDir
	_, err := osutil.Run(time.Hour, cmd)
	return err
}

func (c cuttlefish) createDefconfig(commonDir string, config []byte) error {
	configFile := filepath.Join(commonDir, ".config")
	if err := osutil.WriteFile(configFile, config); err != nil {
		return fmt.Errorf("writing config failed: %w", err)
	}
	if err := osutil.SandboxChown(configFile); err != nil {
		return fmt.Errorf("error changing config owner: %w", err)
	}

	// Create a 'defconfig' file from full '.config'.
	cmd := osutil.Command("make", "savedefconfig")
	cmd.Dir = commonDir
	if err := osutil.Sandbox(cmd, true, false); err != nil {
		return fmt.Errorf("failed to sandbox defconfig creation: %w", err)
	}
	if _, err := osutil.Run(time.Hour, cmd); err != nil {
		return fmt.Errorf("failed to create defconfig: %w", err)
	}

	// Copy defconfig to expected config directory.
	defconfigFile := filepath.Join(commonDir, "arch", "x86", "configs", "gki_defconfig")
	if err := os.Rename(filepath.Join(commonDir, "defconfig"), defconfigFile); err != nil {
		return fmt.Errorf("writing config failed: %w", err)
	}
	if err := osutil.SandboxChown(defconfigFile); err != nil {
		return fmt.Errorf("error changing defconfig owner: %w", err)
	}
	if err := os.Remove(configFile); err != nil {
		return fmt.Errorf("failure removing temp config: %w", err)
	}
	return nil
}

func (c cuttlefish) readCompiler(archivePath string) (string, error) {
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
			bytes, err := io.ReadAll(tr)
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

func (c cuttlefish) build(params Params) (ImageDetails, error) {
	var details ImageDetails

	if params.CmdlineFile != "" {
		return details, fmt.Errorf("cmdline file is not supported for android cuttlefish images")
	}
	if params.SysctlFile != "" {
		return details, fmt.Errorf("sysctl file is not supported for android cuttlefish images")
	}

	var config string
	var err error
	// Clean output directory if it exists.
	if err := osutil.RemoveAll(filepath.Join(params.KernelDir, "out")); err != nil {
		return details, fmt.Errorf("failed to clean before kernel build: %w", err)
	}
	// Default to build.sh if compiler is not specified.
	if params.Compiler == "bazel" {
		if params.Config == nil {
			return details, errors.New("kernel config was not provided for build")
		}
		if err := c.createDefconfig(filepath.Join(params.KernelDir, "common"), params.Config); err != nil {
			return details, fmt.Errorf("failed to create defconfig file: %w", err)
		}
		if err := c.runBazel(params.KernelDir); err != nil {
			return details, fmt.Errorf("failed to build kernel: %w", err)
		}
		// Find the .config file; it is placed in a temporary output directory during the build.
		cmd := osutil.Command("find", ".", "-regex", ".*virtual_device_x86_64_config.*/\\.config")
		cmd.Dir = params.KernelDir
		configBytes, err := osutil.Run(time.Minute, cmd)
		if err != nil {
			return details, fmt.Errorf("failed to find build config: %w", err)
		}
		config = filepath.Join(params.KernelDir, strings.TrimSpace(string(configBytes)))
	} else {
		if err := c.runBuild(params.KernelDir, kernelConfig); err != nil {
			return details, fmt.Errorf("failed to build kernel: %w", err)
		}
		if err := c.runBuild(params.KernelDir, moduleConfig); err != nil {
			return details, fmt.Errorf("failed to build modules: %w", err)
		}
		config = filepath.Join(params.KernelDir, "out", "common", ".config")
	}

	buildDistDir := filepath.Join(params.KernelDir, "dist")
	bzImage := filepath.Join(buildDistDir, "bzImage")
	vmlinux := filepath.Join(buildDistDir, "vmlinux")
	initramfs := filepath.Join(buildDistDir, "initramfs.img")

	details.CompilerID, err = c.readCompiler(filepath.Join(buildDistDir, "kernel-headers.tar.gz"))
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
		return details, fmt.Errorf("failed to generate signature: %w", err)
	}

	return details, nil
}

func (c cuttlefish) clean(kernelDir, targetArch string) error {
	if err := osutil.RemoveAll(filepath.Join(kernelDir, "out")); err != nil {
		return err
	}
	return osutil.RemoveAll(filepath.Join(kernelDir, "dist"))
}
