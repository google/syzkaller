// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package build

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
)

type android struct{}

var ccCompilerRegexp = regexp.MustCompile(`#define\s+CONFIG_CC_VERSION_TEXT\s+"(.*)"`)

func (a android) readCompiler(kernelDir string) (string, error) {
	bytes, err := os.ReadFile(filepath.Join(kernelDir, "out", "mixed", "device-kernel", "private",
		"gs-google", "include", "generated", "autoconf.h"))
	if err != nil {
		return "", err
	}
	result := ccCompilerRegexp.FindSubmatch(bytes)
	if result == nil {
		return "", fmt.Errorf("include/generated/autoconf.h does not contain build information")
	}
	return string(result[1]), nil
}

func (a android) build(params Params) (ImageDetails, error) {
	var details ImageDetails
	if params.CmdlineFile != "" {
		return details, fmt.Errorf("cmdline file is not supported for android images")
	}
	if params.SysctlFile != "" {
		return details, fmt.Errorf("sysctl file is not supported for android images")
	}

	// Build kernel.
	cmd := osutil.Command("./build_cloudripper.sh")
	cmd.Dir = params.KernelDir
	// No cloudripper kasan config; currently only slider has a kasan config.
	defconfigFragment := filepath.Join("private", "gs-google", "build.config.slider.kasan")
	buildTarget := "cloudripper_gki_kasan"
	cmd.Env = append(cmd.Env, "OUT_DIR=out", "DIST_DIR=dist", fmt.Sprintf("GKI_DEFCONFIG_FRAGMENT=%v",
		defconfigFragment), fmt.Sprintf("BUILD_TARGET=%v", buildTarget))

	if _, err := osutil.Run(time.Hour, cmd); err != nil {
		return details, fmt.Errorf("failed to build kernel: %s", err)
	}

	buildDistDir := filepath.Join(params.KernelDir, "dist")

	vmlinux := filepath.Join(buildDistDir, "vmlinux")
	config := filepath.Join(params.KernelDir, "out", "mixed", "device-kernel", "private", "gs-google", ".config")

	var err error
	details.CompilerID, err = a.readCompiler(params.KernelDir)
	if err != nil {
		return details, fmt.Errorf("failed to read compiler: %v", err)
	}

	if err := osutil.CopyFile(vmlinux, filepath.Join(params.OutputDir, "obj", "vmlinux")); err != nil {
		return details, fmt.Errorf("failed to copy vmlinux: %v", err)
	}
	if err := osutil.CopyFile(config, filepath.Join(params.OutputDir, "obj", "kernel.config")); err != nil {
		return details, fmt.Errorf("failed to copy kernel config: %v", err)
	}

	imageFile, err := os.Create(filepath.Join(params.OutputDir, "image"))
	if err != nil {
		return details, fmt.Errorf("failed to create output file: %v", err)
	}
	defer imageFile.Close()

	if err := a.embedImages(imageFile, buildDistDir, "boot.img", "dtbo.img", "vendor_kernel_boot.img",
		"vendor_dlkm.img"); err != nil {
		return details, fmt.Errorf("failed to embed images: %v", err)
	}

	details.Signature, err = elfBinarySignature(vmlinux, params.Tracer)
	if err != nil {
		return details, fmt.Errorf("failed to generate signature: %s", err)
	}

	return details, nil
}

func (a android) embedImages(w io.Writer, srcDir string, imageNames ...string) error {
	tw := tar.NewWriter(w)
	defer tw.Close()

	for _, name := range imageNames {
		path := filepath.Join(srcDir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read %q: %v", name, err)
		}

		if err := tw.WriteHeader(&tar.Header{
			Name: name,
			Mode: 0600,
			Size: int64(len(data)),
		}); err != nil {
			return fmt.Errorf("failed to write header for %q: %v", name, err)
		}

		if _, err := tw.Write(data); err != nil {
			return fmt.Errorf("failed to write data for %q: %v", name, err)
		}
	}

	if err := tw.Close(); err != nil {
		return fmt.Errorf("close archive: %v", err)
	}

	return nil
}

func (a android) clean(kernelDir, targetArch string) error {
	if err := osutil.RemoveAll(filepath.Join(kernelDir, "out")); err != nil {
		return fmt.Errorf("failed to clean 'out' directory: %v", err)
	}
	if err := osutil.RemoveAll(filepath.Join(kernelDir, "dist")); err != nil {
		return fmt.Errorf("failed to clean 'dist' directory: %v", err)
	}
	return nil
}
