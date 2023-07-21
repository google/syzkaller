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

	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/osutil"
)

type android struct{}

type BuildParams struct {
	DefconfigFragment string `json:"defconfig_fragment"`
	BuildTarget       string `json:"build_target"`
	BuildScript       string `json:"build_script"`
	VendorBootImage   string `json:"vendor_boot_image"`
}

var ccCompilerRegexp = regexp.MustCompile(`#define\s+CONFIG_CC_VERSION_TEXT\s+"(.*)"`)

func parseConfig(conf []byte) (*BuildParams, error) {
	buildCfg := new(BuildParams)
	if err := config.LoadData(conf, buildCfg); err != nil {
		return nil, fmt.Errorf("failed to parse build config: %w", err)
	}

	if buildCfg.DefconfigFragment == "" {
		return nil, fmt.Errorf("defconfig fragment not specified for Android build")
	}

	if buildCfg.BuildTarget == "" {
		return nil, fmt.Errorf("build target not specified for Android build")
	}

	if buildCfg.BuildScript == "" {
		return nil, fmt.Errorf("build script not specified for Android build")
	}

	if buildCfg.VendorBootImage == "" {
		return nil, fmt.Errorf("vendor boot image not specified for Android build")
	}

	return buildCfg, nil
}

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

	buildCfg, err := parseConfig(params.Build)
	if err != nil {
		return details, fmt.Errorf("error parsing android configs: %w", err)
	}

	// Build kernel.
	cmd := osutil.Command(fmt.Sprintf("./%v", buildCfg.BuildScript))
	cmd.Dir = params.KernelDir
	cmd.Env = append(cmd.Env, "OUT_DIR=out", "DIST_DIR=dist", fmt.Sprintf("GKI_DEFCONFIG_FRAGMENT=%v",
		buildCfg.DefconfigFragment), fmt.Sprintf("BUILD_TARGET=%v", buildCfg.BuildTarget))

	if _, err := osutil.Run(time.Hour, cmd); err != nil {
		return details, fmt.Errorf("failed to build kernel: %w", err)
	}

	buildDistDir := filepath.Join(params.KernelDir, "dist")

	vmlinux := filepath.Join(buildDistDir, "vmlinux")
	config := filepath.Join(params.KernelDir, "out", "mixed", "device-kernel", "private", "gs-google", ".config")

	details.CompilerID, err = a.readCompiler(params.KernelDir)
	if err != nil {
		return details, fmt.Errorf("failed to read compiler: %w", err)
	}

	if err := osutil.CopyFile(vmlinux, filepath.Join(params.OutputDir, "obj", "vmlinux")); err != nil {
		return details, fmt.Errorf("failed to copy vmlinux: %w", err)
	}
	if err := osutil.CopyFile(config, filepath.Join(params.OutputDir, "obj", "kernel.config")); err != nil {
		return details, fmt.Errorf("failed to copy kernel config: %w", err)
	}

	imageFile, err := os.Create(filepath.Join(params.OutputDir, "image"))
	if err != nil {
		return details, fmt.Errorf("failed to create output file: %w", err)
	}
	defer imageFile.Close()

	if err := a.embedImages(imageFile, buildDistDir, "boot.img", "dtbo.img", buildCfg.VendorBootImage,
		"vendor_dlkm.img"); err != nil {
		return details, fmt.Errorf("failed to embed images: %w", err)
	}

	details.Signature, err = elfBinarySignature(vmlinux, params.Tracer)
	if err != nil {
		return details, fmt.Errorf("failed to generate signature: %w", err)
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
			return fmt.Errorf("failed to read %q: %w", name, err)
		}

		if err := tw.WriteHeader(&tar.Header{
			Name: name,
			Mode: 0600,
			Size: int64(len(data)),
		}); err != nil {
			return fmt.Errorf("failed to write header for %q: %w", name, err)
		}

		if _, err := tw.Write(data); err != nil {
			return fmt.Errorf("failed to write data for %q: %w", name, err)
		}
	}

	if err := tw.Close(); err != nil {
		return fmt.Errorf("close archive: %w", err)
	}

	return nil
}

func (a android) clean(kernelDir, targetArch string) error {
	if err := osutil.RemoveAll(filepath.Join(kernelDir, "out")); err != nil {
		return fmt.Errorf("failed to clean 'out' directory: %w", err)
	}
	if err := osutil.RemoveAll(filepath.Join(kernelDir, "dist")); err != nil {
		return fmt.Errorf("failed to clean 'dist' directory: %w", err)
	}
	return nil
}
