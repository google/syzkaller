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

	if err := a.runBuild(params.KernelDir, kernelConfig); err != nil {
		return details, fmt.Errorf("failed to build kernel: %s", err)
	}
	if err := a.runBuild(params.KernelDir, moduleConfig); err != nil {
		return details, fmt.Errorf("failed to build modules: %s", err)
	}

	buildOutDir := filepath.Join(params.KernelDir, "out", "dist")
	bzImage := filepath.Join(buildOutDir, "bzImage")
	vmlinux := filepath.Join(buildOutDir, "vmlinux")
	initramfs := filepath.Join(buildOutDir, "initramfs.img")

	var err error
	details.CompilerID, err = a.readCompiler(filepath.Join(buildOutDir, "kernel-headers.tar.gz"))
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

	details.Signature, err = elfBinarySignature(vmlinux, params.Tracer)
	if err != nil {
		return details, fmt.Errorf("failed to generate signature: %s", err)
	}

	return details, nil
}

func (a android) clean(kernelDir, targetArch string) error {
	return osutil.RemoveAll(filepath.Join(kernelDir, "out"))
}
