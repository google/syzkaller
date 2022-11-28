// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package build

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/sys/targets"
)

const (
	modulePath      = "common-modules/virtual-device"
	initramfsScript = "config/android-modules/create-initramfs.sh"
	headersScript   = "config/android-modules/zip-kernel-headers.sh"
	moduleEnvVar    = "BUILD_GOLDFISH_DRIVERS=m"
	prebuiltsPath   = "prebuilts/kernel-build-tools/linux-x86/bin/"
)

type android struct{}

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

func (a android) buildCommonKernel(params Params) error {
	commonKernelDir := filepath.Join(params.KernelDir, "common")
	configFile := filepath.Join(commonKernelDir, ".config")
	if err := a.writeFile(configFile, params.Config); err != nil {
		return fmt.Errorf("failed to write config file: %v", err)
	}

	cmd, err := a.makeCmd(params, "olddefconfig")
	if err != nil {
		return fmt.Errorf("failed to create command to make oldconfig: %v", err)
	}
	cmd.Dir = commonKernelDir
	if err := a.runCmd(cmd, params.KernelDir); err != nil {
		return fmt.Errorf("failed to make oldconfig: %v", err)
	}

	// Write updated kernel config early, so that it's captured on build failures.
	outputConfig := filepath.Join(params.OutputDir, "kernel.config")
	if err := osutil.CopyFile(configFile, outputConfig); err != nil {
		return err
	}
	// Ensure CONFIG_GCC_PLUGIN_RANDSTRUCT doesn't prevent ccache usage.
	// See /Documentation/kbuild/reproducible-builds.rst.
	const seed = `const char *randstruct_seed = "e9db0ca5181da2eedb76eba144df7aba4b7f9359040ee58409765f2bdc4cb3b8";`
	gccPluginsDir := filepath.Join(commonKernelDir, "scripts", "gcc-plugins")
	if osutil.IsExist(gccPluginsDir) {
		if err := a.writeFile(filepath.Join(gccPluginsDir, "randomize_layout_seed.h"), []byte(seed)); err != nil {
			return err
		}
	}

	// Different key is generated for each build if key is not provided.
	// see Documentation/reproducible-builds.rst. This is causing problems to our signature calculation.
	certsDir := filepath.Join(commonKernelDir, "certs")
	if osutil.IsExist(certsDir) {
		if err := a.writeFile(filepath.Join(certsDir, "signing_key.pem"), []byte(moduleSigningKey)); err != nil {
			return err
		}
	}

	// Make kernel image and prepare common kernel for modules.
	cmd, err = a.makeCmd(params, "bzImage", "modules", "prepare-objtool")
	if err != nil {
		return fmt.Errorf("failed to create command to make bzImage: %v", err)
	}
	cmd.Dir = commonKernelDir
	if err := a.runCmd(cmd, params.KernelDir); err != nil {
		return fmt.Errorf("failed to make bzImage: %v", err)
	}

	// Install common modules.
	moduleStagingDir := filepath.Join(commonKernelDir, "staging")
	moduleInstallFlag := fmt.Sprintf("INSTALL_MOD_PATH=%v", moduleStagingDir)
	cmd, err = a.makeCmd(params, moduleInstallFlag, "modules_install")
	if err != nil {
		return fmt.Errorf("failed to create command to install modules: %v", err)
	}
	cmd.Dir = commonKernelDir
	if err := a.runCmd(cmd, params.KernelDir); err != nil {
		return fmt.Errorf("failed to install modules: %v", err)
	}
	return nil
}

func (a android) buildExtModules(params Params) error {
	commonKernelDir := filepath.Join(params.KernelDir, "common")

	// Location of external modules relative to common kernel dir.
	mFlag := fmt.Sprintf("M=../%v", modulePath)
	// Absolute location of the kernel source directory.
	srcFlag := fmt.Sprintf("KERNEL_SRC=%v", commonKernelDir)

	moduleStagingDir := filepath.Join(commonKernelDir, "staging")
	moduleInstallFlag := fmt.Sprintf("INSTALL_MOD_PATH=%v", moduleStagingDir)

	// Make external modules.
	cmd, err := a.makeCmd(params, "-C", modulePath, mFlag, srcFlag, moduleInstallFlag)
	if err != nil {
		return fmt.Errorf("failed to create command to make external modules modules: %v", err)
	}
	cmd.Dir = params.KernelDir
	cmd.Env = append([]string{}, moduleEnvVar)
	if err := a.runCmd(cmd, params.KernelDir); err != nil {
		return fmt.Errorf("failed to make external modules: %v", err)
	}

	// Install modules.
	cmd, err = a.makeCmd(params, "-C", modulePath, mFlag, srcFlag, moduleInstallFlag, "modules_install")
	if err != nil {
		return fmt.Errorf("failed to create command to install modules: %v", err)
	}
	cmd.Dir = params.KernelDir
	cmd.Env = append([]string{}, moduleEnvVar)
	if err := a.runCmd(cmd, params.KernelDir); err != nil {
		return fmt.Errorf("failed to install modules: %v", err)
	}

	return nil
}

func (a android) build(params Params) (ImageDetails, error) {
	var details ImageDetails

	if params.CmdlineFile != "" {
		return details, fmt.Errorf("cmdline file is not supported for android cuttlefish images")
	}
	if params.SysctlFile != "" {
		return details, fmt.Errorf("sysctl file is not supported for android cuttlefish images")
	}
	commonKernelDir := filepath.Join(params.KernelDir, "common")

	// Build common kernel.
	if err := a.buildCommonKernel(params); err != nil {
		return details, fmt.Errorf("failed to build android common kernel: %v", err)
	}

	// Build external modules.
	if err := a.buildExtModules(params); err != nil {
		return details, fmt.Errorf("failed to build external modules: %v", err)
	}

	// Zip kernel headers.
	execHeadersScript := fmt.Sprintf("./%v", headersScript)
	cmd := osutil.Command(execHeadersScript, commonKernelDir)
	if err := a.runCmd(cmd, params.KernelDir); err != nil {
		return details, fmt.Errorf("failed to zip kernel headers: %v", err)
	}

	// Create initramfs image.
	execInitramfsScript := fmt.Sprintf("./%v", initramfsScript)
	cmd = osutil.Command(execInitramfsScript, commonKernelDir)
	if err := a.runCmd(cmd, params.KernelDir); err != nil {
		return details, fmt.Errorf("failed to create initramfs image: %v", err)
	}

	bzImage := filepath.Join(commonKernelDir, "arch", "x86", "boot", "bzImage")
	vmlinux := filepath.Join(commonKernelDir, "vmlinux")
	initramfs := filepath.Join(commonKernelDir, "initramfs.img")

	var err error
	details.CompilerID, err = a.readCompiler(filepath.Join(commonKernelDir, "kernel-headers.tar.gz"))
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

func (a android) makeCmd(params Params, extraArgs ...string) (*exec.Cmd, error) {
	target := targets.Get(targets.Linux, params.TargetArch)
	args := LinuxMakeArgs(target, params.Compiler, params.Linker, params.Ccache, "")
	args = append(args, extraArgs...)
	cmd := osutil.Command("make", args...)
	if err := osutil.Sandbox(cmd, true, true); err != nil {
		return cmd, err
	}
	return cmd, nil
}

func (a android) runCmd(cmd *exec.Cmd, kernelDir string) error {
	// Pre-append prebuilts to path.
	absPrebuiltsPath := filepath.Join(kernelDir, prebuiltsPath)
	curPath := os.Getenv("PATH")
	cmd.Env = append(os.Environ(), fmt.Sprintf("PATH=%v:%v", absPrebuiltsPath, curPath))

	cmd.Env = append(cmd.Env,
		"KBUILD_BUILD_VERSION=0",
		"KBUILD_BUILD_TIMESTAMP=now",
		"KBUILD_BUILD_USER=syzkaller",
		"KBUILD_BUILD_HOST=syzkaller",
		"KERNELVERSION=syzkaller",
		"LOCALVERSION=-syzkaller",
	)
	_, err := osutil.Run(time.Hour, cmd)
	return err
}

func (a android) writeFile(file string, data []byte) error {
	if err := osutil.WriteFile(file, data); err != nil {
		return err
	}
	return osutil.SandboxChown(file)
}

func (a android) clean(kernelDir, targetArch string) error {
	if _, err := osutil.RunCmd(time.Second, kernelDir, "rm", "-rf", "common/staging"); err != nil {
		return fmt.Errorf("error removing staging directory: %v", err)
	}
	return runMakeImpl(targetArch, "", "", "", kernelDir, []string{"distclean"})
}
