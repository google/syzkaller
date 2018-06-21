// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package build contains helper functions for building kernels/images.
package build

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
)

// Image creates a disk image for the specified OS/ARCH/VM.
// Kernel is taken from kernelDir, userspace system is taken from userspaceDir.
// If cmdlineFile is not empty, contents of the file are appended to the kernel command line.
// If sysctlFile is not empty, contents of the file are appended to the image /etc/sysctl.conf.
// Output is stored in outputDir and includes:
//  - image: the image
//  - key: ssh key for the image if applicable
//  - kernel.config: actual kernel config used during build
//  - obj/: directory with kernel object files (e.g. vmlinux for linux)
func Image(targetOS, targetArch, vmType, kernelDir, outputDir, compiler, userspaceDir,
	cmdlineFile, sysctlFile string, config []byte) error {
	builder, err := getBuilder(targetOS, targetArch, vmType)
	if err != nil {
		return err
	}
	return builder.build(targetArch, vmType, kernelDir, outputDir, compiler, userspaceDir, cmdlineFile, sysctlFile, config)
}

func Clean(targetOS, targetArch, vmType, kernelDir string) error {
	builder, err := getBuilder(targetOS, targetArch, vmType)
	if err != nil {
		return err
	}
	return builder.clean(kernelDir)
}

type KernelBuildError struct {
	*osutil.VerboseError
}

type builder interface {
	build(targetArch, vmType, kernelDir, outputDir, compiler, userspaceDir,
		cmdlineFile, sysctlFile string, config []byte) error
	clean(kernelDir string) error
}

func getBuilder(targetOS, targetArch, vmType string) (builder, error) {
	switch {
	case targetOS == "linux" && targetArch == "amd64" && vmType == "gvisor":
		return gvisor{}, nil
	case targetOS == "linux" && targetArch == "amd64" && (vmType == "qemu" || vmType == "gce"):
		return linux{}, nil
	default:
		return nil, fmt.Errorf("unsupported image type %v/%v/%v", targetOS, targetArch, vmType)
	}
}

func CompilerIdentity(compiler string) (string, error) {
	arg := "--version"
	if strings.HasSuffix(compiler, "bazel") {
		arg = ""
	}
	output, err := osutil.RunCmd(time.Minute, "", compiler, arg)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(output), "\n") {
		if strings.Contains(line, "Extracting Bazel") {
			continue
		}
		return strings.TrimSpace(line), nil
	}
	return "", fmt.Errorf("no output from compiler --version")
}
