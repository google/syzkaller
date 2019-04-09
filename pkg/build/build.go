// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package build contains helper functions for building kernels/images.
package build

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
)

// Image creates a disk image for the specified OS/ARCH/VM.
// Kernel is taken from kernelDir, userspace system is taken from userspaceDir.
// If cmdlineFile is not empty, contents of the file are appended to the kernel command line.
// If sysctlFile is not empty, contents of the file are appended to the image /etc/sysctl.conf.
// Output is stored in outputDir and includes (everything except for image is optional):
//  - image: the image
//  - key: ssh key for the image
//  - kernel: kernel for injected boot
//  - initrd: initrd for injected boot
//  - kernel.config: actual kernel config used during build
//  - obj/: directory with kernel object files (this should match KernelObject
//    specified in sys/targets, e.g. vmlinux for linux)
func Image(targetOS, targetArch, vmType, kernelDir, outputDir, compiler, userspaceDir,
	cmdlineFile, sysctlFile string, config []byte) error {
	builder, err := getBuilder(targetOS, targetArch, vmType)
	if err != nil {
		return err
	}
	if err := osutil.MkdirAll(filepath.Join(outputDir, "obj")); err != nil {
		return err
	}
	if len(config) != 0 {
		// Write kernel config early, so that it's captured on build failures.
		if err := osutil.WriteFile(filepath.Join(outputDir, "kernel.config"), config); err != nil {
			return fmt.Errorf("failed to write config file: %v", err)
		}
	}
	err = builder.build(targetArch, vmType, kernelDir, outputDir, compiler, userspaceDir, cmdlineFile, sysctlFile, config)
	return extractRootCause(err)
}

func Clean(targetOS, targetArch, vmType, kernelDir string) error {
	builder, err := getBuilder(targetOS, targetArch, vmType)
	if err != nil {
		return err
	}
	return builder.clean(kernelDir, targetArch)
}

type KernelBuildError struct {
	*osutil.VerboseError
}

type builder interface {
	build(targetArch, vmType, kernelDir, outputDir, compiler, userspaceDir,
		cmdlineFile, sysctlFile string, config []byte) error
	clean(kernelDir, targetArch string) error
}

func getBuilder(targetOS, targetArch, vmType string) (builder, error) {
	var supported = []struct {
		OS   string
		arch string
		vms  []string
		b    builder
	}{
		{"linux", "amd64", []string{"gvisor"}, gvisor{}},
		{"linux", "amd64", []string{"gce", "qemu"}, linux{}},
		{"fuchsia", "amd64", []string{"qemu"}, fuchsia{}},
		{"fuchsia", "arm64", []string{"qemu"}, fuchsia{}},
		{"akaros", "amd64", []string{"qemu"}, akaros{}},
		{"openbsd", "amd64", []string{"gce", "vmm"}, openbsd{}},
		{"netbsd", "amd64", []string{"gce", "qemu"}, netbsd{}},
		{"freebsd", "amd64", []string{"gce", "qemu"}, freebsd{}},
	}
	for _, s := range supported {
		if targetOS == s.OS && targetArch == s.arch {
			for _, vm := range s.vms {
				if vmType == vm {
					return s.b, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("unsupported image type %v/%v/%v", targetOS, targetArch, vmType)
}

func CompilerIdentity(compiler string) (string, error) {
	if compiler == "" {
		return "", nil
	}

	bazel := strings.HasSuffix(compiler, "bazel")

	arg := "--version"
	if bazel {
		arg = ""
	}
	output, err := osutil.RunCmd(time.Minute, "", compiler, arg)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(output), "\n") {
		if bazel {
			// Strip extracting and log lines...
			if strings.Contains(line, "Extracting Bazel") {
				continue
			}
			if strings.HasPrefix(line, "INFO: ") {
				continue
			}
			if strings.HasPrefix(line, "WARNING: ") {
				continue
			}
		}

		return strings.TrimSpace(line), nil
	}
	return "", fmt.Errorf("no output from compiler --version")
}

func extractRootCause(err error) error {
	if err == nil {
		return nil
	}
	verr, ok := err.(*osutil.VerboseError)
	if !ok {
		return err
	}
	cause := extractCauseInner(verr.Output)
	if cause != nil {
		verr.Title = string(cause)
	}
	return KernelBuildError{verr}
}

func extractCauseInner(s []byte) []byte {
	var cause []byte
	for _, line := range bytes.Split(s, []byte{'\n'}) {
		for _, pattern := range buildFailureCauses {
			if pattern.weak && cause != nil {
				continue
			}
			if bytes.Contains(line, pattern.pattern) {
				cause = line
				if pattern.weak {
					break
				}
				return cause
			}
		}
	}
	return cause
}

type buildFailureCause struct {
	pattern []byte
	weak    bool
}

var buildFailureCauses = [...]buildFailureCause{
	{pattern: []byte(": error: ")},
	{pattern: []byte("ERROR: ")},
	{pattern: []byte(": fatal error: ")},
	{pattern: []byte(": undefined reference to")},
	{pattern: []byte(": Permission denied")},
	{weak: true, pattern: []byte(": final link failed: ")},
	{weak: true, pattern: []byte("collect2: error: ")},
	{weak: true, pattern: []byte("FAILED: Build did NOT complete")},
}
