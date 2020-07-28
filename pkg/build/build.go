// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package build contains helper functions for building kernels/images.
package build

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/vcs"
)

// Params is input arguments for the Image function.
type Params struct {
	TargetOS     string
	TargetArch   string
	VMType       string
	KernelDir    string
	OutputDir    string
	Compiler     string
	UserspaceDir string
	CmdlineFile  string
	SysctlFile   string
	Config       []byte
}

// Image creates a disk image for the specified OS/ARCH/VM.
// Kernel is taken from KernelDir, userspace system is taken from UserspaceDir.
// If CmdlineFile is not empty, contents of the file are appended to the kernel command line.
// If SysctlFile is not empty, contents of the file are appended to the image /etc/sysctl.conf.
// Output is stored in OutputDir and includes (everything except for image is optional):
//  - image: the image
//  - key: ssh key for the image
//  - kernel: kernel for injected boot
//  - initrd: initrd for injected boot
//  - kernel.config: actual kernel config used during build
//  - obj/: directory with kernel object files (this should match KernelObject
//    specified in sys/targets, e.g. vmlinux for linux)
// The returned string is a kernel ID that will be the same for kernels with the
// same runtime behavior, and different for kernels with different runtime
// behavior. Binary equal builds, or builds that differ only in e.g. debug info,
// have the same ID. The ID may be empty if OS implementation does not have
// a way to calculate such IDs.
func Image(params *Params) (string, error) {
	builder, err := getBuilder(params.TargetOS, params.TargetArch, params.VMType)
	if err != nil {
		return "", err
	}
	if err := osutil.MkdirAll(filepath.Join(params.OutputDir, "obj")); err != nil {
		return "", err
	}
	if len(params.Config) != 0 {
		// Write kernel config early, so that it's captured on build failures.
		if err := osutil.WriteFile(filepath.Join(params.OutputDir, "kernel.config"), params.Config); err != nil {
			return "", fmt.Errorf("failed to write config file: %v", err)
		}
	}
	err = builder.build(params)
	if err != nil {
		return "", extractRootCause(err, params.TargetOS, params.KernelDir)
	}
	if key := filepath.Join(params.OutputDir, "key"); osutil.IsExist(key) {
		if err := os.Chmod(key, 0600); err != nil {
			return "", fmt.Errorf("failed to chmod 0600 %v: %v", key, err)
		}
	}
	sign := ""
	if signer, ok := builder.(signer); ok {
		sign, err = signer.sign(params)
		if err != nil {
			return "", err
		}
	}
	return sign, nil
}

func Clean(targetOS, targetArch, vmType, kernelDir string) error {
	builder, err := getBuilder(targetOS, targetArch, vmType)
	if err != nil {
		return err
	}
	return builder.clean(kernelDir, targetArch)
}

type KernelError struct {
	Report     []byte
	Output     []byte
	Recipients vcs.Recipients
	guiltyFile string
}

func (err *KernelError) Error() string {
	return string(err.Report)
}

type builder interface {
	build(params *Params) error
	clean(kernelDir, targetArch string) error
}

type signer interface {
	sign(params *Params) (string, error)
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
		{"linux", "ppc64le", []string{"qemu"}, linux{}},
		{"fuchsia", "amd64", []string{"qemu"}, fuchsia{}},
		{"fuchsia", "arm64", []string{"qemu"}, fuchsia{}},
		{"akaros", "amd64", []string{"qemu"}, akaros{}},
		{"openbsd", "amd64", []string{"gce", "vmm"}, openbsd{}},
		{"netbsd", "amd64", []string{"gce", "qemu"}, netbsd{}},
		{"freebsd", "amd64", []string{"gce", "qemu"}, freebsd{}},
		{"test", "64", []string{"qemu"}, test{}},
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

func extractRootCause(err error, OS, kernelSrc string) error {
	if err == nil {
		return nil
	}
	verr, ok := err.(*osutil.VerboseError)
	if !ok {
		return err
	}
	reason, file := extractCauseInner(verr.Output, kernelSrc)
	if len(reason) == 0 {
		return err
	}
	kernelErr := &KernelError{
		Report:     reason,
		Output:     verr.Output,
		guiltyFile: file,
	}
	if file != "" && OS == "linux" {
		maintainers, err := report.GetLinuxMaintainers(kernelSrc, file)
		if err != nil {
			kernelErr.Output = append(kernelErr.Output, err.Error()...)
		}
		kernelErr.Recipients = maintainers
	}
	return kernelErr
}

func extractCauseInner(s []byte, kernelSrc string) ([]byte, string) {
	lines := extractCauseRaw(s)
	const maxLines = 20
	if len(lines) > maxLines {
		lines = lines[:maxLines]
	}
	var stripPrefix []byte
	if kernelSrc != "" {
		stripPrefix = []byte(kernelSrc)
		if stripPrefix[len(stripPrefix)-1] != filepath.Separator {
			stripPrefix = append(stripPrefix, filepath.Separator)
		}
	}
	file := ""
	for i := range lines {
		if stripPrefix != nil {
			lines[i] = bytes.Replace(lines[i], stripPrefix, nil, -1)
		}
		if file == "" {
			for _, fileRe := range fileRes {
				match := fileRe.FindSubmatch(lines[i])
				if match != nil {
					file = string(match[1])
					if file[0] != '/' {
						break
					}
					// We already removed kernel source prefix,
					// if we still have an absolute path, it's probably pointing
					// to compiler/system libraries (not going to work).
					file = ""
				}
			}
		}
	}
	file = strings.TrimPrefix(file, "./")
	if strings.HasSuffix(file, ".o") {
		// Linker may point to object files instead.
		file = strings.TrimSuffix(file, ".o") + ".c"
	}
	res := bytes.Join(lines, []byte{'\n'})
	// gcc uses these weird quotes around identifiers, which may be
	// mis-rendered by systems that don't understand utf-8.
	res = bytes.Replace(res, []byte("‘"), []byte{'\''}, -1)
	res = bytes.Replace(res, []byte("’"), []byte{'\''}, -1)
	return res, file
}

func extractCauseRaw(s []byte) [][]byte {
	weak := true
	var cause [][]byte
	dedup := make(map[string]bool)
	for _, line := range bytes.Split(s, []byte{'\n'}) {
		for _, pattern := range buildFailureCauses {
			if !bytes.Contains(line, pattern.pattern) {
				continue
			}
			if weak && !pattern.weak {
				cause = nil
				dedup = make(map[string]bool)
			}
			if dedup[string(line)] {
				continue
			}
			dedup[string(line)] = true
			if cause == nil {
				weak = pattern.weak
			}
			cause = append(cause, line)
			break
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
	{pattern: []byte(": multiple definition of")},
	{pattern: []byte(": Permission denied")},
	{weak: true, pattern: []byte(": final link failed: ")},
	{weak: true, pattern: []byte("collect2: error: ")},
	{weak: true, pattern: []byte("FAILED: Build did NOT complete")},
}

var fileRes = []*regexp.Regexp{
	regexp.MustCompile(`^([a-zA-Z0-9_\-/.]+):[0-9]+:([0-9]+:)? `),
	regexp.MustCompile(`^(?:ld: )?(([a-zA-Z0-9_\-/.]+?)\.o):`),
	regexp.MustCompile(`; (([a-zA-Z0-9_\-/.]+?)\.o):`),
}
