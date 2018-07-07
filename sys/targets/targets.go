// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package targets

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
)

type Target struct {
	init sync.Once
	osCommon
	OS               string
	Arch             string
	PtrSize          uint64
	PageSize         uint64
	NumPages         uint64
	DataOffset       uint64
	CArch            []string
	CFlags           []string
	CrossCFlags      []string
	CCompilerPrefix  string
	CCompiler        string
	KernelArch       string
	KernelHeaderArch string
	// NeedSyscallDefine is used by csource package to decide when to emit __NR_* defines.
	NeedSyscallDefine func(nr uint64) bool
}

type osCommon struct {
	// Does the OS use syscall numbers (e.g. Linux) or has interface based on functions (e.g. fuchsia).
	SyscallNumbers bool
	// E.g. "__NR_" or "SYS_".
	SyscallPrefix string
	// ipc<->executor communication tuning.
	// If ExecutorUsesShmem, programs and coverage are passed through shmem, otherwise via pipes.
	ExecutorUsesShmem bool
	// If ExecutorUsesForkServer, executor uses extended protocol with handshake.
	ExecutorUsesForkServer bool
	// Extension of executable files (notably, .exe for windows).
	ExeExtension string
}

func Get(OS, arch string) *Target {
	target := List[OS][arch]
	if target == nil {
		return nil
	}
	target.init.Do(func() {
		checkStaticBuild(target)
	})
	return target
}

// nolint: lll
var List = map[string]map[string]*Target{
	"test": map[string]*Target{
		"32": {
			PtrSize:  4,
			PageSize: 8 << 10,
		},
		"64": {
			PtrSize:  8,
			PageSize: 4 << 10,
		},
	},
	"linux": map[string]*Target{
		"amd64": {
			PtrSize:          8,
			PageSize:         4 << 10,
			CArch:            []string{"__x86_64__"},
			CFlags:           []string{"-m64"},
			CrossCFlags:      []string{"-m64", "-static"},
			CCompilerPrefix:  "x86_64-linux-gnu-",
			KernelArch:       "x86_64",
			KernelHeaderArch: "x86",
			NeedSyscallDefine: func(nr uint64) bool {
				// Only generate defines for new syscalls
				// (added after commit 8a1ab3155c2ac on 2012-10-04).
				return nr >= 313
			},
		},
		"386": {
			PtrSize:          4,
			PageSize:         4 << 10,
			CArch:            []string{"__i386__"},
			CFlags:           []string{"-m32"},
			CrossCFlags:      []string{"-m32", "-static"},
			CCompilerPrefix:  "x86_64-linux-gnu-",
			KernelArch:       "i386",
			KernelHeaderArch: "x86",
		},
		"arm64": {
			PtrSize:          8,
			PageSize:         4 << 10,
			CArch:            []string{"__aarch64__"},
			CrossCFlags:      []string{"-static"},
			CCompilerPrefix:  "aarch64-linux-gnu-",
			KernelArch:       "arm64",
			KernelHeaderArch: "arm64",
		},
		"arm": {
			PtrSize:          4,
			PageSize:         4 << 10,
			CArch:            []string{"__arm__"},
			CFlags:           []string{"-D__LINUX_ARM_ARCH__=6", "-m32", "-D__ARM_EABI__"},
			CrossCFlags:      []string{"-D__LINUX_ARM_ARCH__=6", "-march=armv6t2", "-static"},
			CCompilerPrefix:  "arm-linux-gnueabihf-",
			KernelArch:       "arm",
			KernelHeaderArch: "arm",
		},
		"ppc64le": {
			PtrSize:          8,
			PageSize:         4 << 10,
			CArch:            []string{"__ppc64__", "__PPC64__", "__powerpc64__"},
			CFlags:           []string{"-D__powerpc64__"},
			CrossCFlags:      []string{"-D__powerpc64__", "-static"},
			CCompilerPrefix:  "powerpc64le-linux-gnu-",
			KernelArch:       "powerpc",
			KernelHeaderArch: "powerpc",
		},
	},
	"freebsd": map[string]*Target{
		"amd64": {
			PtrSize:     8,
			PageSize:    4 << 10,
			CArch:       []string{"__x86_64__"},
			CFlags:      []string{"-m64"},
			CrossCFlags: []string{"-m64", "-static"},
		},
	},
	"netbsd": map[string]*Target{
		"amd64": {
			PtrSize:     8,
			PageSize:    4 << 10,
			CArch:       []string{"__x86_64__"},
			CFlags:      []string{"-m64"},
			CrossCFlags: []string{"-m64", "-static"},
		},
	},
	"fuchsia": map[string]*Target{
		"amd64": {
			PtrSize:          8,
			PageSize:         4 << 10,
			CArch:            []string{"__x86_64__"},
			KernelHeaderArch: "x64",
			CCompiler:        os.ExpandEnv("${SOURCEDIR}/buildtools/linux-x64/clang/bin/clang++"),
			CrossCFlags: []string{
				"-Wno-deprecated",
				"-Wno-error",
				"--target=x86_64-fuchsia",
				"-lfdio",
				"-lzircon",
				"-ldriver",
				"--sysroot", os.ExpandEnv("${SOURCEDIR}/out/build-zircon/build-x64/sysroot"),
				"-L", os.ExpandEnv("${SOURCEDIR}/out/x64/x64-shared"),
				"-L", os.ExpandEnv("${SOURCEDIR}/out/x64/sdks/zircon_sysroot/sysroot/lib"),
				"-L", os.ExpandEnv("${SOURCEDIR}/out/build-zircon/build-x64/system/ulib/driver"),
			},
		},
		"arm64": {
			PtrSize:          8,
			PageSize:         4 << 10,
			CArch:            []string{"__aarch64__"},
			KernelHeaderArch: "arm64",
			CCompiler:        os.ExpandEnv("${SOURCEDIR}/buildtools/linux-x64/clang/bin/clang++"),
			CrossCFlags: []string{
				"-Wno-deprecated",
				"-Wno-error",
				"--target=aarch64-fuchsia",
				"-lfdio",
				"-lzircon",
				"-ldriver",
				"--sysroot", os.ExpandEnv("${SOURCEDIR}/out/build-zircon/build-arm64/sysroot"),
				"-L", os.ExpandEnv("${SOURCEDIR}/out/arm64/arm64-shared"),
				"-L", os.ExpandEnv("${SOURCEDIR}/out/arm64/sdks/zircon_sysroot/sysroot/lib"),
				"-L", os.ExpandEnv("${SOURCEDIR}/out/build-zircon/build-arm64/system/ulib/driver"),
			},
		},
	},
	"windows": map[string]*Target{
		"amd64": {
			PtrSize: 8,
			// TODO(dvyukov): what should we do about 4k vs 64k?
			PageSize: 4 << 10,
			CArch:    []string{"_M_X64"},
		},
	},
	"akaros": map[string]*Target{
		"amd64": {
			PtrSize:           8,
			PageSize:          4 << 10,
			CArch:             []string{"__x86_64__"},
			KernelHeaderArch:  "x86",
			NeedSyscallDefine: dontNeedSyscallDefine,
			CCompiler:         os.ExpandEnv("${SOURCEDIR}/toolchain/x86_64-ucb-akaros-gcc/bin/x86_64-ucb-akaros-g++"),
			CrossCFlags: []string{
				"-static",
			},
		},
	},
}

var oses = map[string]osCommon{
	"linux": {
		SyscallNumbers:         true,
		SyscallPrefix:          "__NR_",
		ExecutorUsesShmem:      true,
		ExecutorUsesForkServer: true,
	},
	"freebsd": {
		SyscallNumbers:         true,
		SyscallPrefix:          "SYS_",
		ExecutorUsesShmem:      true,
		ExecutorUsesForkServer: true,
	},
	"netbsd": {
		SyscallNumbers:         true,
		SyscallPrefix:          "SYS_",
		ExecutorUsesShmem:      true,
		ExecutorUsesForkServer: true,
	},
	"fuchsia": {
		SyscallNumbers:         false,
		ExecutorUsesShmem:      false,
		ExecutorUsesForkServer: false,
	},
	"windows": {
		SyscallNumbers:         false,
		ExecutorUsesShmem:      false,
		ExecutorUsesForkServer: false,
		ExeExtension:           ".exe",
	},
	"akaros": {
		SyscallNumbers:         true,
		SyscallPrefix:          "SYS_",
		ExecutorUsesShmem:      false,
		ExecutorUsesForkServer: true,
	},
}

func init() {
	for OS, archs := range List {
		for arch, target := range archs {
			initTarget(target, OS, arch)
		}
	}
}

func initTarget(target *Target, OS, arch string) {
	target.osCommon = oses[OS]
	target.OS = OS
	target.Arch = arch
	if target.NeedSyscallDefine == nil {
		target.NeedSyscallDefine = needSyscallDefine
	}
	target.DataOffset = 512 << 20
	target.NumPages = (16 << 20) / target.PageSize
	if OS == runtime.GOOS && arch == runtime.GOARCH {
		// Don't use cross-compiler for native compilation, there are cases when this does not work:
		// https://github.com/google/syzkaller/pull/619
		// https://github.com/google/syzkaller/issues/387
		// https://github.com/google/syzkaller/commit/06db3cec94c54e1cf720cdd5db72761514569d56
		target.CCompilerPrefix = ""
	}
	if target.CCompiler == "" {
		target.CCompiler = target.CCompilerPrefix + "gcc"
	}
}

func checkStaticBuild(target *Target) {
	for i, flag := range target.CrossCFlags {
		if flag == "-static" {
			// Some distributions don't have static libraries.
			if !supportsStatic(target) {
				copy(target.CrossCFlags[i:], target.CrossCFlags[i+1:])
				target.CrossCFlags = target.CrossCFlags[:len(target.CrossCFlags)-1]
			}
			break
		}
	}
}

func supportsStatic(target *Target) bool {
	cmd := exec.Command(target.CCompiler, "-x", "c", "-", "-o", "/dev/null", "-static")
	cmd.Stdin = strings.NewReader("int main(){}")
	return cmd.Run() == nil
}

func needSyscallDefine(nr uint64) bool {
	return true
}
func dontNeedSyscallDefine(nr uint64) bool {
	return false
}
