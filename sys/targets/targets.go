// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package targets

import (
	"encoding/binary"
	"fmt"
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
	VMArch           string // e.g. amd64 for 386, or arm64 for arm
	PtrSize          uint64
	PageSize         uint64
	NumPages         uint64
	DataOffset       uint64
	Int64Alignment   uint64
	LittleEndian     bool
	CFlags           []string
	Triple           string
	CCompiler        string
	Objdump          string // name of objdump executable
	KernelCompiler   string // override CC when running kernel make
	KernelLinker     string // override LD when running kernel make
	KernelArch       string
	KernelHeaderArch string
	BrokenCompiler   string
	// NeedSyscallDefine is used by csource package to decide when to emit __NR_* defines.
	NeedSyscallDefine  func(nr uint64) bool
	HostEndian         binary.ByteOrder
	SyscallTrampolines map[string]string
}

type osCommon struct {
	// What OS can build native binaries for this OS.
	// If not set, defaults to itself (i.e. native build).
	// Later we can extend this to be a list, but so far we don't have more than one OS.
	BuildOS string
	// Does the OS use syscall numbers (e.g. Linux) or has interface based on functions (e.g. fuchsia).
	SyscallNumbers bool
	// Syscalls accept int64 arguments (>sizeof(void*)).
	Int64SyscallArgs bool
	// E.g. "__NR_" or "SYS_".
	SyscallPrefix string
	// ipc<->executor communication tuning.
	// If ExecutorUsesShmem, programs and coverage are passed through shmem, otherwise via pipes.
	ExecutorUsesShmem bool
	// If ExecutorUsesForkServer, executor uses extended protocol with handshake.
	ExecutorUsesForkServer bool
	// Special mode for OSes that do not have support for building Go binaries.
	// In this mode we run Go binaries on the host machine, only executor runs on target.
	HostFuzzer bool
	// How to run syz-executor directly.
	// Some systems build syz-executor into their images.
	// If this flag is not empty, syz-executor will not be copied to the machine, and will be run using
	// this command instead.
	SyzExecutorCmd string
	// Extension of executable files (notably, .exe for windows).
	ExeExtension string
	// Name of the kernel object file.
	KernelObject string
	// Name of cpp(1) executable.
	CPP string
	// Common CFLAGS for this OS.
	cflags []string
}

func Get(OS, arch string) *Target {
	target := List[OS][arch]
	if target == nil {
		return nil
	}
	target.init.Do(target.lazyInit)
	return target
}

// nolint: lll
var List = map[string]map[string]*Target{
	"test": {
		"64": {
			PtrSize:  8,
			PageSize: 4 << 10,
			// Compile with -no-pie due to issues with ASan + ASLR on ppc64le.
			CFlags: []string{"-m64", "-fsanitize=address", "-no-pie"},
			osCommon: osCommon{
				SyscallNumbers:         true,
				SyscallPrefix:          "SYS_",
				ExecutorUsesShmem:      false,
				ExecutorUsesForkServer: false,
			},
		},
		"64_fork": {
			PtrSize:  8,
			PageSize: 8 << 10,
			// Compile with -no-pie due to issues with ASan + ASLR on ppc64le.
			CFlags: []string{"-m64", "-fsanitize=address", "-no-pie"},
			osCommon: osCommon{
				SyscallNumbers:         true,
				SyscallPrefix:          "SYS_",
				ExecutorUsesShmem:      false,
				ExecutorUsesForkServer: true,
			},
		},
		"32_shmem": {
			PtrSize:        4,
			PageSize:       8 << 10,
			Int64Alignment: 4,
			CFlags:         []string{"-m32", "-static"},
			osCommon: osCommon{
				SyscallNumbers:         true,
				Int64SyscallArgs:       true,
				SyscallPrefix:          "SYS_",
				ExecutorUsesShmem:      true,
				ExecutorUsesForkServer: false,
			},
		},
		"32_fork_shmem": {
			PtrSize:  4,
			PageSize: 4 << 10,
			CFlags:   []string{"-m32", "-static"},
			osCommon: osCommon{
				SyscallNumbers:         true,
				Int64SyscallArgs:       true,
				SyscallPrefix:          "SYS_",
				ExecutorUsesShmem:      true,
				ExecutorUsesForkServer: true,
				HostFuzzer:             true,
			},
		},
	},
	"linux": {
		"amd64": {
			PtrSize:          8,
			PageSize:         4 << 10,
			LittleEndian:     true,
			CFlags:           []string{"-m64"},
			Triple:           "x86_64-linux-gnu",
			KernelArch:       "x86_64",
			KernelHeaderArch: "x86",
			NeedSyscallDefine: func(nr uint64) bool {
				// Only generate defines for new syscalls
				// (added after commit 8a1ab3155c2ac on 2012-10-04).
				return nr >= 313
			},
		},
		"386": {
			VMArch:           "amd64",
			PtrSize:          4,
			PageSize:         4 << 10,
			Int64Alignment:   4,
			LittleEndian:     true,
			CFlags:           []string{"-m32"},
			Triple:           "x86_64-linux-gnu",
			KernelArch:       "i386",
			KernelHeaderArch: "x86",
		},
		"arm64": {
			PtrSize:          8,
			PageSize:         4 << 10,
			LittleEndian:     true,
			Triple:           "aarch64-linux-gnu",
			KernelArch:       "arm64",
			KernelHeaderArch: "arm64",
		},
		"arm": {
			VMArch:           "arm64",
			PtrSize:          4,
			PageSize:         4 << 10,
			LittleEndian:     true,
			CFlags:           []string{"-D__LINUX_ARM_ARCH__=6", "-march=armv6"},
			Triple:           "arm-linux-gnueabi",
			KernelArch:       "arm",
			KernelHeaderArch: "arm",
		},
		"mips64le": {
			VMArch:           "mips64le",
			PtrSize:          8,
			PageSize:         4 << 10,
			LittleEndian:     true,
			CFlags:           []string{"-march=mips64r2", "-mabi=64", "-EL"},
			Triple:           "mips64el-linux-gnuabi64",
			KernelArch:       "mips",
			KernelHeaderArch: "mips",
		},
		"ppc64le": {
			PtrSize:          8,
			PageSize:         64 << 10,
			LittleEndian:     true,
			CFlags:           []string{"-D__powerpc64__"},
			Triple:           "powerpc64le-linux-gnu",
			KernelArch:       "powerpc",
			KernelHeaderArch: "powerpc",
		},
		"s390x": {
			PtrSize:          8,
			PageSize:         4 << 10,
			LittleEndian:     false,
			Triple:           "s390x-linux-gnu",
			KernelArch:       "s390",
			KernelHeaderArch: "s390",
			SyscallTrampolines: map[string]string{
				// The s390x Linux syscall ABI allows for upto 5 input parameters passed in registers, and this is not enough
				// for the mmap syscall. Therefore, all input parameters for the mmap syscall are packed into a struct
				// on user stack and the pointer to the struct is passed as an input parameter to the syscall.
				// To work around this problem we therefore reroute the mmap syscall to the glibc mmap wrapper.
				"mmap": "mmap",
			},
		},
		"riscv64": {
			PtrSize:          8,
			PageSize:         4 << 10,
			LittleEndian:     true,
			Triple:           "riscv64-linux-gnu",
			KernelArch:       "riscv",
			KernelHeaderArch: "riscv",
		},
	},
	"freebsd": {
		"amd64": {
			PtrSize:           8,
			PageSize:          4 << 10,
			LittleEndian:      true,
			CCompiler:         "clang",
			CFlags:            []string{"-m64"},
			NeedSyscallDefine: dontNeedSyscallDefine,
		},
		"386": {
			VMArch:   "amd64",
			PtrSize:  4,
			PageSize: 4 << 10,
			// The default DataOffset doesn't work with 32-bit
			// FreeBSD and using ld.lld due to collisions.
			DataOffset:        256 << 20,
			Int64Alignment:    4,
			LittleEndian:      true,
			CCompiler:         "clang",
			CFlags:            []string{"-m32"},
			NeedSyscallDefine: dontNeedSyscallDefine,
		},
	},
	"netbsd": {
		"amd64": {
			PtrSize:      8,
			PageSize:     4 << 10,
			LittleEndian: true,
			CFlags: []string{
				"-m64",
				"-static",
				"--sysroot", sourceDirVar + "/dest/",
			},
			CCompiler: sourceDirVar + "/tools/bin/x86_64--netbsd-g++",
		},
	},
	"openbsd": {
		"amd64": {
			PtrSize:      8,
			PageSize:     4 << 10,
			LittleEndian: true,
			CCompiler:    "c++",
			CFlags:       []string{"-m64", "-static", "-lutil"},
			NeedSyscallDefine: func(nr uint64) bool {
				switch nr {
				case 8: // SYS___tfork
					return true
				case 94: // SYS___thrsleep
					return true
				case 198: // SYS___syscall
					return true
				case 295: // SYS___semctl
					return true
				case 301: // SYS___thrwakeup
					return true
				case 302: // SYS___threxit
					return true
				case 303: // SYS___thrsigdivert
					return true
				case 304: // SYS___getcwd
					return true
				case 329: // SYS___set_tcb
					return true
				case 330: // SYS___get_tcb
					return true
				}
				return false
			},
		},
	},
	"fuchsia": {
		"amd64": {
			PtrSize:          8,
			PageSize:         4 << 10,
			LittleEndian:     true,
			KernelHeaderArch: "x64",
			CCompiler:        sourceDirVar + "/prebuilt/third_party/clang/linux-x64/bin/clang",
			Objdump:          sourceDirVar + "/prebuilt/third_party/clang/linux-x64/bin/llvm-objdump",
			CFlags:           fuchsiaCFlags("x64", "x86_64"),
		},
		"arm64": {
			PtrSize:          8,
			PageSize:         4 << 10,
			LittleEndian:     true,
			KernelHeaderArch: "arm64",
			CCompiler:        sourceDirVar + "/prebuilt/third_party/clang/linux-x64/bin/clang",
			Objdump:          sourceDirVar + "/prebuilt/third_party/clang/linux-x64/bin/llvm-objdump",
			CFlags:           fuchsiaCFlags("arm64", "aarch64"),
		},
	},
	"windows": {
		"amd64": {
			PtrSize: 8,
			// TODO(dvyukov): what should we do about 4k vs 64k?
			PageSize:     4 << 10,
			LittleEndian: true,
		},
	},
	"akaros": {
		"amd64": {
			PtrSize:           8,
			PageSize:          4 << 10,
			LittleEndian:      true,
			KernelHeaderArch:  "x86",
			NeedSyscallDefine: dontNeedSyscallDefine,
			CCompiler:         sourceDirVar + "/toolchain/x86_64-ucb-akaros-gcc/bin/x86_64-ucb-akaros-g++",
			CFlags: []string{
				"-static",
			},
		},
	},
	"trusty": {
		"arm": {
			PtrSize:           4,
			PageSize:          4 << 10,
			LittleEndian:      true,
			NeedSyscallDefine: dontNeedSyscallDefine,
		},
	},
}

var oses = map[string]osCommon{
	"linux": {
		SyscallNumbers:         true,
		SyscallPrefix:          "__NR_",
		ExecutorUsesShmem:      true,
		ExecutorUsesForkServer: true,
		KernelObject:           "vmlinux",
		cflags:                 []string{"-static"},
	},
	"freebsd": {
		SyscallNumbers:         true,
		Int64SyscallArgs:       true,
		SyscallPrefix:          "SYS_",
		ExecutorUsesShmem:      true,
		ExecutorUsesForkServer: true,
		KernelObject:           "kernel.full",
		CPP:                    "g++",
		cflags:                 []string{"-static", "-lc++"},
	},
	"netbsd": {
		BuildOS:                "linux",
		SyscallNumbers:         true,
		SyscallPrefix:          "SYS_",
		ExecutorUsesShmem:      true,
		ExecutorUsesForkServer: true,
		KernelObject:           "netbsd.gdb",
	},
	"openbsd": {
		SyscallNumbers:         true,
		SyscallPrefix:          "SYS_",
		ExecutorUsesShmem:      true,
		ExecutorUsesForkServer: true,
		KernelObject:           "bsd.gdb",
		CPP:                    "ecpp",
	},
	"fuchsia": {
		BuildOS:                "linux",
		SyscallNumbers:         false,
		ExecutorUsesShmem:      false,
		ExecutorUsesForkServer: false,
		HostFuzzer:             true,
		SyzExecutorCmd:         "syz-executor",
		KernelObject:           "zircon.elf",
	},
	"windows": {
		SyscallNumbers:         false,
		ExecutorUsesShmem:      false,
		ExecutorUsesForkServer: false,
		ExeExtension:           ".exe",
		KernelObject:           "vmlinux",
	},
	"akaros": {
		BuildOS:                "linux",
		SyscallNumbers:         true,
		SyscallPrefix:          "SYS_",
		ExecutorUsesShmem:      false,
		ExecutorUsesForkServer: true,
		HostFuzzer:             true,
		KernelObject:           "akaros-kernel-64b",
	},
	"trusty": {
		SyscallNumbers:   true,
		Int64SyscallArgs: true,
		SyscallPrefix:    "__NR_",
	},
}

var (
	commonCFlags = []string{
		"-O2",
		"-pthread",
		"-Wall",
		"-Werror",
		"-Wparentheses",
		"-Wunused-const-variable",
		"-Wframe-larger-than=16384", // executor uses stacks of limited size, so no jumbo frames
	}
	optionalCFlags = map[string]bool{
		"-static":                 true, // some distributions don't have static libraries
		"-Wunused-const-variable": true, // gcc 5 does not support this flag
		"-fsanitize=address":      true, // some OSes don't have ASAN
	}
)

func fuchsiaCFlags(arch, clangArch string) []string {
	out := sourceDirVar + "/out/" + arch
	return []string{
		"-Wno-deprecated",
		"-target", clangArch + "-fuchsia",
		"-ldriver",
		"-lfdio",
		"-lzircon",
		"--sysroot", out + "/zircon_toolchain/obj/zircon/public/sysroot/sysroot",
		"-I", sourceDirVar + "/sdk/lib/fdio/include",
		"-I", sourceDirVar + "/zircon/system/ulib/fidl/include",
		"-I", sourceDirVar + "/src/lib/ddk/include",
		"-I", out + "/fidling/gen/sdk/fidl/fuchsia.device",
		"-I", out + "/fidling/gen/sdk/fidl/fuchsia.device.manager",
		"-I", out + "/fidling/gen/sdk/fidl/fuchsia.hardware.nand",
		"-I", out + "/fidling/gen/sdk/fidl/fuchsia.hardware.power.statecontrol",
		"-I", out + "/fidling/gen/sdk/fidl/fuchsia.hardware.usb.peripheral",
		"-I", out + "/fidling/gen/zircon/vdso/zx",
		"-L", out + "/" + arch + "-shared",
	}
}

func init() {
	for OS, archs := range List {
		for arch, target := range archs {
			initTarget(target, OS, arch)
		}
	}
	goarch := runtime.GOARCH
	goos := runtime.GOOS
	if goos == "android" {
		goos = "linux"
	}
	for _, target := range List["test"] {
		if List[goos] != nil {
			if host := List[goos][goarch]; host != nil {
				target.CCompiler = host.CCompiler
				target.CPP = host.CPP
				if goos == "freebsd" {
					// For some configurations -no-pie is passed to the compiler,
					// which is not used by clang.
					// Ensure clang does not complain about it.
					target.CFlags = append(target.CFlags, "-Wno-unused-command-line-argument")
					// When building executor for the test OS, clang needs
					// to link against the libc++ library.
					target.CFlags = append(target.CFlags, "-lc++")
				}
			}
			if target.PtrSize == 4 && goos == "freebsd" && goarch == "amd64" {
				// A hack to let 32-bit "test" target tests run on FreeBSD:
				// freebsd/386 requires a non-default DataOffset to avoid
				// clobbering mappings created by the C runtime. Since that is the
				// only target with this constraint, just special-case it for now.
				target.DataOffset = List[goos]["386"].DataOffset
			}
		}
		target.BuildOS = goos
	}
}

func initTarget(target *Target, OS, arch string) {
	if common, ok := oses[OS]; ok {
		target.osCommon = common
	}
	target.OS = OS
	target.Arch = arch
	if target.NeedSyscallDefine == nil {
		target.NeedSyscallDefine = needSyscallDefine
	}
	if target.DataOffset == 0 {
		target.DataOffset = 512 << 20
	}
	target.NumPages = (16 << 20) / target.PageSize
	sourceDir := os.Getenv("SOURCEDIR_" + strings.ToUpper(OS))
	if sourceDir == "" {
		sourceDir = os.Getenv("SOURCEDIR")
	}
	for sourceDir != "" && sourceDir[len(sourceDir)-1] == '/' {
		sourceDir = sourceDir[:len(sourceDir)-1]
	}
	target.replaceSourceDir(&target.CCompiler, sourceDir)
	target.replaceSourceDir(&target.Objdump, sourceDir)
	for i := range target.CFlags {
		target.replaceSourceDir(&target.CFlags[i], sourceDir)
	}
	if OS == "linux" && arch == runtime.GOARCH {
		// Don't use cross-compiler for native compilation, there are cases when this does not work:
		// https://github.com/google/syzkaller/pull/619
		// https://github.com/google/syzkaller/issues/387
		// https://github.com/google/syzkaller/commit/06db3cec94c54e1cf720cdd5db72761514569d56
		target.Triple = ""
	}
	if target.CCompiler == "" {
		target.CCompiler = "gcc"
		if target.Triple != "" {
			target.CCompiler = target.Triple + "-" + target.CCompiler
		}
	}
	if useClang {
		target.CCompiler = "clang"
		target.KernelCompiler = "clang"
		target.KernelLinker = "ld.lld"
		if target.Triple != "" {
			target.CFlags = append(target.CFlags, "--target="+target.Triple)
		}
		target.CFlags = append(target.CFlags, "-ferror-limit=0")
	}
	if target.CPP == "" {
		target.CPP = "cpp"
	}
	if target.Objdump == "" {
		target.Objdump = "objdump"
		if target.Triple != "" {
			target.Objdump = target.Triple + "-objdump"
		}
	}
	if target.BuildOS == "" {
		target.BuildOS = OS
	}
	if runtime.GOOS != target.BuildOS {
		// Spoil native binaries if they are not usable, so that nobody tries to use them later.
		target.CCompiler = fmt.Sprintf("cant-build-%v-on-%v", target.OS, runtime.GOOS)
		target.CPP = target.CCompiler
	}
	for _, flags := range [][]string{commonCFlags, target.osCommon.cflags} {
		target.CFlags = append(target.CFlags, flags...)
	}
	if OS == "test" {
		if runtime.GOARCH != "s390x" {
			target.LittleEndian = true
		} else {
			target.LittleEndian = false
		}
	}
	if target.LittleEndian {
		target.HostEndian = binary.LittleEndian
	} else {
		target.HostEndian = binary.BigEndian
	}
}

func (target *Target) replaceSourceDir(param *string, sourceDir string) {
	if !strings.Contains(*param, sourceDirVar) {
		return
	}
	if sourceDir == "" {
		target.BrokenCompiler = "SOURCEDIR is not set"
		return
	}
	*param = strings.ReplaceAll(*param, sourceDirVar, sourceDir)
}

func (target *Target) lazyInit() {
	if runtime.GOOS != target.BuildOS || target.BrokenCompiler != "" {
		return
	}
	// Only fail on CI for native build.
	// On CI we want to fail loudly if cross-compilation breaks.
	// Also fail if SOURCEDIR_GOOS is set b/c in that case user probably assumes it will work.
	if (target.OS != runtime.GOOS || !runningOnCI) && os.Getenv("SOURCEDIR_"+strings.ToUpper(target.OS)) == "" {
		if _, err := exec.LookPath(target.CCompiler); err != nil {
			target.BrokenCompiler = fmt.Sprintf("%v is missing (%v)", target.CCompiler, err)
			return
		}
	}
	flags := make(map[string]*bool)
	var wg sync.WaitGroup
	for _, flag := range target.CFlags {
		if !optionalCFlags[flag] {
			continue
		}
		res := new(bool)
		flags[flag] = res
		wg.Add(1)
		go func(flag string) {
			defer wg.Done()
			*res = checkFlagSupported(target, flag)
		}(flag)
	}
	wg.Wait()
	for i := 0; i < len(target.CFlags); i++ {
		if res := flags[target.CFlags[i]]; res != nil && !*res {
			copy(target.CFlags[i:], target.CFlags[i+1:])
			target.CFlags = target.CFlags[:len(target.CFlags)-1]
			i--
		}
	}
	// Check that the compiler is actually functioning. It may be present, but still broken.
	// Common for Linux distros, over time we've seen:
	//	Error: alignment too large: 15 assumed
	//	fatal error: asm/unistd.h: No such file or directory
	//	fatal error: asm/errno.h: No such file or directory
	//	collect2: error: ld terminated with signal 11 [Segmentation fault]
	if runningOnCI || os.Getenv("SOURCEDIR_"+strings.ToUpper(target.OS)) != "" {
		return // On CI all compilers are expected to work, so we don't do the following check.
	}
	args := []string{"-x", "c++", "-", "-o", "/dev/null"}
	args = append(args, target.CFlags...)
	cmd := exec.Command(target.CCompiler, args...)
	cmd.Stdin = strings.NewReader(simpleProg)
	if out, err := cmd.CombinedOutput(); err != nil {
		target.BrokenCompiler = string(out)
		return
	}
}

func checkFlagSupported(target *Target, flag string) bool {
	cmd := exec.Command(target.CCompiler, "-x", "c++", "-", "-o", "/dev/null", flag)
	cmd.Stdin = strings.NewReader(simpleProg)
	return cmd.Run() == nil
}

func needSyscallDefine(nr uint64) bool     { return true }
func dontNeedSyscallDefine(nr uint64) bool { return false }

var (
	runningOnCI = os.Getenv("CI") != ""
	useClang    = os.Getenv("SYZ_CLANG") != ""
)

const (
	sourceDirVar = "${SOURCEDIR}"
	simpleProg   = `
#include <stdio.h>
#include <dirent.h> // ensures that system headers are installed
#include <algorithm> // ensures that C++ headers are installed
int main() { printf("Hello, World!\n"); }
`
)
