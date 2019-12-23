// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package targets

import (
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
	// What OS can build native binaries for this OS.
	// If not set, defaults to itself (i.e. native build).
	// Later we can extend this to be a list, but so far we don't have more than one OS.
	BuildOS string
	// Does the OS use syscall numbers (e.g. Linux) or has interface based on functions (e.g. fuchsia).
	SyscallNumbers bool
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
}

func Get(OS, arch string) *Target {
	target := List[OS][arch]
	if target == nil {
		return nil
	}
	target.init.Do(func() {
		checkOptionalFlags(target)
	})
	return target
}

// nolint: lll
var List = map[string]map[string]*Target{
	"test": {
		"64": {
			PtrSize:  8,
			PageSize: 4 << 10,
			CFlags:   []string{"-m64"},
			// Compile with -no-pie due to issues with ASan + ASLR on ppc64le
			CrossCFlags: []string{"-m64", "-fsanitize=address", "-no-pie"},
			osCommon: osCommon{
				SyscallNumbers:         true,
				SyscallPrefix:          "SYS_",
				ExecutorUsesShmem:      false,
				ExecutorUsesForkServer: false,
				HostFuzzer:             true,
			},
		},
		"64_fork": {
			PtrSize:  8,
			PageSize: 8 << 10,
			CFlags:   []string{"-m64"},
			// Compile with -no-pie due to issues with ASan + ASLR on ppc64le
			CrossCFlags: []string{"-m64", "-fsanitize=address", "-no-pie"},
			osCommon: osCommon{
				SyscallNumbers:         true,
				SyscallPrefix:          "SYS_",
				ExecutorUsesShmem:      false,
				ExecutorUsesForkServer: true,
				HostFuzzer:             true,
			},
		},
		"32_shmem": {
			PtrSize:        4,
			PageSize:       8 << 10,
			Int64Alignment: 4,
			CFlags:         []string{"-m32"},
			CrossCFlags:    []string{"-m32", "-static"},
			osCommon: osCommon{
				SyscallNumbers:         true,
				SyscallPrefix:          "SYS_",
				ExecutorUsesShmem:      true,
				ExecutorUsesForkServer: false,
				HostFuzzer:             true,
			},
		},
		"32_fork_shmem": {
			PtrSize:     4,
			PageSize:    4 << 10,
			CFlags:      []string{"-m32"},
			CrossCFlags: []string{"-m32", "-static"},
			osCommon: osCommon{
				SyscallNumbers:         true,
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
			VMArch:           "amd64",
			PtrSize:          4,
			PageSize:         4 << 10,
			Int64Alignment:   4,
			CFlags:           []string{"-m32"},
			CrossCFlags:      []string{"-m32", "-static"},
			CCompilerPrefix:  "x86_64-linux-gnu-",
			KernelArch:       "i386",
			KernelHeaderArch: "x86",
		},
		"arm64": {
			PtrSize:          8,
			PageSize:         4 << 10,
			CrossCFlags:      []string{"-static"},
			CCompilerPrefix:  "aarch64-linux-gnu-",
			KernelArch:       "arm64",
			KernelHeaderArch: "arm64",
		},
		"arm": {
			VMArch:           "arm64",
			PtrSize:          4,
			PageSize:         4 << 10,
			CFlags:           []string{"-D__LINUX_ARM_ARCH__=6", "-m32", "-D__ARM_EABI__"},
			CrossCFlags:      []string{"-D__LINUX_ARM_ARCH__=6", "-march=armv6", "-static"},
			CCompilerPrefix:  "arm-linux-gnueabi-",
			KernelArch:       "arm",
			KernelHeaderArch: "arm",
		},
		"mips64le": {
			VMArch:           "mips64le",
			PtrSize:          8,
			PageSize:         4 << 10,
			CFlags:           []string{"-D_MIPS_SZLONG=64", "-D__MIPSEL__", "-D__KERNEL__", "-D_MIPS_SIM=_MIPS_SIM_ABI64"},
			CrossCFlags:      []string{"-static", "-march=mips64r2", "-mabi=64", "-EL"},
			CCompilerPrefix:  "mips64el-linux-gnuabi64-",
			KernelArch:       "mips",
			KernelHeaderArch: "mips",
		},
		"ppc64le": {
			PtrSize:  8,
			PageSize: 4 << 10,
			CFlags: []string{
				"-D__powerpc64__",
				"-D__LITTLE_ENDIAN__=1",
				"-D__BYTE_ORDER__=__ORDER_LITTLE_ENDIAN__",
			},
			CrossCFlags:      []string{"-D__powerpc64__", "-static"},
			CCompilerPrefix:  "powerpc64le-linux-gnu-",
			KernelArch:       "powerpc",
			KernelHeaderArch: "powerpc",
		},
	},
	"freebsd": {
		"amd64": {
			PtrSize:           8,
			PageSize:          4 << 10,
			CFlags:            []string{"-m64"},
			CrossCFlags:       []string{"-m64", "-static"},
			NeedSyscallDefine: dontNeedSyscallDefine,
		},
		"386": {
			VMArch:         "amd64",
			PtrSize:        4,
			PageSize:       4 << 10,
			Int64Alignment: 4,
			CFlags:         []string{"-m32"},
			// The story behind -B/usr/lib32 is not completely clear, but it helps in some cases.
			// For context see discussion in https://github.com/google/syzkaller/pull/1202
			CrossCFlags:       []string{"-m32", "-static", "-B/usr/lib32"},
			NeedSyscallDefine: dontNeedSyscallDefine,
		},
	},
	"netbsd": {
		"amd64": {
			PtrSize:  8,
			PageSize: 4 << 10,
			CFlags:   []string{"-m64"},
			CrossCFlags: []string{"-m64", "-static",
				"--sysroot", os.ExpandEnv("${SOURCEDIR}/../dest/"),
			},
			CCompiler: os.ExpandEnv("${SOURCEDIR}/../tools/bin/x86_64--netbsd-g++"),
		},
	},
	"openbsd": {
		"amd64": {
			PtrSize:     8,
			PageSize:    4 << 10,
			CFlags:      []string{"-m64"},
			CCompiler:   "c++",
			CrossCFlags: []string{"-m64", "-static", "-lutil"},
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
			KernelHeaderArch: "x64",
			CCompiler:        os.ExpandEnv("${SOURCEDIR}/prebuilt/third_party/clang/linux-x64/bin/clang"),
			CrossCFlags: []string{
				"-Wno-deprecated",
				"--target=x86_64-fuchsia",
				"-ldriver",
				"-lfdio",
				"-lzircon",
				"--sysroot", os.ExpandEnv("${SOURCEDIR}/out/x64/sdk/exported/zircon_sysroot/arch/x64/sysroot"),
				"-I", os.ExpandEnv("${SOURCEDIR}/zircon/system/ulib/ddk/include"),
				"-I", os.ExpandEnv("${SOURCEDIR}/zircon/system/ulib/fdio/include"),
				"-I", os.ExpandEnv("${SOURCEDIR}/zircon/system/ulib/fidl/include"),
				"-I", os.ExpandEnv("${SOURCEDIR}/out/x64/fidling/gen/zircon/system/fidl/fuchsia-device"),
				"-I", os.ExpandEnv("${SOURCEDIR}/out/x64/fidling/gen/zircon/system/fidl/fuchsia-device-manager"),
				"-I", os.ExpandEnv("${SOURCEDIR}/out/x64/fidling/gen/zircon/system/fidl/fuchsia-hardware-nand"),
				"-I", os.ExpandEnv("${SOURCEDIR}/out/x64/fidling/gen/zircon/system/fidl/fuchsia-hardware-usb-peripheral"),
				"-L", os.ExpandEnv("${SOURCEDIR}/out/x64/x64-shared"),
				"-L", os.ExpandEnv("${SOURCEDIR}/out/x64/gen/zircon/public/lib/fdio"),
			},
		},
		"arm64": {
			PtrSize:          8,
			PageSize:         4 << 10,
			KernelHeaderArch: "arm64",
			CCompiler:        os.ExpandEnv("${SOURCEDIR}/prebuilt/third_party/clang/linux-x64/bin/clang"),
			CrossCFlags: []string{
				"-Wno-deprecated",
				"--target=aarch64-fuchsia",
				"-ldriver",
				"-lfdio",
				"-lzircon",
				"--sysroot", os.ExpandEnv("${SOURCEDIR}/out/arm64/sdk/exported/zircon_sysroot/arch/arm64/sysroot"),
				"-I", os.ExpandEnv("${SOURCEDIR}/zircon/system/ulib/ddk/include"),
				"-I", os.ExpandEnv("${SOURCEDIR}/zircon/system/ulib/fdio/include"),
				"-I", os.ExpandEnv("${SOURCEDIR}/zircon/system/ulib/fidl/include"),
				"-I", os.ExpandEnv("${SOURCEDIR}/out/arm64/fidling/gen/zircon/system/fidl/fuchsia-device"),
				"-I", os.ExpandEnv("${SOURCEDIR}/out/arm64/fidling/gen/zircon/system/fidl/fuchsia-device-manager"),
				"-I", os.ExpandEnv("${SOURCEDIR}/out/arm64/fidling/gen/zircon/system/fidl/fuchsia-hardware-nand"),
				"-I", os.ExpandEnv("${SOURCEDIR}/out/arm64/fidling/gen/zircon/system/fidl/fuchsia-hardware-usb-peripheral"),
				"-L", os.ExpandEnv("${SOURCEDIR}/out/arm64/arm64-shared"),
				"-L", os.ExpandEnv("${SOURCEDIR}/out/arm64/gen/zircon/public/lib/fdio"),
			},
		},
	},
	"windows": {
		"amd64": {
			PtrSize: 8,
			// TODO(dvyukov): what should we do about 4k vs 64k?
			PageSize: 4 << 10,
		},
	},
	"akaros": {
		"amd64": {
			PtrSize:           8,
			PageSize:          4 << 10,
			KernelHeaderArch:  "x86",
			NeedSyscallDefine: dontNeedSyscallDefine,
			CCompiler:         os.ExpandEnv("${SOURCEDIR}/toolchain/x86_64-ucb-akaros-gcc/bin/x86_64-ucb-akaros-g++"),
			CrossCFlags: []string{
				"-static",
			},
		},
	},
	"trusty": {
		"arm": {
			PtrSize:           4,
			PageSize:          4 << 10,
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
	},
	"freebsd": {
		SyscallNumbers:         true,
		SyscallPrefix:          "SYS_",
		ExecutorUsesShmem:      true,
		ExecutorUsesForkServer: true,
		KernelObject:           "kernel.full",
		CPP:                    "g++",
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
		SyscallNumbers: true,
		SyscallPrefix:  "__NR_",
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
		"-Wframe-larger-than=8192",
	}
	optionalCFlags = map[string]bool{
		"-static":                 true, // some distributions don't have static libraries
		"-Wunused-const-variable": true, // gcc 5 does not support this flag
		"-fsanitize=address":      true, // some OSes don't have ASAN
	}
)

func init() {
	for OS, archs := range List {
		for arch, target := range archs {
			initTarget(target, OS, arch)
		}
	}
	goos := runtime.GOOS
	if goos == "android" {
		goos = "linux"
	}
	for _, target := range List["test"] {
		if List[goos] != nil {
			if host := List[goos][runtime.GOARCH]; host != nil {
				target.CCompiler = host.CCompiler
				target.CPP = host.CPP
			}
		}
		target.BuildOS = goos
		if runtime.GOOS == "freebsd" && runtime.GOARCH == "amd64" && target.PtrSize == 4 {
			// -m32 alone does not work on freebsd with gcc.
			// TODO(dvyukov): consider switching to clang on freebsd instead.
			target.CFlags = append(target.CFlags, "-B/usr/lib32")
			target.CrossCFlags = append(target.CrossCFlags, "-B/usr/lib32")
		}
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
	target.DataOffset = 512 << 20
	target.NumPages = (16 << 20) / target.PageSize
	if OS == "linux" && arch == runtime.GOARCH {
		// Don't use cross-compiler for native compilation, there are cases when this does not work:
		// https://github.com/google/syzkaller/pull/619
		// https://github.com/google/syzkaller/issues/387
		// https://github.com/google/syzkaller/commit/06db3cec94c54e1cf720cdd5db72761514569d56
		target.CCompilerPrefix = ""
	}
	if target.CCompiler == "" {
		target.CCompiler = target.CCompilerPrefix + "gcc"
	}
	if target.CPP == "" {
		target.CPP = "cpp"
	}
	if target.BuildOS == "" {
		target.BuildOS = OS
	}
	if runtime.GOOS != target.BuildOS {
		// Spoil native binaries if they are not usable, so that nobody tries to use them later.
		target.CCompiler = fmt.Sprintf("cant-build-%v-on-%v", target.OS, runtime.GOOS)
		target.CPP = target.CCompiler
	}
	target.CrossCFlags = append(append([]string{}, commonCFlags...), target.CrossCFlags...)
}

func checkOptionalFlags(target *Target) {
	if runtime.GOOS != target.BuildOS {
		return
	}
	flags := make(map[string]*bool)
	var wg sync.WaitGroup
	for _, flag := range target.CrossCFlags {
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
	for i := 0; i < len(target.CrossCFlags); i++ {
		if res := flags[target.CrossCFlags[i]]; res != nil && !*res {
			copy(target.CrossCFlags[i:], target.CrossCFlags[i+1:])
			target.CrossCFlags = target.CrossCFlags[:len(target.CrossCFlags)-1]
			i--
		}
	}
}

func checkFlagSupported(target *Target, flag string) bool {
	cmd := exec.Command(target.CCompiler, "-x", "c", "-", "-o", "/dev/null", flag)
	cmd.Stdin = strings.NewReader("int main(){}")
	return cmd.Run() == nil
}

func needSyscallDefine(nr uint64) bool {
	return true
}
func dontNeedSyscallDefine(nr uint64) bool {
	return false
}
