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
	"time"
)

type Target struct {
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

	init      *sync.Once
	initOther *sync.Once
	// Target for the other compiler. If SYZ_CLANG says to use gcc, this will be clang. Or the other way around.
	other    *Target
	timeouts Timeouts
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
	ExecutorBin string
	// Extension of executable files (notably, .exe for windows).
	ExeExtension string
	// Name of the kernel object file.
	KernelObject string
	// Name of cpp(1) executable.
	CPP string
	// Common CFLAGS for this OS.
	cflags []string
}

// Timeouts structure parametrizes timeouts throughout the system.
// It allows to support different operating system, architectures and execution environments
// (emulation, models, etc) without scattering and duplicating knowledge about their execution
// performance everywhere.
// Timeouts calculation consists of 2 parts: base values and scaling.
// Base timeout values consist of a single syscall timeout, program timeout and "no output" timeout
// and are specified by the target (OS/arch), or defaults are used.
// Scaling part is calculated from the execution environment in pkg/mgrconfig based on VM type,
// kernel build type, emulation, etc. Scaling is specifically converged to a single number so that
// it can be specified/overridden for command line tools (e.g. syz-execprog -slowdown=10).
type Timeouts struct {
	// Base scaling factor, used only for a single syscall timeout.
	Slowdown int
	// Capped scaling factor used for timeouts other than syscall timeout.
	// It's already applied to all values in this struct, but can be used for one-off timeout values
	// in the system. This should also be applied to syscall/program timeout attributes in syscall descriptions.
	// Derived from Slowdown and should not be greater than Slowdown.
	// The idea behind capping is that slowdown can be large (10-20) and most timeouts already
	// include some safety margin. If we just multiply them we will get too large timeouts,
	// e.g. program timeout can become 5s*20 = 100s, or "no output" timeout: 5m*20 = 100m.
	Scale time.Duration
	// Timeout for a single syscall, after this time the syscall is considered "blocked".
	Syscall time.Duration
	// Timeout for a single program execution.
	Program time.Duration
	// Timeout for "no output" detection.
	NoOutput time.Duration
	// Limit on a single VM running time, after this time a VM is restarted.
	VMRunningTime time.Duration
	// How long we should test to get "no output" error (derivative of NoOutput, here to avoid duplication).
	NoOutputRunningTime time.Duration
}

const (
	Akaros  = "akaros"
	FreeBSD = "freebsd"
	Fuchsia = "fuchsia"
	Linux   = "linux"
	NetBSD  = "netbsd"
	OpenBSD = "openbsd"
	TestOS  = "test"
	Trusty  = "trusty"
	Windows = "windows"

	AMD64               = "amd64"
	ARM64               = "arm64"
	ARM                 = "arm"
	I386                = "386"
	MIPS64LE            = "mips64le"
	PPC64LE             = "ppc64le"
	S390x               = "s390x"
	RiscV64             = "riscv64"
	TestArch64          = "64"
	TestArch64Fork      = "64_fork"
	TestArch32Shmem     = "32_shmem"
	TestArch32ForkShmem = "32_fork_shmem"
)

func Get(OS, arch string) *Target {
	return GetEx(OS, arch, useClang)
}

func GetEx(OS, arch string, clang bool) *Target {
	target := List[OS][arch]
	if target == nil {
		return nil
	}
	if clang == useClang {
		target.init.Do(target.lazyInit)
		return target
	}
	target.initOther.Do(func() {
		other := new(Target)
		*other = *target
		other.setCompiler(clang)
		other.lazyInit()
		target.other = other
	})
	return target.other
}

// nolint: lll
var List = map[string]map[string]*Target{
	TestOS: {
		TestArch64: {
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
		TestArch64Fork: {
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
		TestArch32Shmem: {
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
		TestArch32ForkShmem: {
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
	Linux: {
		AMD64: {
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
		I386: {
			VMArch:           AMD64,
			PtrSize:          4,
			PageSize:         4 << 10,
			Int64Alignment:   4,
			LittleEndian:     true,
			CFlags:           []string{"-m32"},
			Triple:           "x86_64-linux-gnu",
			KernelArch:       "i386",
			KernelHeaderArch: "x86",
		},
		ARM64: {
			PtrSize:          8,
			PageSize:         4 << 10,
			LittleEndian:     true,
			Triple:           "aarch64-linux-gnu",
			KernelArch:       "arm64",
			KernelHeaderArch: "arm64",
		},
		ARM: {
			VMArch:           ARM64,
			PtrSize:          4,
			PageSize:         4 << 10,
			LittleEndian:     true,
			CFlags:           []string{"-D__LINUX_ARM_ARCH__=6", "-march=armv6"},
			Triple:           "arm-linux-gnueabi",
			KernelArch:       "arm",
			KernelHeaderArch: "arm",
		},
		MIPS64LE: {
			PtrSize:          8,
			PageSize:         4 << 10,
			LittleEndian:     true,
			CFlags:           []string{"-march=mips64r2", "-mabi=64", "-EL"},
			Triple:           "mips64el-linux-gnuabi64",
			KernelArch:       "mips",
			KernelHeaderArch: "mips",
		},
		PPC64LE: {
			PtrSize:          8,
			PageSize:         64 << 10,
			LittleEndian:     true,
			CFlags:           []string{"-D__powerpc64__"},
			Triple:           "powerpc64le-linux-gnu",
			KernelArch:       "powerpc",
			KernelHeaderArch: "powerpc",
		},
		S390x: {
			PtrSize:          8,
			PageSize:         4 << 10,
			DataOffset:       0xfffff000,
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
		RiscV64: {
			PtrSize:          8,
			PageSize:         4 << 10,
			LittleEndian:     true,
			Triple:           "riscv64-linux-gnu",
			KernelArch:       "riscv",
			KernelHeaderArch: "riscv",
		},
	},
	FreeBSD: {
		AMD64: {
			PtrSize:      8,
			PageSize:     4 << 10,
			LittleEndian: true,
			CCompiler:    "clang",
			CFlags:       []string{"-m64"},
			NeedSyscallDefine: func(nr uint64) bool {
				switch nr {
				case 482: // SYS_freebsd_12_shm_open
					return true
				case 571: // SYS_shm_open2
					return true
				case 572: // SYS_shm_rename
					return true
				case 574: // SYS___realpathat
					return true
				case 575: // SYS_close_range
					return true
				}
				return false
			},
		},
		I386: {
			VMArch:   AMD64,
			PtrSize:  4,
			PageSize: 4 << 10,
			// The default DataOffset doesn't work with 32-bit
			// FreeBSD and using ld.lld due to collisions.
			DataOffset:     256 << 20,
			Int64Alignment: 4,
			LittleEndian:   true,
			CCompiler:      "clang",
			CFlags:         []string{"-m32"},
			NeedSyscallDefine: func(nr uint64) bool {
				switch nr {
				case 482: // SYS_freebsd_12_shm_open
					return true
				case 571: // SYS_shm_open2
					return true
				case 572: // SYS_shm_rename
					return true
				case 574: // SYS___realpathat
					return true
				case 575: // SYS_close_range
					return true
				}
				return false
			},
		},
	},
	NetBSD: {
		AMD64: {
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
	OpenBSD: {
		AMD64: {
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
	Fuchsia: {
		AMD64: {
			PtrSize:          8,
			PageSize:         4 << 10,
			LittleEndian:     true,
			KernelHeaderArch: "x64",
			CCompiler:        sourceDirVar + "/prebuilt/third_party/clang/linux-x64/bin/clang",
			Objdump:          sourceDirVar + "/prebuilt/third_party/clang/linux-x64/bin/llvm-objdump",
			CFlags:           fuchsiaCFlags("x64", "x86_64"),
		},
		ARM64: {
			PtrSize:          8,
			PageSize:         4 << 10,
			LittleEndian:     true,
			KernelHeaderArch: ARM64,
			CCompiler:        sourceDirVar + "/prebuilt/third_party/clang/linux-x64/bin/clang",
			Objdump:          sourceDirVar + "/prebuilt/third_party/clang/linux-x64/bin/llvm-objdump",
			CFlags:           fuchsiaCFlags(ARM64, "aarch64"),
		},
	},
	Windows: {
		AMD64: {
			PtrSize: 8,
			// TODO(dvyukov): what should we do about 4k vs 64k?
			PageSize:     4 << 10,
			LittleEndian: true,
		},
	},
	Akaros: {
		AMD64: {
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
	Trusty: {
		ARM: {
			PtrSize:           4,
			PageSize:          4 << 10,
			LittleEndian:      true,
			NeedSyscallDefine: dontNeedSyscallDefine,
		},
	},
}

var oses = map[string]osCommon{
	Linux: {
		SyscallNumbers:         true,
		SyscallPrefix:          "__NR_",
		ExecutorUsesShmem:      true,
		ExecutorUsesForkServer: true,
		KernelObject:           "vmlinux",
		cflags:                 []string{"-static"},
	},
	FreeBSD: {
		SyscallNumbers:         true,
		Int64SyscallArgs:       true,
		SyscallPrefix:          "SYS_",
		ExecutorUsesShmem:      true,
		ExecutorUsesForkServer: true,
		KernelObject:           "kernel.full",
		CPP:                    "g++",
		cflags:                 []string{"-static", "-lc++"},
	},
	NetBSD: {
		BuildOS:                Linux,
		SyscallNumbers:         true,
		SyscallPrefix:          "SYS_",
		ExecutorUsesShmem:      true,
		ExecutorUsesForkServer: true,
		KernelObject:           "netbsd.gdb",
	},
	OpenBSD: {
		SyscallNumbers:         true,
		SyscallPrefix:          "SYS_",
		ExecutorUsesShmem:      true,
		ExecutorUsesForkServer: true,
		KernelObject:           "bsd.gdb",
		CPP:                    "ecpp",
	},
	Fuchsia: {
		BuildOS:                Linux,
		SyscallNumbers:         false,
		ExecutorUsesShmem:      false,
		ExecutorUsesForkServer: false,
		HostFuzzer:             true,
		ExecutorBin:            "syz-executor",
		KernelObject:           "zircon.elf",
	},
	Windows: {
		SyscallNumbers:         false,
		ExecutorUsesShmem:      false,
		ExecutorUsesForkServer: false,
		ExeExtension:           ".exe",
		KernelObject:           "vmlinux",
	},
	Akaros: {
		BuildOS:                Linux,
		SyscallNumbers:         true,
		SyscallPrefix:          "SYS_",
		ExecutorUsesShmem:      false,
		ExecutorUsesForkServer: true,
		HostFuzzer:             true,
		KernelObject:           "akaros-kernel-64b",
	},
	Trusty: {
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
		goos = Linux
	}
	for _, target := range List[TestOS] {
		if List[goos] != nil {
			if host := List[goos][goarch]; host != nil {
				target.CCompiler = host.CCompiler
				target.CPP = host.CPP
				if goos == FreeBSD {
					// For some configurations -no-pie is passed to the compiler,
					// which is not used by clang.
					// Ensure clang does not complain about it.
					target.CFlags = append(target.CFlags, "-Wno-unused-command-line-argument")
					// When building executor for the test OS, clang needs
					// to link against the libc++ library.
					target.CFlags = append(target.CFlags, "-lc++")
				}
				// In ESA/390 mode, the CPU is able to address only 31bit of memory but
				// arithmetic operations are still 32bit
				// Fix cflags by replacing compiler's -m32 option with -m31
				if goarch == S390x {
					for i := range target.CFlags {
						target.CFlags[i] = strings.Replace(target.CFlags[i], "-m32", "-m31", -1)
					}
				}
			}
			if target.PtrSize == 4 && goos == FreeBSD && goarch == AMD64 {
				// A hack to let 32-bit "test" target tests run on FreeBSD:
				// freebsd/386 requires a non-default DataOffset to avoid
				// clobbering mappings created by the C runtime. Since that is the
				// only target with this constraint, just special-case it for now.
				target.DataOffset = List[goos][I386].DataOffset
			}
		}
		target.BuildOS = goos
	}
}

func initTarget(target *Target, OS, arch string) {
	if common, ok := oses[OS]; ok {
		target.osCommon = common
	}
	target.init = new(sync.Once)
	target.initOther = new(sync.Once)
	target.OS = OS
	target.Arch = arch
	if target.KernelArch == "" {
		target.KernelArch = target.Arch
	}
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
	if OS == Linux && arch == runtime.GOARCH {
		// Don't use cross-compiler for native compilation, there are cases when this does not work:
		// https://github.com/google/syzkaller/pull/619
		// https://github.com/google/syzkaller/issues/387
		// https://github.com/google/syzkaller/commit/06db3cec94c54e1cf720cdd5db72761514569d56
		target.Triple = ""
	}
	if target.CCompiler == "" {
		target.setCompiler(useClang)
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
	if OS == TestOS {
		if runtime.GOARCH != S390x {
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

func (target *Target) Timeouts(slowdown int) Timeouts {
	if slowdown <= 0 {
		panic(fmt.Sprintf("bad slowdown %v", slowdown))
	}
	timeouts := target.timeouts
	timeouts.Slowdown = slowdown
	timeouts.Scale = time.Duration(slowdown)
	if timeouts.Scale > 3 {
		timeouts.Scale = 3
	}
	if timeouts.Syscall == 0 {
		timeouts.Syscall = 50 * time.Millisecond
	}
	if timeouts.Program == 0 {
		timeouts.Program = 5 * time.Second
	}
	if timeouts.NoOutput == 0 {
		// The timeout used to be 3 mins for a long time.
		// But (1) we were seeing flakes on linux where net namespace
		// destruction can be really slow, and (2) gVisor watchdog timeout
		// is 3 mins + 1/4 of that for checking period = 3m45s.
		// Current linux max timeout is CONFIG_DEFAULT_HUNG_TASK_TIMEOUT=140
		// and workqueue.watchdog_thresh=140 which both actually result
		// in 140-280s detection delay.
		// So the current timeout is 5 mins (300s).
		// We don't want it to be too long too because it will waste time on real hangs.
		timeouts.NoOutput = 5 * time.Minute
	}
	if timeouts.VMRunningTime == 0 {
		timeouts.VMRunningTime = time.Hour
	}
	timeouts.Syscall *= time.Duration(slowdown)
	timeouts.Program *= timeouts.Scale
	timeouts.NoOutput *= timeouts.Scale
	timeouts.VMRunningTime *= timeouts.Scale
	timeouts.NoOutputRunningTime = timeouts.NoOutput + time.Minute
	return timeouts
}

func (target *Target) setCompiler(clang bool) {
	// setCompiler may be called effectively twice for target.other,
	// so first we remove flags the previous call may have added.
	pos := 0
	for _, flag := range target.CFlags {
		if flag == "-ferror-limit=0" ||
			strings.HasPrefix(flag, "--target=") {
			continue
		}
		target.CFlags[pos] = flag
		pos++
	}
	target.CFlags = target.CFlags[:pos]
	if clang {
		target.CCompiler = "clang"
		target.KernelCompiler = "clang"
		target.KernelLinker = "ld.lld"
		if target.Triple != "" {
			target.CFlags = append(target.CFlags, "--target="+target.Triple)
		}
		target.CFlags = append(target.CFlags, "-ferror-limit=0")
	} else {
		target.CCompiler = "gcc"
		target.KernelCompiler = ""
		target.KernelLinker = ""
		if target.Triple != "" {
			target.CCompiler = target.Triple + "-" + target.CCompiler
		}
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
	*param = strings.Replace(*param, sourceDirVar, sourceDir, -1)
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
