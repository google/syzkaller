
package targets

import (
	"bytes"
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
	VMArch           string // VM architecture (always amd64 for Linux)
	PtrSize          uint64
	PageSize         uint64
	NumPages         uint64
	DataOffset       uint64
	Int64Alignment   uint64
	BigEndian        bool
	CFlags           []string
	CxxFlags         []string
	Triple           string
	CCompiler        string
	CxxCompiler      string
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
	Addr2Line          func() (string, error)
	KernelAddresses    KernelAddresses

	init      *sync.Once
	initOther *sync.Once
	// Target for the other compiler. If SYZ_CLANG says to use gcc, this will be clang. Or the other way around.
	other    *Target
	timeouts Timeouts
}

// KernelAddresses contain approximate rounded up kernel text/data ranges
// that are used to filter signal and comparisons for bogus/unuseful entries.
// Zero values mean no filtering.
type KernelAddresses struct {
	TextStart uint64
	TextEnd   uint64
	DataStart uint64
	DataEnd   uint64
}

func (target *Target) HasCallNumber(callName string) bool {
	return target.SyscallNumbers && !strings.HasPrefix(callName, "syz_")
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
	// If ExecutorUsesForkServer, executor uses extended protocol with handshake.
	ExecutorUsesForkServer bool
	// Special mode for OSes that do not have support for building Go binaries.
	// In this mode we run Go binaries on the host machine, only executor runs on target.
	HostFuzzer bool
	// How to run syz-execprog/executor directly.
	// Some systems build syz-execprog/executor into their images.
	// If this flag is not empty, syz-execprog/executor will not be copied to the machine, and will be run using
	// this command instead.
	ExecprogBin string
	ExecutorBin string
	// Extension of executable files (notably, .exe for windows).
	ExeExtension string
	// Name of the kernel object file.
	KernelObject string
	// Name of cpp(1) executable.
	CPP string
	// Syscalls on which pseudo syscalls depend. Syzkaller will make sure that __NR* or SYS* definitions
	// for those syscalls are enabled.
	PseudoSyscallDeps map[string][]string
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
	Linux = "linux"
	AMD64 = "amd64"
)

func Get(OS, arch string) *Target {
	return GetEx(OS, arch, useClang)
}

func GetEx(OS, arch string, clang bool) *Target {
	target := List[OS][arch]
	if target == nil {
		return nil
	}
	target.init.Do(target.lazyInit)
	// Always use clang (ignore clang parameter)
	return target
}

// nolint: lll
var List = map[string]map[string]*Target{
	Linux: {
		AMD64: {
			PtrSize:          8,
			PageSize:         4 << 10,
			CFlags:           []string{"-m64"},
			Triple:           "x86_64-linux-gnu",
			KernelArch:       "x86_64",
			KernelHeaderArch: "x86",
			NeedSyscallDefine: func(nr uint64) bool {
				// Only generate defines for new syscalls
				// (added after commit 8a1ab3155c2ac on 2012-10-04).
				return nr >= 313
			},
			KernelAddresses: KernelAddresses{
				// Text/modules range for x86_64.
				TextStart: 0xffffffff80000000,
				TextEnd:   0xffffffffff000000,
				// This range corresponds to the first 1TB of the physical memory mapping,
				// see Documentation/arch/x86/x86_64/mm.rst.
				DataStart: 0xffff880000000000,
				DataEnd:   0xffff890000000000,
			},
		},
	},
}

var oses = map[string]osCommon{
	Linux: {
		SyscallNumbers:         true,
		SyscallPrefix:          "__NR_",
		ExecutorUsesForkServer: true,
		KernelObject:           "vmlinux",
		PseudoSyscallDeps: map[string][]string{
			"syz_read_part_table": {"memfd_create"},
			"syz_mount_image":     {"memfd_create"},
			"syz_io_uring_setup":  {"io_uring_setup"},
			"syz_clone3":          {"clone3", "exit"},
			"syz_clone":           {"clone", "exit"},
			"syz_pidfd_open":      {"pidfd_open"},
		},
		cflags: []string{"-static-pie"},
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
		"-Wno-stringop-overflow",
		"-Wno-array-bounds",
		"-Wno-format-overflow",
		"-Wno-unused-but-set-variable",
		"-Wno-unused-command-line-argument",
	}
	optionalCFlags = map[string]bool{
		"-static":                           true, // some distributions don't have static libraries
		"-static-pie":                       true, // this flag is also not supported everywhere
		"-Wunused-const-variable":           true, // gcc 5 does not support this flag
		"-fsanitize=address":                true, // some OSes don't have ASAN
		"-Wno-stringop-overflow":            true,
		"-Wno-array-bounds":                 true,
		"-Wno-format-overflow":              true,
		"-Wno-unused-but-set-variable":      true,
		"-Wno-unused-command-line-argument": true,
	}
	fallbackCFlags = map[string]string{
		"-static-pie": "-static", // if an ASLR static binary is impossible, build just a static one
	}
	// These are used only when building executor.
	// For C repros and syz-extract, we build C source files.
	commonCxxFlags = []string{
		"-std=c++17",
		"-I.",
		"-Iexecutor/_include",
	}
)

func init() {
	for OS, archs := range List {
		for arch, target := range archs {
			initTarget(target, OS, arch)
		}
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
		target.DataOffset = target.defaultDataOffset()
	}
	target.NumPages = (16 << 20) / target.PageSize
	sourceDir := getSourceDir(target)
	for sourceDir != "" && sourceDir[len(sourceDir)-1] == '/' {
		sourceDir = sourceDir[:len(sourceDir)-1]
	}
	target.replaceSourceDir(&target.CCompiler, sourceDir)
	target.replaceSourceDir(&target.Objdump, sourceDir)
	for i := range target.CFlags {
		target.replaceSourceDir(&target.CFlags[i], sourceDir)
	}

	if cc := os.Getenv("SYZ_CC_" + OS + "_" + arch); cc != "" {
		target.CCompiler = strings.Fields(cc)[0]
		target.CFlags = append(target.CFlags, strings.Fields(cc)[1:]...)
	}
	if cxx := os.Getenv("SYZ_CXX_" + OS + "_" + arch); cxx != "" {
		target.CxxCompiler = strings.Fields(cxx)[0]
		target.CxxFlags = append(target.CxxFlags, strings.Fields(cxx)[1:]...)
	}

	// Always native compilation (linux/amd64 on linux/amd64)
	// Don't use cross-compiler for native compilation
	target.Triple = ""
	if target.CCompiler == "" {
		target.setCompiler(useClang)
	}
	if target.CxxCompiler == "" {
		target.CxxCompiler = strings.TrimSuffix(strings.TrimSuffix(target.CCompiler, "cc"), "++") + "++"
	}
	if target.CPP == "" {
		target.CPP = "cpp"
	}
	if target.Objdump == "" {
		// Always use native objdump (Triple is always "")
		target.Objdump = "objdump"
	}
	// BuildOS defaults to OS (always linux)
	if target.BuildOS == "" {
		target.BuildOS = OS
	}
	for _, flags := range [][]string{commonCFlags, target.osCommon.cflags} {
		target.CFlags = append(target.CFlags, flags...)
	}
	target.HostEndian = binary.LittleEndian
	target.initAddr2Line()
}

func (target *Target) defaultDataOffset() uint64 {
	// An address from ASAN's 64-bit HighMem area for amd64.
	// During real fuzzing, we don't build with ASAN, so the address should not matter much as long as
	// it's far enough from the area allocated by malloc().
	return 0x200000000000
}

func (target *Target) initAddr2Line() {
	// Initialize addr2line lazily since lots of tests don't need it,
	// but we invoke a number of external binaries during addr2line detection.
	var (
		init sync.Once
		bin  string
		err  error
	)
	target.Addr2Line = func() (string, error) {
		init.Do(func() { bin, err = target.findAddr2Line() })
		return bin, err
	}
}

func (target *Target) findAddr2Line() (string, error) {
	// Try llvm-addr2line first as it's significantly faster on large binaries.
	if path, err := exec.LookPath("llvm-addr2line"); err == nil {
		return path, nil
	}
	// Always use native addr2line (Triple is always "")
	return "addr2line", nil
}

func (target *Target) Timeouts(slowdown int) Timeouts {
	if slowdown <= 0 {
		panic(fmt.Sprintf("bad slowdown %v", slowdown))
	}
	timeouts := target.timeouts
	timeouts.Slowdown = slowdown
	timeouts.Scale = min(time.Duration(slowdown), 3)
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

const (
	DefaultLLVMCompiler = "clang"
	DefaultLLVMLinker   = "ld.lld"
)

func (target *Target) setCompiler(clang bool) {
	// Always use clang (ignore parameter for compatibility)
	target.CCompiler = DefaultLLVMCompiler
	target.KernelCompiler = DefaultLLVMCompiler
	target.KernelLinker = DefaultLLVMLinker
	target.CFlags = append(target.CFlags, "-ferror-limit=0")
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
	// Always native build (linux on linux)
	if target.BrokenCompiler != "" {
		return
	}
	// Only fail on CI for native build, or if SOURCEDIR is set
	if !runningOnCI && getSourceDir(target) == "" {
		for _, comp := range []string{target.CCompiler, target.CxxCompiler} {
			if _, err := exec.LookPath(comp); err != nil {
				target.BrokenCompiler = fmt.Sprintf("%v is missing (%v)", comp, err)
				return
			}
		}
	}

	flagsToCheck := append([]string{}, target.CFlags...)
	for _, value := range fallbackCFlags {
		flagsToCheck = append(flagsToCheck, value)
	}

	flags := make(map[string]*bool)
	commonCFlags := []string{}
	uncommonCFlags := []string{}
	var wg sync.WaitGroup
	for _, flag := range flagsToCheck {
		if !optionalCFlags[flag] {
			commonCFlags = append(commonCFlags, flag)
			continue
		}
		uncommonCFlags = append(uncommonCFlags, flag)
	}
	for _, flag := range uncommonCFlags {
		_, exists := flags[flag]
		if exists {
			continue
		}
		res := new(bool)
		flags[flag] = res
		wg.Add(1)
		go func(flag string) {
			defer wg.Done()
			*res = checkFlagSupported(target, commonCFlags, flag)
		}(flag)
	}
	wg.Wait()
	newCFlags := []string{}
	for _, flag := range target.CFlags {
		for {
			if res := flags[flag]; res == nil || *res {
				// The flag is either verified to be supported or must be supported.
				newCFlags = append(newCFlags, flag)
			} else if fallback := fallbackCFlags[flag]; fallback != "" {
				// The flag is not supported, but probably we can replace it by another one.
				flag = fallback
				continue
			}
			break
		}
	}
	target.CFlags = newCFlags
	target.CxxFlags = append(target.CFlags, commonCxxFlags...)
	// Check that the compiler is actually functioning. It may be present, but still broken.
	// Common for Linux distros, over time we've seen:
	//	Error: alignment too large: 15 assumed
	//	fatal error: asm/unistd.h: No such file or directory
	//	fatal error: asm/errno.h: No such file or directory
	//	collect2: error: ld terminated with signal 11 [Segmentation fault]
	if runningOnCI || getSourceDir(target) != "" {
		return // On CI all compilers are expected to work, so we don't do the following check.
	}
	for _, cxx := range []bool{false, true} {
		lang, prog, comp, flags := "c", simpleCProg, target.CCompiler, target.CFlags
		if cxx {
			lang, prog, comp, flags = "c++", simpleCxxProg, target.CxxCompiler, target.CxxFlags
		}
		args := []string{"-x", lang, "-", "-o", "/dev/null"}
		args = append(args, flags...)
		cmd := exec.Command(comp, args...)
		cmd.Stdin = strings.NewReader(prog)
		if out, err := cmd.CombinedOutput(); err != nil {
			target.BrokenCompiler = fmt.Sprintf("error running command: '%s':\ngotoutput: %s",
				comp+" "+strings.Join(args, " "), out)
			return
		}
	}
}

func checkFlagSupported(target *Target, targetCFlags []string, flag string) bool {
	args := []string{"-x", "c++", "-", "-o", "/dev/null", "-Werror", flag}
	args = append(args, targetCFlags...)
	cmd := exec.Command(target.CCompiler, args...)
	cmd.Stdin = strings.NewReader(simpleCProg)
	return cmd.Run() == nil
}

func processMergedFlags(flags []string) []string {
	mutuallyExclusive := [][]string{
		// For GCC, "-static-pie -static" is not equal to "-static".
		// And since we do it anyway, also clean up those that do get overridden -
		// this will improve the flags list readability.
		{"-static", "-static-pie", "-no-pie", "-pie"},
	}
	// For mutually exclusive groups, keep only the last flag.
	for _, group := range mutuallyExclusive {
		m := map[string]bool{}
		for _, s := range group {
			m[s] = true
		}
		keep := ""
		for i := len(flags) - 1; i >= 0; i-- {
			if m[flags[i]] {
				keep = flags[i]
				break
			}
		}
		if keep != "" {
			newFlags := []string{}
			for _, s := range flags {
				if s == keep || !m[s] {
					newFlags = append(newFlags, s)
				}
			}
			flags = newFlags
		}
	}
	// Clean up duplicates.
	dup := map[string]bool{}
	newFlags := []string{}
	for _, s := range flags {
		if dup[s] {
			continue
		}
		newFlags = append(newFlags, s)
		dup[s] = true
	}
	return newFlags
}

func getSourceDir(target *Target) string {
	// First try the most granular env option (hardcoded for linux/amd64).
	name := fmt.Sprintf("SOURCEDIR_%s_%s_LINUX_AMD64",
		strings.ToUpper(target.OS), strings.ToUpper(target.Arch),
	)
	if ret := os.Getenv(name); ret != "" {
		return ret
	}
	// .. then the older one.
	name = fmt.Sprintf("SOURCEDIR_%s", strings.ToUpper(target.OS))
	if ret := os.Getenv(name); ret != "" {
		return ret
	}
	return os.Getenv("SOURCEDIR")
}

func needSyscallDefine(nr uint64) bool     { return true }
func dontNeedSyscallDefine(nr uint64) bool { return false }

var (
	runningOnCI = os.Getenv("CI") != ""
	// Always use clang for amd64
	useClang = true
)

const (
	sourceDirVar = "${SOURCEDIR}"
	simpleCProg  = `
#include <stdio.h>
#include <dirent.h> // ensures that system headers are installed
int main() { printf("Hello, World!\n"); }
`
	simpleCxxProg = `
#include <algorithm> // ensures that C++ headers are installed
#include <vector>
int main() { std::vector<int> v(10); }
`
)
