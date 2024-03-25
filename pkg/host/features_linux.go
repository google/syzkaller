// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package host

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"runtime/debug"
	"strconv"
	"syscall"
	"unsafe"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/linux"
	"golang.org/x/sys/unix"
)

func init() {
	checkFeature[FeatureCoverage] = checkCoverage
	checkFeature[FeatureComparisons] = checkComparisons
	checkFeature[FeatureExtraCoverage] = checkExtraCoverage
	checkFeature[FeatureDelayKcovMmap] = checkDelayKcovMmap
	checkFeature[FeatureSandboxSetuid] = unconditionallyEnabled
	checkFeature[FeatureSandboxNamespace] = checkSandboxNamespace
	checkFeature[FeatureSandboxAndroid] = checkSandboxAndroid
	checkFeature[FeatureFault] = checkFault
	checkFeature[FeatureLeak] = checkLeak
	checkFeature[FeatureNetInjection] = checkNetInjection
	checkFeature[FeatureNetDevices] = unconditionallyEnabled
	checkFeature[FeatureKCSAN] = checkKCSAN
	checkFeature[FeatureDevlinkPCI] = checkDevlinkPCI
	checkFeature[FeatureNicVF] = checkNicVF
	checkFeature[FeatureUSBEmulation] = checkUSBEmulation
	checkFeature[FeatureVhciInjection] = checkVhciInjection
	checkFeature[FeatureWifiEmulation] = checkWifiEmulation
	checkFeature[Feature802154Emulation] = check802154Emulation
	checkFeature[FeatureSwap] = checkSwap
}

func checkCoverage() string {
	if reason := checkDebugFS(); reason != "" {
		return reason
	}
	if !osutil.IsExist("/sys/kernel/debug/kcov") {
		return "CONFIG_KCOV is not enabled"
	}
	if err := osutil.IsAccessible("/sys/kernel/debug/kcov"); err != nil {
		return err.Error()
	}
	return ""
}

func checkComparisons() (reason string) {
	return checkCoverageFeature(FeatureComparisons)
}

func checkExtraCoverage() (reason string) {
	return checkCoverageFeature(FeatureExtraCoverage)
}

func checkDelayKcovMmap() string {
	// The kcov implementation in Linux (currently) does not adequately handle subsequent
	// mmap invocations on the same descriptor. When that problem is fixed, we want
	// syzkaller to differentiate between distributions as this allows to noticeably speed
	// up fuzzing.
	return checkCoverageFeature(FeatureDelayKcovMmap)
}

func kcovTestMmap(fd int, coverSize uintptr) (reason string) {
	mem, err := syscall.Mmap(fd, 0, int(coverSize*unsafe.Sizeof(uintptr(0))),
		syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		return fmt.Sprintf("KCOV mmap failed: %v", err)
	}
	defer func() {
		if err := syscall.Munmap(mem); err != nil {
			reason = fmt.Sprintf("munmap failed: %v", err)
		}
	}()
	// Now the tricky part - mmap may say it has succeeded, but the memory is
	// in fact not allocated.
	// We try to access it. If go does not panic, everything is fine.
	prevValue := debug.SetPanicOnFault(true)
	defer debug.SetPanicOnFault(prevValue)
	defer func() {
		if r := recover(); r != nil {
			reason = "mmap returned an invalid pointer"
		}
	}()
	mem[0] = 0
	return ""
}

func checkCoverageFeature(feature int) (reason string) {
	if reason = checkDebugFS(); reason != "" {
		return reason
	}
	// TODO(dvyukov): this should run under target arch.
	// E.g. KCOV ioctls were initially not supported on 386 (missing compat_ioctl),
	// and a 386 executor won't be able to use them, but an amd64 fuzzer will be.
	fd, err := syscall.Open("/sys/kernel/debug/kcov", syscall.O_RDWR, 0)
	if err != nil {
		return "CONFIG_KCOV is not enabled"
	}
	defer syscall.Close(fd)
	// Trigger host target lazy initialization, it will fill linux.KCOV_INIT_TRACE.
	// It's all wrong and needs to be refactored.
	if _, err := prog.GetTarget(runtime.GOOS, runtime.GOARCH); err != nil {
		return fmt.Sprintf("failed to get target: %v", err)
	}
	coverSize := uintptr(64 << 10)
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL, uintptr(fd), linux.KCOV_INIT_TRACE, coverSize)
	if errno != 0 {
		return fmt.Sprintf("ioctl(KCOV_INIT_TRACE) failed: %v", errno)
	}
	if reason = kcovTestMmap(fd, coverSize); reason != "" {
		return reason
	}
	disableKcov := func() {
		_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), linux.KCOV_DISABLE, 0)
		if errno != 0 {
			reason = fmt.Sprintf("ioctl(KCOV_DISABLE) failed: %v", errno)
		}
	}
	switch feature {
	case FeatureComparisons:
		_, _, errno = syscall.Syscall(syscall.SYS_IOCTL,
			uintptr(fd), linux.KCOV_ENABLE, linux.KCOV_TRACE_CMP)
		if errno != 0 {
			if errno == 524 { // ENOTSUPP
				return "CONFIG_KCOV_ENABLE_COMPARISONS is not enabled"
			}
			return fmt.Sprintf("ioctl(KCOV_TRACE_CMP) failed: %v", errno)
		}
		defer disableKcov()
	case FeatureExtraCoverage:
		arg := KcovRemoteArg{
			TraceMode:    uint32(linux.KCOV_TRACE_PC),
			AreaSize:     uint32(coverSize * unsafe.Sizeof(uintptr(0))),
			NumHandles:   0,
			CommonHandle: 0,
		}
		_, _, errno = syscall.Syscall(syscall.SYS_IOCTL,
			uintptr(fd), linux.KCOV_REMOTE_ENABLE, uintptr(unsafe.Pointer(&arg)))
		if errno != 0 {
			if errno == 25 { // ENOTTY
				return "extra coverage is not supported by the kernel"
			}
			return fmt.Sprintf("ioctl(KCOV_REMOTE_ENABLE) failed: %v", errno)
		}
		defer disableKcov()
	case FeatureDelayKcovMmap:
		if reason = kcovTestMmap(fd, coverSize); reason != "" {
			return reason
		}
	default:
		panic("unknown feature in checkCoverageFeature")
	}
	return ""
}

type KcovRemoteArg struct {
	TraceMode    uint32
	AreaSize     uint32
	NumHandles   uint32
	_            uint32
	CommonHandle uint64
	// Handles []uint64 goes here.
}

func checkFault() string {
	if err := osutil.IsAccessible("/proc/self/make-it-fail"); err != nil {
		return "CONFIG_FAULT_INJECTION is not enabled"
	}
	if err := osutil.IsAccessible("/proc/thread-self/fail-nth"); err != nil {
		return "kernel does not have systematic fault injection support"
	}
	if reason := checkDebugFS(); reason != "" {
		return reason
	}
	if err := osutil.IsAccessible("/sys/kernel/debug/failslab/ignore-gfp-wait"); err != nil {
		return "CONFIG_FAULT_INJECTION_DEBUG_FS or CONFIG_FAILSLAB are not enabled"
	}
	return ""
}

func checkLeak() string {
	if reason := checkDebugFS(); reason != "" {
		return reason
	}
	fd, err := syscall.Open("/sys/kernel/debug/kmemleak", syscall.O_RDWR, 0)
	if err != nil {
		return "CONFIG_DEBUG_KMEMLEAK is not enabled"
	}
	defer syscall.Close(fd)
	if _, err := syscall.Write(fd, []byte("scan=off")); err != nil {
		if err == syscall.EBUSY {
			return "KMEMLEAK disabled: increase CONFIG_DEBUG_KMEMLEAK_EARLY_LOG_SIZE or unset CONFIG_DEBUG_KMEMLEAK_DEFAULT_OFF"
		}
		return fmt.Sprintf("/sys/kernel/debug/kmemleak write failed: %v", err)
	}
	return ""
}

func checkSandboxNamespace() string {
	if err := osutil.IsAccessible("/proc/self/ns/user"); err != nil {
		return err.Error()
	}
	return ""
}

func checkSandboxAndroid() string {
	if err := osutil.IsAccessible("/sys/fs/selinux/policy"); err != nil {
		return err.Error()
	}
	return ""
}

func checkNetInjection() string {
	if err := osutil.IsAccessible("/dev/net/tun"); err != nil {
		return err.Error()
	}
	return ""
}

func checkUSBEmulation() string {
	if err := osutil.IsAccessible("/dev/raw-gadget"); err != nil {
		return err.Error()
	}
	return ""
}

func checkVhciInjection() string {
	if err := osutil.IsAccessible("/dev/vhci"); err != nil {
		return err.Error()
	}
	return ""
}

func checkDebugFS() string {
	if err := osutil.IsAccessible("/sys/kernel/debug"); err != nil {
		return "debugfs is not enabled or not mounted"
	}
	return ""
}

func checkKCSAN() string {
	if err := osutil.IsAccessible("/sys/kernel/debug/kcsan"); err != nil {
		return err.Error()
	}
	return ""
}

func checkDevlinkPCI() string {
	if err := osutil.IsAccessible("/sys/bus/pci/devices/0000:00:10.0/"); err != nil {
		return "PCI device 0000:00:10.0 is not available"
	}
	if err := osutil.IsAccessible("/proc/self/ns/net"); err != nil {
		// Initialize_devlink_pci in executor fails w/o this.
		return "/proc/self/ns/net does not exist"
	}
	return ""
}

func checkNicVF() string {
	if err := osutil.IsAccessible("/sys/bus/pci/devices/0000:00:11.0/"); err != nil {
		return "PCI device 0000:00:11.0 is not available"
	}
	return ""
}

func checkWifiEmulation() string {
	if err := osutil.IsAccessible("/sys/class/mac80211_hwsim/"); err != nil {
		return err.Error()
	}
	// We use HWSIM_ATTR_PERM_ADDR which was added in 4.17.
	return requireKernel(4, 17)
}

func check802154Emulation() string {
	if err := osutil.IsAccessible("/sys/bus/platform/devices/mac802154_hwsim"); err != nil {
		return err.Error()
	}
	return ""
}

func checkSwap() string {
	if err := osutil.IsAccessible("/proc/swaps"); err != nil {
		return err.Error()
	}
	if _, err := exec.LookPath("mkswap"); err != nil {
		return "mkswap is not available"
	}
	// We use fallocate in syz-executor, so let's check if the filesystem supports it.
	// /tmp might not always be the best choice for this
	// (on some systems, a different filesystem might be used for /tmp).
	dir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Sprintf("failed to get home dir: %v", err)
	}
	f, err := os.CreateTemp(dir, "any-file")
	if err != nil {
		return fmt.Sprintf("failed to create temp file: %v", err)
	}
	defer os.Remove(f.Name())
	err = syscall.Fallocate(int(f.Fd()), unix.FALLOC_FL_ZERO_RANGE, 0, 2048)
	if err != nil {
		return fmt.Sprintf("fallocate failed: %v", err)
	}
	return ""
}

func requireKernel(x, y int) string {
	info := new(unix.Utsname)
	if err := unix.Uname(info); err != nil {
		return fmt.Sprintf("uname failed: %v", err)
	}
	ver := string(info.Release[:])
	if ok, bad := matchKernelVersion(ver, x, y); bad {
		return fmt.Sprintf("failed to parse kernel version (%v)", ver)
	} else if !ok {
		return fmt.Sprintf("kernel %v.%v required (have %v)", x, y, ver)
	}
	return ""
}

func matchKernelVersion(ver string, x, y int) (bool, bool) {
	match := kernelVersionRe.FindStringSubmatch(ver)
	if match == nil {
		return false, true
	}
	major, err := strconv.Atoi(match[1])
	if err != nil {
		return false, true
	}
	if major <= 0 || major > 999 {
		return false, true
	}
	minor, err := strconv.Atoi(match[2])
	if err != nil {
		return false, true
	}
	if minor <= 0 || minor > 999 {
		return false, true
	}
	return major*1000+minor >= x*1000+y, false
}

var kernelVersionRe = regexp.MustCompile(`^([0-9]+)\.([0-9]+)`)
