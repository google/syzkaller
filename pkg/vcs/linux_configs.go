// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vcs

import (
	"strings"

	"github.com/google/syzkaller/pkg/debugtracer"
	"github.com/google/syzkaller/pkg/kconfig"
	"github.com/google/syzkaller/pkg/report/crash"
)

// setLinuxTagConfigs() disables Linux kernel configurations depending on the Linux kernel version,
// which is determined by the git tags reachable from HEAD.
// The problem is that Linux kernel is regularly broken w.r.t syzbot configs, especially on older versions.
func setLinuxTagConfigs(cf *kconfig.ConfigFile, tags map[string]bool) {
	const disableAlways = "disable-always"
	// If tags is nil, disable only configs marked as disableAlways.
	checkTag := func(tag string) bool {
		return tags != nil && !tags[tag] ||
			tags == nil && tag == disableAlways
	}
	disable := map[string]string{
		// 5.2 has CONFIG_SECURITY_TOMOYO_INSECURE_BUILTIN_SETTING which allows to test tomoyo better.
		// This config also enables CONFIG_SECURITY_TOMOYO_OMIT_USERSPACE_LOADER
		// but we need it disabled to boot older kernels.
		"SECURITY_TOMOYO_OMIT_USERSPACE_LOADER": "v5.2",
		// Kernel is boot broken before 4.15 due to double-free in vudc_probe:
		// https://lkml.org/lkml/2018/9/7/648
		// Fixed by e28fd56ad5273be67d0fae5bedc7e1680e729952.
		"USBIP_VUDC": "v4.15",
		// CONFIG_CAN causes:
		// all runs: crashed: INFO: trying to register non-static key in can_notifier
		// for v4.11..v4.12 and v4.12..v4.13 ranges.
		// Fixed by 74b7b490886852582d986a33443c2ffa50970169.
		"CAN": "v4.13",
		// Setup of network devices is broken before v4.12 with a "WARNING in hsr_get_node".
		// Fixed by 675c8da049fd6556eb2d6cdd745fe812752f07a8.
		"HSR": "v4.12",
		// Setup of network devices is broken before v4.12 with a "WARNING: ODEBUG bug in __sk_destruct"
		// coming from smc_release.
		"SMC": "v4.12",
		// Kernel is boot broken before 4.10 with a lockdep warning in vhci_hcd_probe.
		"USBIP_VHCI_HCD": "v4.10",
		"BT_HCIVHCI":     "v4.10",
		// Setup of network devices is broken before v4.7 with a deadlock involving team.
		"NET_TEAM": "v4.7",
		// Setup of network devices is broken before v4.5 with a warning in batadv_tvlv_container_remove.
		"BATMAN_ADV": "v4.5",
		// UBSAN is broken in multiple ways before v5.3, see:
		// https://github.com/google/syzkaller/issues/1523#issuecomment-696514105
		"UBSAN": "v5.3",
		// First, we disable coverage in pkg/bisect because it fails machine testing starting from 4.7.
		// Second, at 6689da155bdcd17abfe4d3a8b1e245d9ed4b5f2c CONFIG_KCOV selects CONFIG_GCC_PLUGIN_SANCOV
		// (why?), which is build broken for hundreds of revisions.
		// However, as there's a chance that KCOV might positively affect bug reproduction rate, let's
		// keep it for newer kernel revisions. Bisection algorithm will try to drop it anyway during
		// kernel config minimization.
		"KCOV": "v5.4",
		// This helps to produce stable binaries in presence of kernel tag changes.
		"LOCALVERSION_AUTO": disableAlways,
		// BTF fails lots of builds with:
		// pahole version v1.9 is too old, need at least v1.13
		// Failed to generate BTF for vmlinux. Try to disable CONFIG_DEBUG_INFO_BTF.
		"DEBUG_INFO_BTF": disableAlways,
		// This config only adds debug output. It should not be enabled at all,
		// but it was accidentially enabled on some instances for some periods of time,
		// and kernel is boot-broken for prolonged ranges of commits with deadlock
		// which makes bisections take weeks.
		"DEBUG_KOBJECT": disableAlways,
		// This config is causing problems to kernel signature calculation as new initramfs is generated
		// as a part of every build. Due to this init.data section containing this generated initramfs
		// is differing between builds causing signture being random number.
		"BLK_DEV_INITRD": disableAlways,
	}
	for cfg, tag := range disable {
		if checkTag(tag) {
			cf.Unset(cfg)
		}
	}
	alter := []struct {
		From string
		To   string
		Tag  string
	}{
		// Even though ORC unwinder was introduced a long time ago, it might have been broken for
		// some time. 5.4 is chosen as a version tag, where ORC unwinder seems to work properly.
		{"UNWINDER_ORC", "UNWINDER_FRAME_POINTER", "v5.4"},
	}
	for _, a := range alter {
		if checkTag(a.Tag) {
			cf.Unset(a.From)
			cf.Set(a.To, kconfig.Yes)
		}
	}
}

// setLinuxSanitizerConfigs() removes Linux kernel sanitizers that are not necessary
// to trigger the specified crash types.
func setLinuxSanitizerConfigs(cf *kconfig.ConfigFile, types []crash.Type, dt debugtracer.DebugTracer) {
	keep := map[crash.Type]func(){
		crash.Hang: func() {
			cf.Unset("RCU_STALL_COMMON")
			cf.Unset("LOCKUP_DETECTOR")
			cf.Unset("SOFTLOCKUP_DETECTOR")
			cf.Unset("HARDLOCKUP_DETECTOR")
			cf.Unset("DETECT_HUNG_TASK")
			// It looks like it's the only reliable way to completely disable hung errors.
			cmdline := cf.Value("CMDLINE")
			pos := strings.LastIndexByte(cmdline, '"')
			const rcuStallSuppress = "rcupdate.rcu_cpu_stall_suppress=1"
			if pos >= 0 && !strings.Contains(cmdline, rcuStallSuppress) {
				cf.Set("CMDLINE", cmdline[:pos]+" "+rcuStallSuppress+cmdline[pos:])
			}
		},
		crash.MemoryLeak: func() { cf.Unset("DEBUG_KMEMLEAK") },
		crash.UBSAN:      func() { cf.Unset("UBSAN") },
		crash.Bug:        func() { cf.Unset("BUG") },
		crash.KASAN:      func() { cf.Unset("KASAN") },
		crash.LockdepBug: func() {
			cf.Unset("LOCKDEP")
			cf.Unset("PROVE_LOCKING") // it selects LOCKDEP
		},
		crash.AtomicSleep: func() { cf.Unset("DEBUG_ATOMIC_SLEEP") },
	}
	need := map[crash.Type]bool{}
	for _, typ := range types {
		if typ == crash.Warning {
			// These are disabled together.
			typ = crash.Bug
		}
		need[typ] = true
	}
	var disabled []string
	for typ, f := range keep {
		if need[typ] {
			continue
		}
		f()
		disabled = append(disabled, string(typ))
	}
	if len(disabled) > 0 {
		dt.Log("disabling configs for %v, they are not needed", disabled)
	}
}
