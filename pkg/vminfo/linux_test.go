// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vminfo

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/assert"
)

func TestLinuxSyscalls(t *testing.T) {
	cfg := testConfig(t, targets.Linux, targets.AMD64)
	checker := New(cfg)
	filesystems := []string{
		// Without sysfs, the checks would also disable mount().
		"", "sysfs", "ext4", "binder", "",
	}
	files := []flatrpc.FileInfo{
		{
			Name:   "/proc/version",
			Exists: true,
			Data:   []byte("Linux version 6.8.0-dirty"),
		},
		{
			Name:   "/proc/filesystems",
			Exists: true,
			Data:   []byte(strings.Join(filesystems, "\nnodev\t")),
		},
	}
	stop := make(chan struct{})
	go createSuccessfulResults(checker, stop)
	enabled, disabled, features, err := checker.Run(files, allFeatures())
	close(stop)
	if err != nil {
		t.Fatal(err)
	}
	expectDisabled := map[string]bool{
		"syz_kvm_setup_cpu$arm64": true,
		"syz_kvm_setup_cpu$ppc64": true,
	}
	// All mount and syz_mount_image calls except for ext4 and binder will be disabled.
	for call := range disabled {
		name := call.Name
		if name == "mount$binder" || name == "syz_mount_image$ext4" {
			continue
		}
		if strings.HasPrefix(name, "syz_mount_image$") || strings.HasPrefix(name, "mount$") {
			expectDisabled[name] = true
		}
	}
	for call, reason := range disabled {
		if expectDisabled[call.Name] {
			continue
		}
		t.Errorf("disabled call %v: %v", call.Name, reason)
	}
	for _, id := range cfg.Syscalls {
		call := cfg.Target.Syscalls[id]
		if enabled[call] && disabled[call] != "" {
			t.Fatalf("%s is both enabled and disabled", call.Name)
		}
		expected := !expectDisabled[call.Name]
		got := enabled[call]
		if expected != got {
			t.Errorf("%s: expected %t, got %t", call.Name, expected, got)
		}
	}
	expectEnabled := len(cfg.Syscalls) - len(expectDisabled)
	if len(enabled) != expectEnabled {
		t.Errorf("enabled only %v calls out of %v", len(enabled), expectEnabled)
	}
	if len(features) != len(flatrpc.EnumNamesFeature) {
		t.Errorf("enabled only %v features out of %v", len(features), len(flatrpc.EnumNamesFeature))
	}
	for feat, info := range features {
		if !info.Enabled {
			t.Errorf("feature %v is not enabled: %v", flatrpc.EnumNamesFeature[feat], info.Reason)
		}
	}
}

func TestReadKVMInfo(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("not linux")
	}
	_, files := hostChecker(t)
	fs := createVirtualFilesystem(files)
	buf := new(bytes.Buffer)
	if _, err := linuxReadKVMInfo(fs, buf); err != nil {
		t.Fatal(err)
	}
	for s := bufio.NewScanner(buf); s.Scan(); {
		line := s.Text()
		if line == "" {
			continue
		}
		splitted := strings.Split(line, ":")
		if len(splitted) != 2 {
			t.Fatalf("the format of line \"%s\" is not correct", line)
		}
		key := strings.TrimSpace(splitted[0])
		if key == "" {
			t.Fatalf("empty key")
		}
		if key[0] != '/' {
			continue
		}

		if !strings.HasPrefix(key, "/sys/module/kvm") {
			t.Fatalf("the directory does not match /sys/module/kvm*")
		}
	}
}

func TestCannedCPUInfoLinux(t *testing.T) {
	tests := cpuInfoTests
	if runtime.GOOS == "linux" {
		data, err := os.ReadFile("/proc/cpuinfo")
		if err != nil {
			t.Fatal(err)
		}
		tests = append(tests, cannedTest{
			arch: runtime.GOARCH,
			data: string(data),
		})
	}
	for i, test := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			files := createVirtualFilesystem([]flatrpc.FileInfo{{
				Name:   "/proc/cpuinfo",
				Exists: true,
				Data:   []byte(test.data),
			}})
			buf := new(bytes.Buffer)
			if _, err := linuxReadCPUInfo(files, buf); err != nil {
				t.Fatal(err)
			}
			if test.want != "" {
				if diff := cmp.Diff(buf.String(), test.want); diff != "" {
					t.Fatal(diff)
				}
				return
			}
			checkCPUInfo(t, buf.Bytes(), test.arch)
		})
	}
}

func checkCPUInfo(t *testing.T, data []byte, arch string) {
	keys := make(map[string]bool)
	s := bufio.NewScanner(bytes.NewReader(data))
	s.Buffer(nil, 1<<20)
	for s.Scan() {
		splitted := strings.Split(s.Text(), ":")
		if len(splitted) != 2 {
			t.Fatalf("the format of line %q is not correct", s.Text())
		}
		key := strings.TrimSpace(splitted[0])
		keys[key] = true
	}
	assert.Nil(t, s.Err(), "scanner failed reading the CpuInfo: %v", s.Err())

	importantKeys := map[string][]string{
		targets.PPC64LE:  {"cpu", "revision", "platform", "model", "machine"},
		targets.AMD64:    {"vendor_id", "model", "flags"},
		targets.S390x:    {"vendor_id", "processor 0", "features"},
		targets.I386:     {"vendor_id", "model", "flags"},
		targets.ARM64:    {"CPU implementer", "CPU part", "Features"},
		targets.ARM:      {"CPU implementer", "CPU part", "Features"},
		targets.MIPS64LE: {"system type", "cpu model", "ASEs implemented"},
		targets.RiscV64:  {"processor", "isa", "mmu"},
	}
	archKeys := importantKeys[arch]
	if len(archKeys) == 0 {
		t.Fatalf("unknown arch %v", arch)
	}
	for _, name := range archKeys {
		if !keys[name] {
			t.Fatalf("key %q not found", name)
		}
	}
}

type cannedTest struct {
	arch string
	data string
	want string
}

// nolint:lll
var cpuInfoTests = []cannedTest{
	{
		arch: targets.PPC64LE,
		data: `
processor	: 0
cpu		: POWER8 (architected), altivec supported
clock		: 3425.000000MHz
revision	: 2.1 (pvr 004b 0201)

processor	: 1
cpu		: POWER8 (architected), altivec supported
clock		: 3425.000000MHz
revision	: 2.1 (pvr 004b 0201)

processor	: 2
cpu		: POWER8 (architected), altivec supported
clock		: 3425.000000MHz
revision	: 2.1 (pvr 004b 0201)

processor	: 3
cpu		: POWER8 (architected), altivec supported
clock		: 3425.000000MHz
revision	: 2.1 (pvr 004b 0201)

timebase	: 512000000
platform	: pSeries
model		: IBM pSeries (emulated by qemu)
machine		: CHRP IBM pSeries (emulated by qemu)
MMU		: Hash
`,
	},
	{
		arch: targets.PPC64LE,
		data: `
processor       : 0
cpu             : POWER8 (architected), altivec supported
clock           : 3425.000000MHz
revision        : 2.1 (pvr 004b 0201)

<insert 62 more processors here>

processor       : 63
cpu             : POWER8 (architected), altivec supported
clock           : 3425.000000MHz
revision        : 2.1 (pvr 004b 0201)

timebase        : 512000000
platform        : pSeries
model           : IBM,8247-22L
machine         : CHRP IBM,8247-22L
MMU             : Hash
`,
	},
	{
		arch: targets.PPC64LE,
		data: `
processor       : 0
cpu             : POWER8E, altivec supported
clock           : 3358.000000MHz
revision        : 2.1 (pvr 004b 0201)

processor       : 8
cpu             : POWER8E, altivec supported
clock           : 3358.000000MHz
revision        : 2.1 (pvr 004b 0201)

processor       : 16
cpu             : POWER8E, altivec supported
clock           : 3358.000000MHz
revision        : 2.1 (pvr 004b 0201)

processor       : 24
cpu             : POWER8E, altivec supported
clock           : 3358.000000MHz
revision        : 2.1 (pvr 004b 0201)

processor       : 32
cpu             : POWER8E, altivec supported
clock           : 3358.000000MHz
revision        : 2.1 (pvr 004b 0201)

processor       : 40
cpu             : POWER8E, altivec supported
clock           : 3358.000000MHz
revision        : 2.1 (pvr 004b 0201)

timebase        : 512000000
platform        : PowerNV
model           : 8286-41A
machine         : PowerNV 8286-41A
firmware        : OPAL
MMU             : Hash
`,
	},
	{
		arch: targets.AMD64,
		data: `
processor	: 0
vendor_id	: GenuineIntel
cpu family	: 6
model		: 142
model name	: Intel(R) Core(TM) i7-8650U CPU @ 1.90GHz
stepping	: 10
microcode	: 0xd6
cpu MHz		: 2015.517
cache size	: 8192 KB
physical id	: 0
siblings	: 8
core id		: 0
cpu cores	: 4
apicid		: 0
initial apicid	: 0
fpu		: yes
fpu_exception	: yes
cpuid level	: 22
wp		: yes
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush dts acpi mmx fxsr sse sse2 ss ht tm pbe syscall nx pdpe1gb rdtscp lm constant_tsc art arch_perfmon pebs bts rep_good nopl xtopology nonstop_tsc cpuid aperfmperf pni pclmulqdq dtes64 monitor ds_cpl vmx smx est tm2 ssse3 sdbg fma cx16 xtpr pdcm pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand lahf_lm abm 3dnowprefetch cpuid_fault epb invpcid_single pti ssbd ibrs ibpb stibp tpr_shadow vnmi flexpriority ept vpid ept_ad fsgsbase tsc_adjust bmi1 hle avx2 smep bmi2 erms invpcid rtm mpx rdseed adx smap clflushopt intel_pt xsaveopt xsavec xgetbv1 xsaves dtherm ida arat pln pts hwp hwp_notify hwp_act_window hwp_epp md_clear flush_l1d
vmx flags	: vnmi preemption_timer invvpid ept_x_only ept_ad ept_1gb flexpriority tsc_offset vtpr mtf vapic ept vpid unrestricted_guest ple shadow_vmcs pml ept_mode_based_exec
bugs		: cpu_meltdown spectre_v1 spectre_v2 spec_store_bypass l1tf mds swapgs taa itlb_multihit srbds
bogomips	: 4199.88
clflush size	: 64
cache_alignment	: 64
address sizes	: 39 bits physical, 48 bits virtual
power management:

processor	: 1
vendor_id	: GenuineIntel
cpu family	: 6
model		: 142
model name	: Intel(R) Core(TM) i7-8650U CPU @ 1.90GHz
stepping	: 10
microcode	: 0xd6
cpu MHz		: 1384.935
cache size	: 8192 KB
physical id	: 0
siblings	: 8
core id		: 1
cpu cores	: 4
apicid		: 2
initial apicid	: 2
fpu		: yes
fpu_exception	: yes
cpuid level	: 22
wp		: yes
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush dts acpi mmx fxsr sse sse2 ss ht tm pbe syscall nx pdpe1gb rdtscp lm constant_tsc art arch_perfmon pebs bts rep_good nopl xtopology nonstop_tsc cpuid aperfmperf pni pclmulqdq dtes64 monitor ds_cpl vmx smx est tm2 ssse3 sdbg fma cx16 xtpr pdcm pcid sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand lahf_lm abm 3dnowprefetch cpuid_fault epb invpcid_single pti ssbd ibrs ibpb stibp tpr_shadow vnmi flexpriority ept vpid ept_ad fsgsbase tsc_adjust bmi1 hle avx2 smep bmi2 erms invpcid rtm mpx rdseed adx smap clflushopt intel_pt xsaveopt xsavec xgetbv1 xsaves dtherm ida arat pln pts hwp hwp_notify hwp_act_window hwp_epp md_clear flush_l1d
vmx flags	: vnmi preemption_timer invvpid ept_x_only ept_ad ept_1gb flexpriority tsc_offset vtpr mtf vapic ept vpid unrestricted_guest ple shadow_vmcs pml ept_mode_based_exec
bugs		: cpu_meltdown spectre_v1 spectre_v2 spec_store_bypass l1tf mds swapgs taa itlb_multihit srbds
bogomips	: 4199.88
clflush size	: 64
cache_alignment	: 64
address sizes	: 39 bits physical, 48 bits virtual
power management:
`,
	},
	{
		arch: targets.AMD64,
		data: `
processor	: 0
vendor_id	: GenuineIntel
cpu family	: 6
model		: 85
model name	: Intel(R) Xeon(R) CPU @ 2.00GHz
stepping	: 3
microcode	: 0x1
cpu MHz		: 2000.166
cache size	: 56320 KB
physical id	: 0
siblings	: 64
core id		: 0
cpu cores	: 32
apicid		: 0
initial apicid	: 0
fpu		: yes
fpu_exception	: yes
cpuid level	: 13
wp		: yes
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss ht syscall nx pdpe1gb rdtscp lm constant_tsc rep_good nopl xtopology nonstop_tsc cpuid tsc_known_freq pni pclmulqdq ssse3 fma cx16 pcid sse4_1 sse4_2 x2apic movbe popcnt aes xsave avx f16c rdrand hypervisor lahf_lm abm 3dnowprefetch invpcid_single pti fsgsbase tsc_adjust bmi1 hle avx2 smep bmi2 erms invpcid rtm mpx avx512f avx512dq rdseed adx smap clflushopt clwb avx512cd avx512bw avx512vl xsaveopt xsavec xgetbv1 xsaves
bugs		: cpu_meltdown spectre_v1 spectre_v2 spec_store_bypass l1tf mds swapgs
bogomips	: 4000.33
clflush size	: 64
cache_alignment	: 64
address sizes	: 46 bits physical, 48 bits virtual
power management:

processor	: 1
vendor_id	: GenuineIntel
cpu family	: 6
model		: 85
model name	: Intel(R) Xeon(R) CPU @ 2.00GHz
stepping	: 3
microcode	: 0x1
cpu MHz		: 2000.166
cache size	: 56320 KB
physical id	: 0
siblings	: 64
core id		: 1
cpu cores	: 32
apicid		: 2
initial apicid	: 2
fpu		: yes
fpu_exception	: yes
cpuid level	: 13
wp		: yes
flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss ht syscall nx pdpe1gb rdtscp lm constant_tsc rep_good nopl xtopology nonstop_tsc cpuid tsc_known_freq pni pclmulqdq ssse3 fma cx16 pcid sse4_1 sse4_2 x2apic movbe popcnt aes xsave avx f16c rdrand hypervisor lahf_lm abm 3dnowprefetch invpcid_single pti fsgsbase tsc_adjust bmi1 hle avx2 smep bmi2 erms invpcid rtm mpx avx512f avx512dq rdseed adx smap clflushopt clwb avx512cd avx512bw avx512vl xsaveopt xsavec xgetbv1 xsaves
bugs		: cpu_meltdown spectre_v1 spectre_v2 spec_store_bypass l1tf mds swapgs
bogomips	: 4000.33
clflush size	: 64
cache_alignment	: 64
address sizes	: 46 bits physical, 48 bits virtual
power management:
`,
	},
	{
		data: `A:	a
B:	b

C:	c1
D:	d
C:	c1
D:	d
C:	c2
D:	d
`,
		want: `A                   : a
B                   : b
C                   : c1, c1, c2
D                   : d
`,
	},
}
