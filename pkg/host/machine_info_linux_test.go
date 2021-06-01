// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package host

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/sys/targets"
)

func TestCollectMachineInfo(t *testing.T) {
	info, err := CollectMachineInfo()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("machine info:\n%s", info)
}

func TestReadCPUInfoLinux(t *testing.T) {
	buf := new(bytes.Buffer)
	if err := readCPUInfo(buf); err != nil {
		t.Fatal(err)
	}
	checkCPUInfo(t, buf.Bytes(), runtime.GOARCH)
}

func TestCannedCPUInfoLinux(t *testing.T) {
	for i, test := range cpuInfoTests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			buf := new(bytes.Buffer)
			scanCPUInfo(buf, bufio.NewScanner(strings.NewReader(test.data)))
			checkCPUInfo(t, buf.Bytes(), test.arch)
		})
	}
}

func checkCPUInfo(t *testing.T, data []byte, arch string) {
	t.Logf("input data:\n%s", data)
	keys := make(map[string]bool)
	for s := bufio.NewScanner(bytes.NewReader(data)); s.Scan(); {
		splitted := strings.Split(s.Text(), ":")
		if len(splitted) != 2 {
			t.Fatalf("the format of line %q is not correct", s.Text())
		}
		key := strings.TrimSpace(splitted[0])
		keys[key] = true
	}
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

func TestReadKVMInfoLinux(t *testing.T) {
	buf := new(bytes.Buffer)
	if err := readKVMInfo(buf); err != nil {
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

func TestScanCPUInfo(t *testing.T) {
	input := `A:	a
B:	b

C:	c1
D:	d
C:	c1
D:	d
C:	c2
D:	d
`

	output := []struct {
		key, val string
	}{
		{"A", "a"},
		{"B", "b"},
		{"C", "c1, c1, c2"},
		{"D", "d"},
	}
	scanner := bufio.NewScanner(strings.NewReader(input))
	buffer := new(bytes.Buffer)
	scanCPUInfo(buffer, scanner)
	result := bufio.NewScanner(buffer)

	idx := 0
	for result.Scan() {
		line := result.Text()
		splitted := strings.Split(line, ":")
		if len(splitted) != 2 {
			t.Fatalf("the format of line \"%s\" is not correct", line)
		}
		key := strings.TrimSpace(splitted[0])
		val := strings.TrimSpace(splitted[1])
		if idx >= len(output) {
			t.Fatalf("additional line \"%s: %s\"", key, val)
		}
		expected := output[idx]
		if key != expected.key || val != expected.val {
			t.Fatalf("expected \"%s: %s\", got \"%s: %s\"",
				expected.key, expected.val, key, val)
		}
		idx++
	}
	if idx < len(output) {
		expected := output[idx]
		t.Fatalf("expected \"%s: %s\", got end of output",
			expected.key, expected.val)
	}
}

func TestGetModulesInfo(t *testing.T) {
	modules, err := getModulesInfo()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("modules:\n%v", modules)
}

type cannedTest struct {
	arch string
	data string
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
}

func TestGetGlobsInfo(t *testing.T) {
	if err := osutil.MkdirAll("globstest/a/b/c/d"); err != nil {
		t.Fatal(err)
	}
	if err := osutil.MkdirAll("globstest/a/b/c/e"); err != nil {
		t.Fatal(err)
	}
	if err := osutil.MkdirAll("globstest/a/c/d"); err != nil {
		t.Fatal(err)
	}
	if err := osutil.MkdirAll("globstest/a/c/e"); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll("globstest")

	globs := map[string]bool{
		"globstest/a/**/*:-globstest/a/c/e": true,
	}
	infos, err := getGlobsInfo(globs)
	if err != nil {
		t.Fatal(err)
	}
	for _, files := range infos {
		for _, file := range files {
			if file == "globstest/a/c/e" {
				t.Fatal("failed to exclude globstest/a/c/e")
			}
		}
	}
}
