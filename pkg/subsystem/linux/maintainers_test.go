// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package linux

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/syzkaller/pkg/subsystem"
)

func TestRecordToPathRule(t *testing.T) {
	tests := []struct {
		name    string
		record  maintainersRecord
		match   []string
		noMatch []string
	}{
		{
			name: `general test`,
			record: maintainersRecord{
				includePatterns: []string{
					`drivers/gpio/gpio-*wm*.c`,
					`drivers/hwmon/wm83??-hwmon.c`,
					`include/linux/mfd/arizona/`,
					`include/linux/wm97xx.h`,
				},
			},
			match: []string{
				`drivers/gpio/gpio-wm831x.c`,
				`drivers/gpio/gpio-abcdwm831x.c`,
				`drivers/hwmon/wm8355-hwmon.c`,
				`include/linux/mfd/arizona/file.c`,
				`include/linux/mfd/arizona/subfolder/file.c`,
				`include/linux/wm97xx.h`,
			},
			noMatch: []string{
				`drivers/gpio/gpio-w831x.c`,
				`drivers/hwmon/wm83556-hwmon.c`,
				`drivers/hwmon/wm831-hwmon.c`,
				`include/linux/mfd`,
				`include`,
				`random-file`,
			},
		},
		{
			name: `include patterns and regexp`,
			record: maintainersRecord{
				includePatterns: []string{`drivers/rtc/rtc-opal.c`},
				regexps:         []string{`[^a-z0-9]ps3`},
			},
			match: []string{
				`drivers/rtc/rtc-opal.c`,
				`drivers/ps3/a.c`,
				`drivers/sub/ps3/a.c`,
				`drivers/sub/sub/ps3.c`,
			},
			noMatch: []string{
				`drivers/aps3/a.c`,
				`drivers/abc/aps3.c`,
			},
		},
		{
			name: `exclude patterns`,
			record: maintainersRecord{
				includePatterns: []string{`security/`},
				excludePatterns: []string{`security/selinux/`},
			},
			match: []string{
				`security/apparmor/abcd.c`,
				`security/abcd.c`,
			},
			noMatch: []string{
				`security/selinux/abcd.c`,
			},
		},
		{
			name: `handle / at the end`,
			record: maintainersRecord{
				includePatterns: []string{
					`with-subfolders/`,
					`dir/only-one`,
					`also-with-subfolders/*`,
				},
			},
			match: []string{
				`with-subfolders/a`,
				`with-subfolders/a/b`,
				`dir/only-one`,
				`also-with-subfolders/a.c`,
				`also-with-subfolders/b/a.c`,
			},
			noMatch: []string{
				`dir/only-one/a.c`,
				`dir/only-one/a/b.c`,
			},
		},
		{
			name: `wildcards are well escaped`,
			record: maintainersRecord{
				includePatterns: []string{`drivers/net/ethernet/smsc/smc91x.*`},
			},
			match: []string{
				`drivers/net/ethernet/smsc/smc91x.c`,
				`drivers/net/ethernet/smsc/smc91x.h`,
			},
			noMatch: []string{
				`drivers/net/ethernet/smsc/smc91xAh`,
			},
		},
		{
			name: `match everything`,
			record: maintainersRecord{
				includePatterns: []string{`*`, `*/`},
			},
			match: []string{
				`a`,
				`a/b`,
				`a/b/c`,
			},
		},
	}

	for _, loopTest := range tests {
		test := loopTest
		t.Run(test.name, func(t *testing.T) {
			pm := subsystem.MakePathMatcher([]*subsystem.Subsystem{
				{PathRules: []subsystem.PathRule{test.record.ToPathRule()}},
			})
			for _, path := range test.match {
				if len(pm.Match(path)) != 1 {
					t.Fatalf("did not match %#v", path)
				}
			}
			for _, path := range test.noMatch {
				if len(pm.Match(path)) > 0 {
					t.Fatalf("matched %#v", path)
				}
			}
		})
	}
}

func TestLinuxMaintainers(t *testing.T) {
	result, err := parseLinuxMaintainers(
		strings.NewReader(maintainersSample),
	)
	if err != nil {
		t.Fatal(err)
	}
	targetResult := []*maintainersRecord{
		{
			name: "3C59X NETWORK DRIVER",
			includePatterns: []string{
				"Documentation/networking/device_drivers/ethernet/3com/vortex.rst",
				"drivers/net/ethernet/3com/3c59x.c",
			},
			lists:       []string{"netdev@vger.kernel.org"},
			maintainers: []string{"email1@kernel.org"},
		},
		{
			name: "ABI/API",
			includePatterns: []string{
				"include/linux/syscalls.h",
				"kernel/sys_ni.c",
			},
			excludePatterns: []string{
				"include/uapi/",
				"arch/*/include/uapi/",
			},
			lists: []string{"linux-api@vger.kernel.org"},
		},
		{
			name:            "AD1889 ALSA SOUND DRIVER",
			includePatterns: []string{"sound/pci/ad1889.*"},
			lists:           []string{"linux-parisc@vger.kernel.org"},
		},
		{
			name: "PVRUSB2 VIDEO4LINUX DRIVER",
			includePatterns: []string{
				"Documentation/driver-api/media/drivers/pvrusb2*",
				"drivers/media/usb/pvrusb2/",
			},
			lists: []string{
				"pvrusb2@isely.net",
				"linux-media@vger.kernel.org",
			},
			maintainers: []string{"email2@kernel.org"},
			trees:       []string{"git git://linuxtv.org/media_tree.git"},
		},
		{
			name:            "RISC-V ARCHITECTURE",
			includePatterns: []string{"arch/riscv/"},
			regexps:         []string{"riscv"},
			lists:           []string{"linux-riscv@lists.infradead.org"},
			maintainers: []string{
				"email3@kernel.org",
				"email4@kernel.org",
				"email5@kernel.org",
			},
			trees: []string{"git git://git.kernel.org/pub/scm/linux/kernel/git/riscv/linux.git"},
		},
		{
			name:            "THE REST",
			includePatterns: []string{"*", "*/"},
			lists:           []string{"linux-kernel@vger.kernel.org"},
			maintainers:     []string{"email6@kernel.org"},
			trees:           []string{"git git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git"},
		},
	}
	if diff := cmp.Diff(targetResult, result,
		cmp.AllowUnexported(maintainersRecord{})); diff != "" {
		t.Fatal(diff)
	}
}

const maintainersSample = `
List of maintainers and how to submit kernel changes
====================================================

Please try to follow the guidelines below.  This will make things
easier on the maintainers.  Not all of these guidelines matter for every
trivial patch so apply some common sense.

Tips for patch submitters
-------------------------

1.	Always *test* your changes, however small, on at least 4 or
	5 people, preferably many more.

< ... >

8.	Happy hacking.

Descriptions of section entries and preferred order
---------------------------------------------------

	M: *Mail* patches to: FullName <address@domain>
	R: Designated *Reviewer*: FullName <address@domain>
	   These reviewers should be CCed on patches.
< ... >
	K: *Content regex* (perl extended) pattern match in a patch or file.
	   For instance:
	   K: of_get_profile
	      matches patches or files that contain "of_get_profile"
	   K: \b(printk|pr_(info|err))\b
	      matches patches or files that contain one or more of the words
	      printk, pr_info or pr_err
	   One regex pattern per line.  Multiple K: lines acceptable.

Maintainers List
----------------

.. note:: When reading this list, please look for the most precise areas
          first. When adding to this list, please keep the entries in
          alphabetical order.

3C59X NETWORK DRIVER
M:	Name1 Surname <email1@kernel.org>
L:	netdev@vger.kernel.org
S:	Odd Fixes
F:	Documentation/networking/device_drivers/ethernet/3com/vortex.rst
F:	drivers/net/ethernet/3com/3c59x.c

ABI/API
L:	linux-api@vger.kernel.org
F:	include/linux/syscalls.h
F:	kernel/sys_ni.c
X:	include/uapi/
X:	arch/*/include/uapi/

AD1889 ALSA SOUND DRIVER
L:	linux-parisc@vger.kernel.org
S:	Maintained
W:	https://parisc.wiki.kernel.org/index.php/AD1889
F:	sound/pci/ad1889.*

PVRUSB2 VIDEO4LINUX DRIVER
M:	Name2 <email2@kernel.org>
L:	pvrusb2@isely.net	(subscribers-only)
L:	linux-media@vger.kernel.org
S:	Maintained
W:	http://www.isely.net/pvrusb2/
T:	git git://linuxtv.org/media_tree.git
F:	Documentation/driver-api/media/drivers/pvrusb2*
F:	drivers/media/usb/pvrusb2/

RISC-V ARCHITECTURE
M:	Name3 <email3@kernel.org>
M:	Name4 <email4@kernel.org>
M:	Name5 <email5@kernel.org>
L:	linux-riscv@lists.infradead.org
S:	Supported
Q:	https://patchwork.kernel.org/project/linux-riscv/list/
P:	Documentation/riscv/patch-acceptance.rst
T:	git git://git.kernel.org/pub/scm/linux/kernel/git/riscv/linux.git
F:	arch/riscv/
N:	riscv
K:	riscv

THE REST
M:	Name6 <email6@kernel.org>
L:	linux-kernel@vger.kernel.org
S:	Buried alive in reporters
T:	git git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
F:	*
F:	*/
`
