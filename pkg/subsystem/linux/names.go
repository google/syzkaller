// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package linux

import (
	"fmt"
	"regexp"

	"github.com/google/syzkaller/pkg/subsystem"
)

// setSubsystemNames assigns unique names to the presented subsystems.
// If it failed to assign a name to a subsystem, the Name field remains empty.
func setSubsystemNames(list []*subsystem.Subsystem) error {
	dups := map[string]bool{}
	for _, item := range list {
		// For now, we can only infer name from the list email.
		if len(item.Lists) == 0 {
			return fmt.Errorf("no lists for %#v", item)
		}
		email := item.Lists[0]
		name := emailToName(email)
		if !validateName(name) {
			return fmt.Errorf("failed to extract a name from %s", email)
		}
		if dups[name] {
			return fmt.Errorf("duplicate subsystem name: %s", item.Name)
		}
		item.Name = name
		dups[name] = true
	}
	return nil
}

func validateName(name string) bool {
	const (
		minLen = 2
		maxLen = 16 // otherwise the email subject can get too big
	)
	return len(name) >= minLen && len(name) <= maxLen
}

func emailToName(email string) string {
	if name := emailExceptions[email]; name != "" {
		return name
	}
	ret := emailStripRe.FindStringSubmatch(email)
	if ret == nil {
		return ""
	}
	return ret[1]
}

func buildEmailStripRe() *regexp.Regexp {
	raw := `^(?:`
	for i := 0; i < len(stripPrefixes); i++ {
		if i > 0 {
			raw += "|"
		}
		raw += regexp.QuoteMeta(stripPrefixes[i])
	}
	raw += ")*(.*?)(?:"
	for i := 0; i < len(stripSuffixes); i++ {
		if i > 0 {
			raw += "|"
		}
		raw += regexp.QuoteMeta(stripSuffixes[i])
	}
	raw += ")*@.*$"
	return regexp.MustCompile(raw)
}

var (
	emailExceptions = map[string]string{
		"patches@opensource.cirrus.com":             "cirrus",
		"virtualization@lists.linux-foundation.org": "virt", // the name is too long
		"dev@openvswitch.org":                       "openvswitch",
		"devel@acpica.org":                          "acpica",
		"kernel@dh-electronics.com":                 "dh-electr",
		"devel@lists.orangefs.org":                  "orangefs",
		"linux-arm-kernel@axis.com":                 "axis",
		"Dell.Client.Kernel@dell.com":               "dell",
		"sound-open-firmware@alsa-project.org":      "sof",
		"platform-driver-x86@vger.kernel.org":       "x86-drivers",
		"linux-trace-devel@vger.kernel.org":         "rt-tools",
		"aws-nitro-enclaves-devel@amazon.com":       "nitro",
		"brcm80211-dev-list.pdl@broadcom.com":       "brcm80211",
		"osmocom-net-gprs@lists.osmocom.org":        "osmocom",
		"netdev@vger.kernel.org":                    "net",
		"megaraidlinux.pdl@broadcom.com":            "megaraid",
		"mpi3mr-linuxdrv.pdl@broadcom.com":          "mpi3",
		"MPT-FusionLinux.pdl@broadcom.com":          "mpt-fusion",
		"linux-security-module@vger.kernel.org":     "lsm",       // the original name is too long
		"linux-unionfs@vger.kernel.org":             "overlayfs", // the name has changed
	}
	stripPrefixes = []string{"linux-"}
	stripSuffixes = []string{
		"-devel", "-dev", "-devs", "-developer", "devel",
		"-user", "-users",
		"-discussion", "-discuss", "-list", "-en",
		"-kernel", "-linux", "-general",
	}
	emailStripRe = buildEmailStripRe()
)
