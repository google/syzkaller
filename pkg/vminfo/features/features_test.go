// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package features

import (
	"testing"
)

func TestParseFlags(t *testing.T) {
	tests := []struct {
		Enable   string
		Disable  string
		Default  bool
		Features map[string]bool
	}{
		{
			Enable:  "none",
			Disable: "none",
			Default: true,
			Features: map[string]bool{
				"tun":         true,
				"net_dev":     true,
				"net_reset":   true,
				"cgroups":     true,
				"binfmt_misc": true,
				"close_fds":   true,
				"devlink_pci": true,
				"nic_vf":      true,
				"usb":         true,
				"vhci":        true,
				"wifi":        true,
				"ieee802154":  true,
				"sysctl":      true,
				"swap":        true,
			}},
		{
			Enable:   "none",
			Disable:  "none",
			Default:  false,
			Features: map[string]bool{}},
		{
			Enable:  "all",
			Disable: "none",
			Default: true,
			Features: map[string]bool{
				"tun":         true,
				"net_dev":     true,
				"net_reset":   true,
				"cgroups":     true,
				"binfmt_misc": true,
				"close_fds":   true,
				"devlink_pci": true,
				"nic_vf":      true,
				"usb":         true,
				"vhci":        true,
				"wifi":        true,
				"ieee802154":  true,
				"sysctl":      true,
				"swap":        true,
			}},
		{
			Enable:   "",
			Disable:  "none",
			Default:  true,
			Features: map[string]bool{}},
		{
			Enable:   "none",
			Disable:  "all",
			Default:  true,
			Features: map[string]bool{}},
		{
			Enable:  "none",
			Disable: "",
			Default: true,
			Features: map[string]bool{
				"tun":         true,
				"net_dev":     true,
				"net_reset":   true,
				"cgroups":     true,
				"binfmt_misc": true,
				"close_fds":   true,
				"devlink_pci": true,
				"nic_vf":      true,
				"usb":         true,
				"vhci":        true,
				"wifi":        true,
				"ieee802154":  true,
				"sysctl":      true,
				"swap":        true,
			}},
		{
			Enable:  "tun,net_dev",
			Disable: "none",
			Default: true,
			Features: map[string]bool{
				"tun":     true,
				"net_dev": true,
			}},
		{
			Enable:  "none",
			Disable: "cgroups,net_dev",
			Default: true,
			Features: map[string]bool{
				"tun":         true,
				"net_reset":   true,
				"binfmt_misc": true,
				"close_fds":   true,
				"devlink_pci": true,
				"nic_vf":      true,
				"usb":         true,
				"vhci":        true,
				"wifi":        true,
				"ieee802154":  true,
				"sysctl":      true,
				"swap":        true,
			}},
		{
			Enable:  "close_fds",
			Disable: "none",
			Default: true,
			Features: map[string]bool{
				"close_fds": true,
			}},
		{
			Enable:  "swap",
			Disable: "none",
			Default: true,
			Features: map[string]bool{
				"swap": true,
			}},
	}
	for i, test := range tests {
		features, err := ParseFlags(test.Enable, test.Disable, test.Default)
		if err != nil {
			t.Fatalf("failed to parse features flags: %v", err)
		}
		for name, feature := range features {
			if feature.Enabled != test.Features[name] {
				t.Fatalf("test #%v: invalid value for feature flag %s: got %v, want %v",
					i, name, feature.Enabled, test.Features[name])
			}
		}
	}
}
