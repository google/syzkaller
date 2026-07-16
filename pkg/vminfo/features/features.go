// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package features provides definitions for various fuzzing features.
package features

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/google/syzkaller/pkg/flatrpc"
)

type Feature struct {
	Description string
	Enabled     bool
}

type Features map[string]Feature

func defaultFeatures(value bool) Features {
	return map[string]Feature{
		"tun":         {"setup and use /dev/tun for packet injection", value},
		"net_dev":     {"setup more network devices for testing", value},
		"net_reset":   {"reset network namespace between programs", value},
		"cgroups":     {"setup cgroups for testing", value},
		"binfmt_misc": {"setup binfmt_misc for testing", value},
		"close_fds":   {"close fds after each program", value},
		"devlink_pci": {"setup devlink PCI device", value},
		"nic_vf":      {"setup NIC VF device", value},
		"usb":         {"setup and use /dev/raw-gadget for USB emulation", value},
		"vhci":        {"setup and use /dev/vhci for hci packet injection", value},
		"wifi":        {"setup and use mac80211_hwsim for wifi emulation", value},
		"ieee802154":  {"setup and use mac802154_hwsim for emulation", value},
		"sysctl":      {"setup sysctl's for fuzzing", value},
		"swap":        {"setup and use a swap file", value},
	}
}

func ParseFlags(enable, disable string, defaultValue bool) (Features, error) {
	const (
		none = "none"
		all  = "all"
	)
	if enable == none && disable == none {
		return defaultFeatures(defaultValue), nil
	}
	if enable != none && disable != none {
		return nil, fmt.Errorf("can't use -enable and -disable flags at the same time")
	}
	if enable == all || disable == "" {
		return defaultFeatures(true), nil
	}
	if disable == all || enable == "" {
		return defaultFeatures(false), nil
	}
	var items []string
	var features Features
	if enable != none {
		items = strings.Split(enable, ",")
		features = defaultFeatures(false)
	} else {
		items = strings.Split(disable, ",")
		features = defaultFeatures(true)
	}
	for _, item := range items {
		if _, ok := features[item]; !ok {
			return nil, fmt.Errorf("unknown feature specified: %s", item)
		}
		feature := features[item]
		feature.Enabled = enable != none
		features[item] = feature
	}
	return features, nil
}

func PrintAvailableFlags() {
	fmt.Printf("available features for -enable and -disable:\n")
	features := defaultFeatures(false)
	names := slices.Sorted(maps.Keys(features))
	for _, name := range names {
		fmt.Printf("  %s - %s\n", name, features[name].Description)
	}
}

func FeaturesToFlags(features flatrpc.Feature, manual Features) flatrpc.ExecEnv {
	for feat := range flatrpc.EnumNamesFeature {
		opt := FlatRPCFeaturesToCSource[feat]
		if opt != "" && manual != nil && !manual[opt].Enabled {
			features &= ^feat
		}
	}
	var flags flatrpc.ExecEnv
	if manual == nil || manual["net_reset"].Enabled {
		flags |= flatrpc.ExecEnvEnableNetReset
	}
	if manual == nil || manual["cgroups"].Enabled {
		flags |= flatrpc.ExecEnvEnableCgroups
	}
	if manual == nil || manual["close_fds"].Enabled {
		flags |= flatrpc.ExecEnvEnableCloseFds
	}
	if features&flatrpc.FeatureExtraCoverage != 0 {
		flags |= flatrpc.ExecEnvExtraCover
	}
	if features&flatrpc.FeatureDelayKcovMmap != 0 {
		flags |= flatrpc.ExecEnvDelayKcovMmap
	}
	if features&flatrpc.FeatureNetInjection != 0 {
		flags |= flatrpc.ExecEnvEnableTun
	}
	if features&flatrpc.FeatureNetDevices != 0 {
		flags |= flatrpc.ExecEnvEnableNetDev
	}
	if features&flatrpc.FeatureDevlinkPCI != 0 {
		flags |= flatrpc.ExecEnvEnableDevlinkPCI
	}
	if features&flatrpc.FeatureNicVF != 0 {
		flags |= flatrpc.ExecEnvEnableNicVF
	}
	if features&flatrpc.FeatureVhciInjection != 0 {
		flags |= flatrpc.ExecEnvEnableVhciInjection
	}
	if features&flatrpc.FeatureWifiEmulation != 0 {
		flags |= flatrpc.ExecEnvEnableWifi
	}
	return flags
}

// FlatRPCFeaturesToCSource maps FlatRPC features to their corresponding C source configuration flags.
var FlatRPCFeaturesToCSource = map[flatrpc.Feature]string{
	flatrpc.FeatureNetInjection:    "tun",
	flatrpc.FeatureNetDevices:      "net_dev",
	flatrpc.FeatureDevlinkPCI:      "devlink_pci",
	flatrpc.FeatureNicVF:           "nic_vf",
	flatrpc.FeatureVhciInjection:   "vhci",
	flatrpc.FeatureWifiEmulation:   "wifi",
	flatrpc.FeatureUSBEmulation:    "usb",
	flatrpc.FeatureBinFmtMisc:      "binfmt_misc",
	flatrpc.FeatureLRWPANEmulation: "ieee802154",
	flatrpc.FeatureSwap:            "swap",
}
