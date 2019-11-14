// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package host

import (
	"time"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

// DetectSupportedSyscalls returns list on supported and unsupported syscalls on the host.
// For unsupported syscalls it also returns reason as to why it is unsupported.
func DetectSupportedSyscalls(target *prog.Target, sandbox string) (
	map[*prog.Syscall]bool, map[*prog.Syscall]string, error) {
	log.Logf(1, "detecting supported syscalls")
	supported := make(map[*prog.Syscall]bool)
	unsupported := make(map[*prog.Syscall]string)
	// These do not have own host and parasitize on some other OS.
	if targets.Get(target.OS, target.Arch).HostFuzzer {
		for _, c := range target.Syscalls {
			supported[c] = true
		}
		return supported, unsupported, nil
	}
	for _, c := range target.Syscalls {
		ok, reason := false, ""
		switch c.CallName {
		case "syz_execute_func":
			// syz_execute_func caused multiple problems:
			// 1. First it lead to corpus exploision. The program used existing values in registers
			// to pollute output area. We tried to zero registers (though, not reliably).
			// 2. It lead to explosion again. The exact mechanics are unknown, here is one sample:
			// syz_execute_func(&(0x7f0000000440)="f2af91930f0124eda133fa20430fbafce842f66188d0d4
			//	430fc7f314c1ab5bf9e2f9660f3a0fae5e090000ba023c1fb63ac4817d73d74ec482310d46f44
			//	9f216c863fa438036a91bdbae95aaaa420f383c02c401405c6bfd49d768d768f833fefbab6464
			//	660f38323c8f26dbc1a1fe5ff6f6df0804f4c4efa59c0f01c4288ba6452e000054c4431d5cc100")
			// 3. The code can also execute syscalls (and it is know to), but it's not subject to
			// target.SanitizeCall. As the result it can do things that programs are not supposed to do.
			// 4. Besides linux, corpus explosion also happens on freebsd and is clearly attributable
			// to syz_execute_func based on corpus contents. Mechanics are also not known.
			// It also did not cause finding of any new bugs (at least not that I know of).
			// Let's disable it for now until we figure out how to resolve all these problems.
			ok = false
			reason = "always disabled for now"
		default:
			ok, reason = isSupported(c, target, sandbox)
		}
		if ok {
			supported[c] = true
		} else {
			if reason == "" {
				reason = "unknown"
			}
			unsupported[c] = reason
		}
	}
	return supported, unsupported, nil
}

var testFallback = false

const (
	FeatureCoverage = iota
	FeatureComparisons
	FeatureExtraCoverage
	FeatureSandboxSetuid
	FeatureSandboxNamespace
	FeatureSandboxAndroidUntrustedApp
	FeatureFaultInjection
	FeatureLeakChecking
	FeatureNetworkInjection
	FeatureNetworkDevices
	FeatureKCSAN
	FeatureDevlinkPCI
	numFeatures
)

type Feature struct {
	Name    string
	Enabled bool
	Reason  string
}

type Features [numFeatures]Feature

var checkFeature [numFeatures]func() string

func unconditionallyEnabled() string { return "" }

// Check detects features supported on the host.
// Empty string for a feature means the feature is supported,
// otherwise the string contains the reason why the feature is not supported.
func Check(target *prog.Target) (*Features, error) {
	const unsupported = "support is not implemented in syzkaller"
	res := &Features{
		FeatureCoverage:                   {Name: "code coverage", Reason: unsupported},
		FeatureComparisons:                {Name: "comparison tracing", Reason: unsupported},
		FeatureExtraCoverage:              {Name: "extra coverage", Reason: unsupported},
		FeatureSandboxSetuid:              {Name: "setuid sandbox", Reason: unsupported},
		FeatureSandboxNamespace:           {Name: "namespace sandbox", Reason: unsupported},
		FeatureSandboxAndroidUntrustedApp: {Name: "Android sandbox", Reason: unsupported},
		FeatureFaultInjection:             {Name: "fault injection", Reason: unsupported},
		FeatureLeakChecking:               {Name: "leak checking", Reason: unsupported},
		FeatureNetworkInjection:           {Name: "net packet injection", Reason: unsupported},
		FeatureNetworkDevices:             {Name: "net device setup", Reason: unsupported},
		FeatureKCSAN:                      {Name: "concurrency sanitizer", Reason: unsupported},
		FeatureDevlinkPCI:                 {Name: "devlink PCI setup", Reason: unsupported},
	}
	if targets.Get(target.OS, target.Arch).HostFuzzer {
		return res, nil
	}
	for n, check := range checkFeature {
		if check == nil {
			continue
		}
		if reason := check(); reason == "" {
			res[n].Enabled = true
			res[n].Reason = "enabled"
		} else {
			res[n].Reason = reason
		}
	}
	return res, nil
}

// Setup enables and does any one-time setup for the requested features on the host.
// Note: this can be called multiple times and must be idempotent.
func Setup(target *prog.Target, features *Features, featureFlags csource.Features, executor string) error {
	if targets.Get(target.OS, target.Arch).HostFuzzer {
		return nil
	}
	args := []string{"setup"}
	if features[FeatureLeakChecking].Enabled {
		args = append(args, "leak")
	}
	if features[FeatureFaultInjection].Enabled {
		args = append(args, "fault")
	}
	if target.OS == "linux" && featureFlags["binfmt_misc"].Enabled {
		args = append(args, "binfmt_misc")
	}
	if features[FeatureKCSAN].Enabled {
		args = append(args, "kcsan")
	}
	_, err := osutil.RunCmd(time.Minute, "", executor, args...)
	return err
}
