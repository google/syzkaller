// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vcs

import (
	"testing"

	"github.com/google/syzkaller/pkg/debugtracer"
	"github.com/google/syzkaller/pkg/kconfig"
)

func TestLinuxSanitizers(t *testing.T) {
	tests := []struct {
		name  string
		crash string
		test  func(cf *kconfig.ConfigFile) bool
	}{
		{
			name:  "warning",
			crash: "WARNING in abcd",
			test: func(cf *kconfig.ConfigFile) bool {
				return onlySet(cf, "BUG")
			},
		},
		{
			name:  "kasan bug",
			crash: "KASAN: slab-use-after-free Read in abcd",
			test: func(cf *kconfig.ConfigFile) bool {
				return onlySet(cf, "KASAN")
			},
		},
		{
			name:  "lockdep",
			crash: "possible deadlock in abcd",
			test: func(cf *kconfig.ConfigFile) bool {
				return onlySet(cf, "LOCKDEP")
			},
		},
		{
			name:  "rcu stall",
			crash: "INFO: rcu detected stall in abcd",
			test: func(cf *kconfig.ConfigFile) bool {
				return onlySet(cf, "BUG", "RCU_STALL_COMMON")
			},
		},
		{
			name:  "unknown title",
			crash: "general protection fault in abcd",
			test: func(cf *kconfig.ConfigFile) bool {
				return onlySet(cf, "BUG", "KASAN", "LOCKDEP", "RCU_STALL_COMMON", "UBSAN")
			},
		},
		{
			name:  "no title",
			crash: "",
			test: func(cf *kconfig.ConfigFile) bool {
				return onlySet(cf, "BUG", "KASAN", "LOCKDEP", "RCU_STALL_COMMON", "UBSAN")
			},
		},
	}

	const base = `
CONFIG_BUG=y
CONFIG_KASAN=y
CONFIG_LOCKDEP=y
CONFIG_RCU_STALL_COMMON=y
CONFIG_UBSAN=y
`
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			conf, err := kconfig.ParseConfigData([]byte(base), "base")
			if err != nil {
				t.Fatal(err)
			}
			adjustLinuxSanitizers(conf, test.crash, &debugtracer.NullTracer{})
			if !test.test(conf) {
				t.Fatal("invalid results")
			}
		})
	}
}

func onlySet(cf *kconfig.ConfigFile, names ...string) bool {
	for _, name := range names {
		if cf.Value(name) != kconfig.Yes {
			return false
		}
	}
	total := 0
	for _, param := range cf.Configs {
		if cf.Value(param.Name) == kconfig.Yes {
			total++
		}
	}
	return total == len(names)
}
