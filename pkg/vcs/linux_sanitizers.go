// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vcs

import (
	"regexp"

	"github.com/google/syzkaller/pkg/debugtracer"
	"github.com/google/syzkaller/pkg/kconfig"
)

type linuxSanitizer struct {
	name      string
	titleRe   *regexp.Regexp
	disable   func(cf *kconfig.ConfigFile)
	dependsOn []*linuxSanitizer
}

var linuxSanitizers = []*linuxSanitizer{
	warnings,
	{
		name:    "ubsan",
		titleRe: regexp.MustCompile(`UBSAN`),
		disable: disableUBSAN,
	},
	{
		name:    "kasan",
		titleRe: regexp.MustCompile(`KASAN`),
		disable: disableKASAN,
	},
	{
		name:    "lockdep",
		titleRe: regexp.MustCompile(`possible deadlock in`),
		disable: disableLockdep,
	},
	{
		name:    "rcu stalls",
		titleRe: regexp.MustCompile(`INFO: rcu detected stall in`),
		disable: disableRcuStalls,
		// TODO: verify whether it actually depends.
		dependsOn: []*linuxSanitizer{warnings},
	},
}

var warnings = &linuxSanitizer{
	name:    "warnings/bugs",
	titleRe: regexp.MustCompile(`WARNING in|kernel BUG in|BUG: `),
	disable: disableWarnings,
}

// It's assumed that the config _already_ has all the needed sanitizers enabled
// and, additionally, some that are not really needed.
func adjustLinuxSanitizers(cf *kconfig.ConfigFile, crashTitle string, dt debugtracer.DebugTracer) {
	matched := map[*linuxSanitizer]bool{}
	for _, item := range linuxSanitizers {
		if !item.titleRe.MatchString(crashTitle) {
			continue
		}
		// Assume there are no cycles.
		queue := []*linuxSanitizer{item}
		for len(queue) > 0 {
			item := queue[len(queue)-1]
			matched[item] = true
			queue = append(queue[:len(queue)-1], item.dependsOn...)
		}
	}
	if len(matched) == 0 {
		// We didn't recognize any sanitizer, so let's not risk disabling all of them.
		return
	}
	var disabledNames []string
	for _, item := range linuxSanitizers {
		if matched[item] {
			continue
		}
		disabledNames = append(disabledNames, item.name)
		item.disable(cf)
	}
	dt.Log("disabled %v in config as it was not needed", disabledNames)
}

func disableWarnings(cf *kconfig.ConfigFile) {
	cf.Unset("BUG")
}

func disableUBSAN(cf *kconfig.ConfigFile) {
	cf.Unset("UBSAN")
}

func disableKASAN(cf *kconfig.ConfigFile) {
	cf.Unset("KASAN")
}

func disableLockdep(cf *kconfig.ConfigFile) {
	cf.Unset("LOCKDEP")
}

func disableRcuStalls(cf *kconfig.ConfigFile) {
	cf.Unset("RCU_STALL_COMMON")
}
