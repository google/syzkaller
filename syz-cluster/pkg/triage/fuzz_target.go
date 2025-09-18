// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package triage

import (
	"sort"
	"strings"

	"github.com/google/syzkaller/syz-cluster/pkg/api"
)

func SelectFuzzConfigs(series *api.Series, fuzzConfigs []*api.FuzzTriageTarget) []*api.KernelFuzzConfig {
	seriesCc := map[string]bool{}
	for _, cc := range series.Cc {
		seriesCc[strings.ToLower(cc)] = true
	}
	var ret, defaultRet []*api.KernelFuzzConfig
	for _, config := range fuzzConfigs {
		intersects := false
		for _, cc := range config.EmailLists {
			intersects = intersects || seriesCc[cc]
		}
		if intersects {
			ret = append(ret, config.Campaigns...)
		} else if len(config.EmailLists) == 0 {
			defaultRet = append(defaultRet, config.Campaigns...)
		}
	}
	// We want to return the fallback option only if no element matched exactly.
	if len(ret) > 0 {
		return ret
	}
	return defaultRet
}

type MergedFuzzConfig struct {
	KernelConfig string
	FuzzConfig   *api.FuzzConfig
}

func MergeKernelFuzzConfigs(configs []*api.KernelFuzzConfig) []*MergedFuzzConfig {
	type groupKey struct {
		config     string
		track      string
		bugTitleRe string
	}
	groups := map[groupKey][]*api.KernelFuzzConfig{}
	var orderedKeys []groupKey
	for _, config := range configs {
		// Some of the different fuzz configs may still be merged together,
		// e.g. if they only differ in the syscall lists and corpuses.
		key := groupKey{config.KernelConfig, config.Track, config.BugTitleRe}
		if _, ok := groups[key]; !ok {
			orderedKeys = append(orderedKeys, key)
		}
		groups[key] = append(groups[key], config)
	}
	var ret []*MergedFuzzConfig
	for _, key := range orderedKeys {
		// TODO: is there way to auto-generate a prefix?
		ret = append(ret, &MergedFuzzConfig{
			KernelConfig: key.config,
			FuzzConfig:   mergeFuzzConfigs(groups[key]),
		})
	}
	return ret
}

func mergeFuzzConfigs(configs []*api.KernelFuzzConfig) *api.FuzzConfig {
	var ret api.FuzzConfig
	for _, config := range configs {
		if config.Focus != "" {
			ret.Focus = append(ret.Focus, config.Focus)
		}
		if config.CorpusURL != "" {
			ret.CorpusURLs = append(ret.CorpusURLs, config.CorpusURL)
		}
		ret.SkipCoverCheck = ret.SkipCoverCheck || config.SkipCoverCheck
		// Must be the same.
		ret.BugTitleRe = config.BugTitleRe
		ret.Track = config.Track
	}
	ret.Focus = unique(ret.Focus)
	ret.CorpusURLs = unique(ret.CorpusURLs)
	return &ret
}

func unique(list []string) []string {
	seen := make(map[string]struct{}, len(list))
	for _, s := range list {
		seen[s] = struct{}{}
	}
	var unique []string
	for s := range seen {
		unique = append(unique, s)
	}
	sort.Strings(unique)
	return unique
}
