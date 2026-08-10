// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package triage

import (
	"regexp"
	"slices"
	"strings"

	"github.com/google/syzkaller/syz-cluster/pkg/api"
)

func SelectFuzzConfigs(series *api.Series, fuzzConfigs []*api.FuzzTriageTarget) []*api.KernelFuzzConfig {
	seriesCc := map[string]bool{}
	for _, cc := range series.Cc {
		seriesCc[strings.ToLower(cc)] = true
	}
	modifiedFiles := series.ModifiedFiles()
	var ret, defaultRet []*api.KernelFuzzConfig
	for _, config := range fuzzConfigs {
		matched := slices.ContainsFunc(config.EmailLists, func(cc string) bool {
			return seriesCc[cc]
		})
		matched = matched || matchesPaths(config.PathRegexps, modifiedFiles)
		if matched {
			ret = append(ret, expandCampaigns(config)...)
		} else if len(config.EmailLists) == 0 && len(config.PathRegexps) == 0 {
			defaultRet = append(defaultRet, expandCampaigns(config)...)
		}
	}
	// We want to return the fallback option only if no element matched exactly.
	if len(ret) > 0 {
		return ret
	}
	return defaultRet
}

func matchesPaths(regexps, modifiedFiles []string) bool {
	if len(regexps) == 0 || len(modifiedFiles) == 0 {
		return false
	}
	for _, r := range regexps {
		re, err := regexp.Compile(r)
		if err != nil {
			continue
		}
		if slices.ContainsFunc(modifiedFiles, re.MatchString) {
			return true
		}
	}
	return false
}

func expandCampaigns(config *api.FuzzTriageTarget) []*api.KernelFuzzConfig {
	var ret []*api.KernelFuzzConfig
	for _, campaign := range config.Campaigns {
		c := *campaign
		if c.Focus == "" {
			c.Focus = config.Focus
		}
		if c.CorpusURL == "" {
			c.CorpusURL = config.CorpusURL
		}
		ret = append(ret, &c)
	}
	return ret
}

type MergedFuzzConfig struct {
	KernelConfig string
	Track        string
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
			Track:        key.track,
			FuzzConfig:   mergeFuzzConfigs(groups[key]),
		})
	}
	return ret
}

func mergeFuzzConfigs(configs []*api.KernelFuzzConfig) *api.FuzzConfig {
	var ret api.FuzzConfig
	for _, config := range configs {
		ret.Focus = append(ret.Focus, config.Focus)
		if config.CorpusURL != "" {
			ret.CorpusURLs = append(ret.CorpusURLs, config.CorpusURL)
		}
		ret.SkipCoverCheck = ret.SkipCoverCheck || config.SkipCoverCheck
		// Must be the same.
		ret.BugTitleRe = config.BugTitleRe
	}
	if slices.Contains(ret.Focus, "") {
		// If there's at least one unfocused target,
		// we fuzz everything this way.
		ret.Focus = nil
	} else {
		ret.Focus = unique(ret.Focus)
	}
	ret.CorpusURLs = unique(ret.CorpusURLs)
	return &ret
}

func unique(list []string) []string {
	list = slices.Clone(list)
	slices.Sort(list)
	return slices.Compact(list)
}
