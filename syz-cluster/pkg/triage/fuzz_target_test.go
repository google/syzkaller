// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package triage

import (
	"testing"

	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/stretchr/testify/assert"
)

func TestSelectFuzzConfigs(t *testing.T) {
	bpf, bpfKmsan, net, mainline := &api.KernelFuzzConfig{},
		&api.KernelFuzzConfig{},
		&api.KernelFuzzConfig{},
		&api.KernelFuzzConfig{}
	configs := []*api.FuzzTriageTarget{
		{
			EmailLists: []string{"bpf@list"},
			Campaigns:  []*api.KernelFuzzConfig{bpf, bpfKmsan},
		},
		{
			EmailLists: []string{"net@list"},
			Campaigns:  []*api.KernelFuzzConfig{net},
		},
		{
			EmailLists: nil,
			Campaigns:  []*api.KernelFuzzConfig{mainline},
		},
	}
	tests := []struct {
		testName string
		result   []*api.KernelFuzzConfig
		series   *api.Series
	}{
		{
			testName: "select-one",
			result:   []*api.KernelFuzzConfig{net},
			series:   &api.Series{Cc: []string{"net@list"}},
		},
		{
			testName: "select-both",
			result:   []*api.KernelFuzzConfig{bpf, bpfKmsan, net},
			series:   &api.Series{Cc: []string{"bpf@list", "net@list"}},
		},
		{
			testName: "fallback",
			result:   []*api.KernelFuzzConfig{mainline},
			series:   &api.Series{Cc: []string{"unknown@list"}},
		},
	}

	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			ret := SelectFuzzConfigs(test.series, configs)
			assert.Equal(t, test.result, ret)
		})
	}
}

func TestMergeKernelFuzzConfigs(t *testing.T) {
	t.Run("split", func(t *testing.T) {
		assert.Equal(t, []*MergedFuzzConfig{
			{
				KernelConfig: "kasan_config",
				FuzzConfig: &api.FuzzConfig{
					Track: "KASAN",
					Focus: []string{"net"},
				},
			},
			{
				KernelConfig: "kmsan_config",
				FuzzConfig: &api.FuzzConfig{
					Track: "KMSAN",
					Focus: []string{"net"},
				},
			},
		}, MergeKernelFuzzConfigs([]*api.KernelFuzzConfig{
			{
				Track:        "KASAN",
				KernelConfig: "kasan_config",
				Focus:        "net",
			},
			{
				Track:        "KMSAN",
				KernelConfig: "kmsan_config",
				Focus:        "net",
			},
		}))
	})
	t.Run("merge", func(t *testing.T) {
		assert.Equal(t, []*MergedFuzzConfig{
			{
				KernelConfig: "kasan_config",
				FuzzConfig: &api.FuzzConfig{
					Track: "KASAN",
					Focus: []string{"bpf", "net"},
				},
			},
		}, MergeKernelFuzzConfigs([]*api.KernelFuzzConfig{
			{
				Track:        "KASAN",
				KernelConfig: "kasan_config",
				Focus:        "net",
			},
			{
				Track:        "KASAN",
				KernelConfig: "kasan_config",
				Focus:        "bpf",
			},
		}))
	})
}

func TestMergeFuzzConfigs(t *testing.T) {
	assert.Equal(t, &api.FuzzConfig{
		Focus:          []string{"bpf", "net"},
		CorpusURLs:     []string{"url1", "url2"},
		SkipCoverCheck: true,
		BugTitleRe:     "regexp",
	}, mergeFuzzConfigs([]*api.KernelFuzzConfig{
		{
			Focus:      "net",
			CorpusURL:  "url2",
			BugTitleRe: "regexp",
		},
		{
			Focus:          "bpf",
			CorpusURL:      "url1",
			BugTitleRe:     "regexp",
			SkipCoverCheck: true,
		},
	}))
}
