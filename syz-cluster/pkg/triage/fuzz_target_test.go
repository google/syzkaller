// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package triage

import (
	"fmt"
	"testing"

	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSelectFuzzConfigs(t *testing.T) {
	bpf, bpfKmsan, net, bt, fs, mainline := &api.KernelFuzzConfig{},
		&api.KernelFuzzConfig{},
		&api.KernelFuzzConfig{},
		&api.KernelFuzzConfig{},
		&api.KernelFuzzConfig{},
		&api.KernelFuzzConfig{}
	configs := []*api.FuzzTriageTarget{
		{
			EmailLists: []string{"bpf@list"},
			Campaigns:  []*api.KernelFuzzConfig{bpf, bpfKmsan},
		},
		{
			EmailLists:         []string{"net@list"},
			PathRegexps:        []string{"^net/"},
			ExcludePathRegexps: []string{"^net/bluetooth/"},
			Campaigns:          []*api.KernelFuzzConfig{net},
		},
		{
			EmailLists:  []string{"bt@list"},
			PathRegexps: []string{"^net/bluetooth/"},
			Campaigns:   []*api.KernelFuzzConfig{bt},
		},
		{
			EmailLists:  []string{"fs@list"},
			PathRegexps: []string{"^fs/|include/linux/fs"},
			Campaigns:   []*api.KernelFuzzConfig{fs},
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
			testName: "select-by-email",
			result:   []*api.KernelFuzzConfig{net},
			series:   &api.Series{Cc: []string{"net@list"}},
		},
		{
			testName: "select-both-by-email",
			result:   []*api.KernelFuzzConfig{bpf, bpfKmsan, net},
			series:   &api.Series{Cc: []string{"bpf@list", "net@list"}},
		},
		{
			testName: "select-by-path-only",
			result:   []*api.KernelFuzzConfig{fs},
			series: &api.Series{
				Cc: []string{"unknown@list"},
				Patches: []api.SeriesPatch{
					{Body: []byte("diff --git a/fs/ext4/super.c b/fs/ext4/super.c\n--- a/fs/ext4/super.c\n+++ b/fs/ext4/super.c\n")},
				},
			},
		},
		{
			testName: "exclude-path-regexp",
			result:   []*api.KernelFuzzConfig{bt},
			series: &api.Series{
				Cc: []string{"unknown@list"},
				Patches: []api.SeriesPatch{
					{Body: []byte("diff --git a/net/bluetooth/hci.c b/net/bluetooth/hci.c\n" +
						"--- a/net/bluetooth/hci.c\n+++ b/net/bluetooth/hci.c\n")},
				},
			},
		},
		{
			testName: "exclude-and-include-path-regexp",
			result:   []*api.KernelFuzzConfig{net, bt},
			series: &api.Series{
				Cc: []string{"unknown@list"},
				Patches: []api.SeriesPatch{
					{Body: []byte("diff --git a/net/bluetooth/hci.c b/net/bluetooth/hci.c\n" +
						"--- a/net/bluetooth/hci.c\n+++ b/net/bluetooth/hci.c\n")},
					{Body: []byte("diff --git a/net/core/sock.c b/net/core/sock.c\n--- a/net/core/sock.c\n+++ b/net/core/sock.c\n")},
				},
			},
		},
		{
			testName: "select-by-email-and-path",
			result:   []*api.KernelFuzzConfig{net, fs},
			series: &api.Series{
				Cc: []string{"net@list"},
				Patches: []api.SeriesPatch{
					{Body: []byte("diff --git a/fs/ext4/super.c b/fs/ext4/super.c\n--- a/fs/ext4/super.c\n+++ b/fs/ext4/super.c\n")},
				},
			},
		},
		{
			testName: "fallback-when-neither-matches",
			result:   []*api.KernelFuzzConfig{mainline},
			series: &api.Series{
				Cc: []string{"unknown@list"},
				Patches: []api.SeriesPatch{
					{Body: []byte("diff --git a/mm/vma.c b/mm/vma.c\n--- a/mm/vma.c\n+++ b/mm/vma.c\n")},
				},
			},
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
				Track:        "KASAN",
				FuzzConfig: &api.FuzzConfig{
					Focus: []string{"net"},
				},
			},
			{
				KernelConfig: "kmsan_config",
				Track:        "KMSAN",
				FuzzConfig: &api.FuzzConfig{
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
				Track:        "KASAN",
				FuzzConfig: &api.FuzzConfig{
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
	t.Run("all-focused", func(t *testing.T) {
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
	})
	t.Run("with-unfocused", func(t *testing.T) {
		assert.Equal(t, &api.FuzzConfig{
			Focus:          nil,
			CorpusURLs:     []string{"url1", "url2"},
			SkipCoverCheck: true,
			BugTitleRe:     "regexp",
		}, mergeFuzzConfigs([]*api.KernelFuzzConfig{
			{
				Focus:      "fs",
				CorpusURL:  "url2",
				BugTitleRe: "regexp",
			},
			{
				Focus:          "",
				CorpusURL:      "url1",
				BugTitleRe:     "regexp",
				SkipCoverCheck: true,
			},
		}))
	})
}

func TestDefaultFuzzTargetsSelection(t *testing.T) {
	targets := api.DefaultFuzzTargets()
	tests := []struct {
		name           string
		files          []string
		cc             []string
		wantFocus      []string
		skipCoverCheck bool
	}{
		{
			name:      "kvm-by-path",
			files:     []string{"arch/x86/kvm/vmx/vmx.c"},
			wantFocus: []string{api.FocusKVM},
		},
		{
			name:      "kvm-by-cc",
			cc:        []string{"kvm@vger.kernel.org"},
			wantFocus: []string{api.FocusKVM},
		},
		{
			name:      "io_uring",
			files:     []string{"io_uring/io_uring.c"},
			wantFocus: []string{api.FocusIoUring},
		},
		{
			name:      "bpf-by-path",
			files:     []string{"kernel/bpf/verifier.c"},
			wantFocus: []string{api.FocusBPF},
		},
		{
			name:      "bpf-by-cc",
			cc:        []string{"bpf@vger.kernel.org"},
			wantFocus: []string{api.FocusBPF},
		},
		{
			name:      "net-by-path",
			files:     []string{"net/ipv4/tcp.c"},
			wantFocus: []string{api.FocusNet},
		},
		{
			name:      "net-by-cc",
			cc:        []string{"netdev@vger.kernel.org"},
			wantFocus: []string{api.FocusNet},
		},
		{
			name:      "bluetooth-excluded-from-net",
			files:     []string{"net/bluetooth/hci_core.c"},
			wantFocus: []string{api.FocusBluetooth},
		},
		{
			name:      "bluetooth-and-net",
			files:     []string{"net/bluetooth/hci_core.c", "net/ipv4/tcp.c"},
			wantFocus: []string{api.FocusBluetooth, api.FocusNet},
		},
		{
			name:      "network-fs-by-path",
			files:     []string{"fs/smb/client/cifsfs.c"},
			wantFocus: []string{api.FocusFS, api.FocusNet},
		},
		{
			name:      "network-fs-by-cc",
			cc:        []string{"linux-nfs@vger.kernel.org"},
			wantFocus: []string{api.FocusFS, api.FocusNet},
		},
		{
			name:      "local-fs",
			files:     []string{"fs/ext4/inode.c"},
			wantFocus: []string{api.FocusFS},
		},
		{
			name:      "usb",
			files:     []string{"drivers/usb/core/hub.c"},
			wantFocus: []string{api.FocusUSB},
		},
		{
			name:           "mm-by-path",
			files:          []string{"mm/mmap.c"},
			wantFocus:      []string{api.FocusMM},
			skipCoverCheck: true,
		},
		{
			name:           "mm-by-cc",
			cc:             []string{"linux-mm@kvack.org"},
			wantFocus:      []string{api.FocusMM},
			skipCoverCheck: true,
		},
		{
			name:      "multi-subsystem-files",
			files:     []string{"net/ipv4/tcp.c", "kernel/bpf/verifier.c"},
			wantFocus: []string{api.FocusBPF, api.FocusNet},
		},
		{
			name:      "matched-and-unmatched-files",
			files:     []string{"net/ipv4/tcp.c", "kernel/sched/core.c"},
			wantFocus: []string{api.FocusNet},
		},
		{
			name:      "fallback",
			files:     []string{"kernel/sched/core.c", "lib/string.c"},
			cc:        []string{"linux-kernel@vger.kernel.org"},
			wantFocus: nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			configs := MergeKernelFuzzConfigs(SelectFuzzConfigs(makeTestSeries(tc.files, tc.cc), targets))
			require.Len(t, configs, 1)
			assert.Equal(t, tc.wantFocus, configs[0].FuzzConfig.Focus)
			assert.Equal(t, tc.skipCoverCheck, configs[0].FuzzConfig.SkipCoverCheck)
			assert.NotEmpty(t, configs[0].FuzzConfig.CorpusURLs)
		})
	}
}

func makeTestSeries(files, cc []string) *api.Series {
	series := &api.Series{Cc: cc}
	for _, file := range files {
		diff := fmt.Sprintf("diff --git a/%s b/%s\n--- a/%s\n+++ b/%s\n", file, file, file, file)
		series.Patches = append(series.Patches, api.SeriesPatch{Body: []byte(diff)})
	}
	return series
}
