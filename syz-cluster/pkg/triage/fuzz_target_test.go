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
			PathRegexps: []string{"^kernel/bpf/"},
			Campaigns:   []*api.KernelFuzzConfig{bpf, bpfKmsan},
		},
		{
			PathRegexps:        []string{"^net/"},
			ExcludePathRegexps: []string{"^net/bluetooth/"},
			Campaigns:          []*api.KernelFuzzConfig{net},
		},
		{
			PathRegexps: []string{"^net/bluetooth/"},
			Campaigns:   []*api.KernelFuzzConfig{bt},
		},
		{
			PathRegexps: []string{"^fs/|include/linux/fs"},
			Campaigns:   []*api.KernelFuzzConfig{fs},
		},
		{
			Campaigns: []*api.KernelFuzzConfig{mainline},
		},
	}
	tests := []struct {
		testName string
		result   []*api.KernelFuzzConfig
		series   *api.Series
	}{
		{
			testName: "select-by-path",
			result:   []*api.KernelFuzzConfig{fs},
			series:   makeTestSeries([]string{"fs/ext4/super.c"}),
		},
		{
			testName: "select-multiple-targets",
			result:   []*api.KernelFuzzConfig{bpf, bpfKmsan, net},
			series:   makeTestSeries([]string{"kernel/bpf/verifier.c", "net/core/sock.c"}),
		},
		{
			testName: "exclude-path-regexp",
			result:   []*api.KernelFuzzConfig{bt},
			series:   makeTestSeries([]string{"net/bluetooth/hci.c"}),
		},
		{
			testName: "exclude-and-include-path-regexp",
			result:   []*api.KernelFuzzConfig{net, bt},
			series:   makeTestSeries([]string{"net/bluetooth/hci.c", "net/core/sock.c"}),
		},
		{
			testName: "fallback-when-unmatched",
			result:   []*api.KernelFuzzConfig{mainline},
			series:   makeTestSeries([]string{"mm/vma.c"}),
		},
		{
			testName: "fallback-when-empty",
			result:   []*api.KernelFuzzConfig{mainline},
			series:   makeTestSeries(nil),
		},
		{
			testName: "small-stable-rc-stays-focused",
			result:   []*api.KernelFuzzConfig{net},
			series:   makeStableRCSeries("net/core/sock.c", api.MaxRCFocusedPatches),
		},
		{
			testName: "large-stable-rc-uses-unfocused-fallback",
			result:   []*api.KernelFuzzConfig{mainline},
			series:   makeStableRCSeries("net/core/sock.c", api.MaxRCFocusedPatches+1),
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
		wantFocus      []string
		skipCoverCheck bool
		wantCorpora    []string
	}{
		{
			name:      "kvm",
			files:     []string{"arch/x86/kvm/vmx/vmx.c"},
			wantFocus: []string{api.FocusKVM},
		},
		{
			name:      "kvm-arm64-not-matched-as-kvm",
			files:     []string{"arch/arm64/kvm/sys_regs.c", "include/kvm/arm_vgic.h"},
			wantFocus: nil,
		},
		{
			name:      "io_uring",
			files:     []string{"io_uring/io_uring.c"},
			wantFocus: []string{api.FocusIoUring},
		},
		{
			name:      "bpf",
			files:     []string{"kernel/bpf/verifier.c"},
			wantFocus: []string{api.FocusBPF},
		},
		{
			name:      "net",
			files:     []string{"net/ipv4/tcp.c"},
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
			name:      "network-fs",
			files:     []string{"fs/smb/client/cifsfs.c"},
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
			name:      "usb-wireless-ath9k-wmi",
			files:     []string{"drivers/net/wireless/ath/ath9k/wmi.c"},
			wantFocus: []string{api.FocusNet, api.FocusUSB},
		},
		{
			name:      "pci-wireless-ath9k-excluded-from-usb",
			files:     []string{"drivers/net/wireless/ath/ath9k/pci.c"},
			wantFocus: []string{api.FocusNet},
		},
		{
			name:           "mm",
			files:          []string{"mm/mmap.c"},
			wantFocus:      []string{api.FocusMM},
			skipCoverCheck: true,
		},
		{
			name:      "mmc-and-mmiotrace-headers-not-mm",
			files:     []string{"include/linux/mmc/host.h", "include/linux/mmiotrace.h"},
			wantFocus: nil,
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
			name: "selftest-and-doc-do-not-hijack-core-series",
			files: []string{
				"include/linux/spinlock.h",
				"kernel/locking/spinlock.c",
				"rust/kernel/sync/lock/spinlock.rs",
				"tools/testing/selftests/bpf/bpf_experimental.h",
				"Documentation/usb/raw-gadget.rst",
			},
			wantFocus: nil,
			wantCorpora: []string{
				"https://storage.googleapis.com/syzkaller/corpus/ci-upstream-kasan-gce-root-corpus.db",
			},
		},
		{
			name:      "fallback",
			files:     []string{"kernel/sched/core.c", "lib/string.c"},
			wantFocus: nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			configs := MergeKernelFuzzConfigs(SelectFuzzConfigs(makeTestSeries(tc.files), targets))
			require.Len(t, configs, 1)
			assert.Equal(t, tc.wantFocus, configs[0].FuzzConfig.Focus)
			assert.Equal(t, tc.skipCoverCheck, configs[0].FuzzConfig.SkipCoverCheck)
			assert.NotEmpty(t, configs[0].FuzzConfig.CorpusURLs)
			if tc.wantCorpora != nil {
				assert.Equal(t, tc.wantCorpora, configs[0].FuzzConfig.CorpusURLs)
			}
		})
	}
}

func makeTestSeries(files []string) *api.Series {
	series := &api.Series{}
	for _, file := range files {
		diff := fmt.Sprintf("diff --git a/%s b/%s\n--- a/%s\n+++ b/%s\n", file, file, file, file)
		series.Patches = append(series.Patches, api.SeriesPatch{Body: []byte(diff)})
	}
	return series
}

func makeStableRCSeries(file string, numPatches int) *api.Series {
	files := make([]string, numPatches)
	for i := range files {
		files[i] = file
	}
	series := makeTestSeries(files)
	series.XStable = "review"
	series.XKernelTestBranch = "linux-6.12.y"
	return series
}
