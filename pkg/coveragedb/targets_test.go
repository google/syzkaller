// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package coveragedb_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"cloud.google.com/go/civil"
	"cloud.google.com/go/spanner"
	"github.com/google/syzkaller/pkg/coveragedb"
	"github.com/google/syzkaller/pkg/coveragedb/testutil"
	"github.com/stretchr/testify/require"
)

func saveMergeResult(t *testing.T, client *spanner.Client, descr *coveragedb.HistoryRecord,
	files []*coveragedb.MergedCoverageRecord, funcs []*coveragedb.FuncLines) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, f := range files {
		require.NoError(t, enc.Encode(coveragedb.JSONLWrapper{MCR: f}))
	}
	for _, fn := range funcs {
		require.NoError(t, enc.Encode(coveragedb.JSONLWrapper{FL: fn}))
	}
	_, err := coveragedb.SaveMergeResult(t.Context(), client, descr, json.NewDecoder(&buf))
	require.NoError(t, err)
}

func saveSession(t *testing.T, client *spanner.Client, descr *coveragedb.HistoryRecord,
	filePath, funcName string) {
	saveMergeResult(t, client, descr, []*coveragedb.MergedCoverageRecord{
		makeFileRecord(filePath, map[int]int64{10: 0, 20: 1}),
	}, []*coveragedb.FuncLines{
		{FilePath: filePath, FuncName: funcName, Lines: []int64{10}},
	})
}

func makeFileRecord(path string, lineHits map[int]int64) *coveragedb.MergedCoverageRecord {
	cov := &coveragedb.Coverage{}
	for line, hits := range lineHits {
		cov.AddLineHitCount(line, hits)
	}
	return &coveragedb.MergedCoverageRecord{
		Manager:  "*",
		FilePath: path,
		FileData: cov,
	}
}

func TestGetCoverageTargets(t *testing.T) {
	t.Run("nil client", func(t *testing.T) {
		got, err := coveragedb.GetCoverageTargets(t.Context(), nil, "upstream", coveragedb.TargetFilter{})
		require.Error(t, err)
		require.Nil(t, got)
	})

	t.Run("empty database", func(t *testing.T) {
		client := testutil.SetupCoverageTestDB(t)
		got, err := coveragedb.GetCoverageTargets(t.Context(), client, "upstream", coveragedb.TargetFilter{})
		require.NoError(t, err)
		require.Equal(t, &coveragedb.CoverageTargets{
			Namespace: "upstream",
			Targets:   []coveragedb.UncoveredFunction{},
		}, got)
	})

	t.Run("target discovery and filtering", func(t *testing.T) {
		client := testutil.SetupCoverageTestDB(t)
		ctx := t.Context()

		periodOld, err := coveragedb.MakeTimePeriod(civil.Date{Year: 2026, Month: 8, Day: 31}, "month")
		require.NoError(t, err)
		periodNew, err := coveragedb.MakeTimePeriod(civil.Date{Year: 2026, Month: 9, Day: 30}, "month")
		require.NoError(t, err)

		// Older session in upstream namespace (should NOT be used by GetCoverageTargets).
		saveSession(t, client, &coveragedb.HistoryRecord{
			Namespace: "upstream",
			Repo:      "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git",
			Commit:    "old_commit_1111",
			Duration:  int64(periodOld.Days),
			DateTo:    periodOld.DateTo,
		}, "net/core/dev.c", "old_func")

		// Session in another namespace (android) to verify namespace isolation.
		saveSession(t, client, &coveragedb.HistoryRecord{
			Namespace: "android",
			Repo:      "https://android.googlesource.com/kernel/common",
			Commit:    "android_commit_2222",
			Duration:  int64(periodNew.Days),
			DateTo:    periodNew.DateTo,
		}, "net/core/dev.c", "android_func")

		// Latest session in upstream namespace.
		latestHist := &coveragedb.HistoryRecord{
			Namespace: "upstream",
			Repo:      "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git",
			Commit:    "latest_commit_3333",
			Duration:  int64(periodNew.Days),
			DateTo:    periodNew.DateTo,
		}

		files := []*coveragedb.MergedCoverageRecord{
			// Partially covered file: arch/x86/kvm/mmu.c (lines 10, 20 uncovered; lines 30, 40 covered).
			makeFileRecord("arch/x86/kvm/mmu.c", map[int]int64{10: 0, 20: 0, 30: 5, 40: 2}),
			// Partially covered file: net/core/dev.c (lines 100, 110 uncovered; line 120 covered).
			makeFileRecord("net/core/dev.c", map[int]int64{100: 0, 110: 0, 120: 3}),
			// Partially covered file: fs/ext4/super.c (line 200 uncovered; line 210 covered).
			makeFileRecord("fs/ext4/super.c", map[int]int64{200: 0, 210: 1}),
			// Fully uncovered file: drivers/gpu/drm.c (covered = 0) -> should be excluded.
			makeFileRecord("drivers/gpu/drm.c", map[int]int64{300: 0, 310: 0}),
			// Fully covered file: mm/slab.c (covered = instrumented) -> should be excluded.
			makeFileRecord("mm/slab.c", map[int]int64{400: 1, 410: 2}),
		}

		funcs := []*coveragedb.FuncLines{
			// In arch/x86/kvm/mmu.c:
			// Uncovered function: lines 10, 20 have hitcount 0 -> CANDIDATE!
			{
				FilePath: "arch/x86/kvm/mmu.c",
				FuncName: "kvm_mmu_calc_shadow",
				Lines:    []int64{20, 10}, // Out of order to verify line sorting.
			},
			// Fully covered function: lines 30, 40 have hitcounts 5, 2 -> excluded.
			{
				FilePath: "arch/x86/kvm/mmu.c",
				FuncName: "kvm_mmu_init_page",
				Lines:    []int64{30, 40},
			},
			// Init function: line 10 has hitcount 0, but name starts with __init -> excluded.
			{
				FilePath: "arch/x86/kvm/mmu.c",
				FuncName: "__init_kvm_mmu",
				Lines:    []int64{10},
			},
			// Function with no lines -> excluded.
			{
				FilePath: "arch/x86/kvm/mmu.c",
				FuncName: "empty_kvm_func",
				Lines:    nil,
			},

			// In net/core/dev.c:
			// Uncovered function: lines 100, 110 have hitcount 0 -> CANDIDATE!
			{
				FilePath: "net/core/dev.c",
				FuncName: "dev_queue_xmit_nit",
				Lines:    []int64{100, 110},
			},
			// Partially covered function: line 110 hitcount 0, line 120 hitcount 3 -> CANDIDATE with HasCovered: true!
			{
				FilePath: "net/core/dev.c",
				FuncName: "dev_hard_start_xmit",
				Lines:    []int64{110, 120},
			},

			// In fs/ext4/super.c:
			// Uncovered function: line 200 has hitcount 0 -> CANDIDATE!
			{
				FilePath: "fs/ext4/super.c",
				FuncName: "ext4_destroy_inode",
				Lines:    []int64{200},
			},

			// In drivers/gpu/drm.c (fully uncovered file): should be excluded!
			{
				FilePath: "drivers/gpu/drm.c",
				FuncName: "drm_init_device",
				Lines:    []int64{300, 310},
			},

			// In mm/slab.c (fully covered file): should be excluded!
			{
				FilePath: "mm/slab.c",
				FuncName: "kmem_cache_create",
				Lines:    []int64{400, 410},
			},
		}

		saveMergeResult(t, client, latestHist, files, funcs)

		t.Run("all targets without prefix filter", func(t *testing.T) {
			got, err := coveragedb.GetCoverageTargets(ctx, client, "upstream", coveragedb.TargetFilter{})
			require.NoError(t, err)
			require.Equal(t, "upstream", got.Namespace)
			require.Equal(t, latestHist.Repo, got.KernelRepo)
			require.Equal(t, latestHist.Commit, got.KernelCommit)

			wantTargets := []coveragedb.UncoveredFunction{
				{
					FilePath:   "arch/x86/kvm/mmu.c",
					FuncName:   "kvm_mmu_calc_shadow",
					HasCovered: false,
					Lines:      []int64{10, 20},
				},
				{
					FilePath:   "fs/ext4/super.c",
					FuncName:   "ext4_destroy_inode",
					HasCovered: false,
					Lines:      []int64{200},
				},
				{
					FilePath:   "net/core/dev.c",
					FuncName:   "dev_hard_start_xmit",
					HasCovered: true,
					Lines:      []int64{110},
				},
				{
					FilePath:   "net/core/dev.c",
					FuncName:   "dev_queue_xmit_nit",
					HasCovered: false,
					Lines:      []int64{100, 110},
				},
			}
			require.Equal(t, wantTargets, got.Targets)
		})

		t.Run("filter by folder prefixes with priority ordering", func(t *testing.T) {
			got, err := coveragedb.GetCoverageTargets(ctx, client, "upstream", coveragedb.TargetFilter{
				Prefixes: []string{"net/", "arch/x86/kvm/"},
			})
			require.NoError(t, err)

			// net/ was specified before arch/x86/kvm/, so net candidates come first.
			// fs/ is excluded.
			wantTargets := []coveragedb.UncoveredFunction{
				{
					FilePath:   "net/core/dev.c",
					FuncName:   "dev_hard_start_xmit",
					HasCovered: true,
					Lines:      []int64{110},
				},
				{
					FilePath:   "net/core/dev.c",
					FuncName:   "dev_queue_xmit_nit",
					HasCovered: false,
					Lines:      []int64{100, 110},
				},
				{
					FilePath:   "arch/x86/kvm/mmu.c",
					FuncName:   "kvm_mmu_calc_shadow",
					HasCovered: false,
					Lines:      []int64{10, 20},
				},
			}
			require.Equal(t, wantTargets, got.Targets)
		})

		t.Run("filter with non-matching prefix returns empty targets", func(t *testing.T) {
			got, err := coveragedb.GetCoverageTargets(ctx, client, "upstream", coveragedb.TargetFilter{
				Prefixes: []string{"kernel/bpf/"},
			})
			require.NoError(t, err)
			require.Empty(t, got.Targets)
		})

		t.Run("limit results", func(t *testing.T) {
			got, err := coveragedb.GetCoverageTargets(ctx, client, "upstream", coveragedb.TargetFilter{
				Prefixes: []string{"net/", "arch/x86/kvm/"},
				Limit:    1,
			})
			require.NoError(t, err)
			require.Len(t, got.Targets, 1)
			require.Equal(t, "net/core/dev.c", got.Targets[0].FilePath)
			require.Equal(t, "dev_hard_start_xmit", got.Targets[0].FuncName)
			require.True(t, got.Targets[0].HasCovered)
		})
	})
}
