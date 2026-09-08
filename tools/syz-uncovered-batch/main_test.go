// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"math/rand"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/stretchr/testify/require"
)

const sampleCoverageJSONL = `{
	"repo": "git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git",
	"commit": "abdf623ddb75b24659018d3952d8f61937306ae5",
	"file_path": "virt/kvm/kvm_main.c",
	"functions": [
		{
			"func_name": "kvm_uncovered_fn",
			"blocks": [
				{
					"from_line": 2570,
					"to_line": 2580,
					"hit_count": 0
				}
			]
		},
		{
			"func_name": "kvm_partially_covered_fn",
			"blocks": [
				{
					"from_line": 3000,
					"to_line": 3010,
					"hit_count": 5
				},
				{
					"from_line": 3020,
					"to_line": 3030,
					"hit_count": 0
				}
			]
		}
	]
}
{
	"file_path": "virt/kvm/excluded/test.c",
	"functions": [
		{
			"func_name": "kvm_excluded_fn",
			"blocks": [
				{"from_line": 10, "to_line": 20, "hit_count": 0}
			]
		}
	]
}
{
	"file_path": "drivers/gpu/drm/i915.c",
	"functions": [
		{
			"func_name": "i915_init_fn",
			"blocks": [
				{"from_line": 100, "to_line": 100, "hit_count": 0}
			]
		}
	]
}
{
	"file_path": "virt/kvm/header.h",
	"functions": [
		{
			"func_name": "kvm_header_fn",
			"blocks": [
				{"from_line": 5, "to_line": 5, "hit_count": 0}
			]
		}
	]
}
`

func TestExtractUncoveredTargets(t *testing.T) {
	t.Run("default filtering", func(t *testing.T) {
		cfg := FilterConfig{
			Paths:        []string{"virt/kvm"},
			ExcludePaths: []string{"virt/kvm/excluded"},
			FilePattern:  regexp.MustCompile(`.*\.c$`),
		}
		repo, commit, targets, err := ExtractUncoveredTargets(strings.NewReader(sampleCoverageJSONL), cfg)
		require.NoError(t, err)
		require.Equal(t, "git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git", repo)
		require.Equal(t, "abdf623ddb75b24659018d3952d8f61937306ae5", commit)
		require.Len(t, targets, 1)
		require.Equal(t, UncoveredTarget{
			ID:         "virt_kvm_kvm_main.c_kvm_uncovered_fn_2575",
			FilePath:   "virt/kvm/kvm_main.c",
			LineNumber: 2575,
			FuncName:   "kvm_uncovered_fn",
		}, targets[0])
	})

	t.Run("include covered funcs", func(t *testing.T) {
		cfg := FilterConfig{
			Paths:               []string{"virt/kvm"},
			ExcludePaths:        []string{"virt/kvm/excluded"},
			FilePattern:         regexp.MustCompile(`.*\.c$`),
			IncludeCoveredFuncs: true,
		}
		_, _, targets, err := ExtractUncoveredTargets(strings.NewReader(sampleCoverageJSONL), cfg)
		require.NoError(t, err)
		require.Len(t, targets, 2)
		require.Equal(t, "virt_kvm_kvm_main.c_kvm_uncovered_fn_2575", targets[0].ID)
		require.Equal(t, "virt_kvm_kvm_main.c_kvm_partially_covered_fn_3025", targets[1].ID)
	})

	t.Run("limit", func(t *testing.T) {
		cfg := FilterConfig{
			Paths:               []string{"virt/kvm"},
			ExcludePaths:        []string{"virt/kvm/excluded"},
			FilePattern:         regexp.MustCompile(`.*\.c$`),
			IncludeCoveredFuncs: true,
			Limit:               1,
		}
		_, _, targets, err := ExtractUncoveredTargets(strings.NewReader(sampleCoverageJSONL), cfg)
		require.NoError(t, err)
		require.Len(t, targets, 1)
	})
}

// TestExtractUncoveredTargetsRoundRobin verifies that, once every function has
// contributed a target, the remaining uncovered blocks are sampled round-robin.
// A nil FilterConfig.Rand keeps both the block and the candidate order stable.
func TestExtractUncoveredTargetsRoundRobin(t *testing.T) {
	const jsonl = `{
		"repo": "git://repo.git",
		"commit": "commit123",
		"file_path": "a.c",
		"functions": [
			{
				"func_name": "fn_multi",
				"blocks": [
					{"from_line": 10, "to_line": 10, "hit_count": 0},
					{"from_line": 20, "to_line": 20, "hit_count": 0}
				]
			},
			{
				"func_name": "fn_single",
				"blocks": [
					{"from_line": 30, "to_line": 30, "hit_count": 0}
				]
			}
		]
	}`
	var (
		multi10  = UncoveredTarget{ID: "a.c_fn_multi_10", FilePath: "a.c", LineNumber: 10, FuncName: "fn_multi"}
		multi20  = UncoveredTarget{ID: "a.c_fn_multi_20", FilePath: "a.c", LineNumber: 20, FuncName: "fn_multi"}
		single30 = UncoveredTarget{ID: "a.c_fn_single_30", FilePath: "a.c", LineNumber: 30, FuncName: "fn_single"}
	)
	tests := []struct {
		name  string
		limit int
		want  []UncoveredTarget
	}{
		{
			name:  "one target per function",
			limit: 2,
			want:  []UncoveredTarget{multi10, single30},
		},
		{
			name:  "second pass over functions with blocks left",
			limit: 3,
			want:  []UncoveredTarget{multi10, single30, multi20},
		},
		{
			name:  "limit above the number of uncovered blocks",
			limit: 5,
			want:  []UncoveredTarget{multi10, single30, multi20},
		},
		{
			name:  "no limit takes all uncovered blocks",
			limit: 0,
			want:  []UncoveredTarget{multi10, single30, multi20},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, got, err := ExtractUncoveredTargets(strings.NewReader(jsonl), FilterConfig{Limit: tt.limit})
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestGenerateTaskFiles(t *testing.T) {
	tempDir := t.TempDir()
	baseInputs := map[string]any{
		"Image":      "/path/to/image",
		"TargetOS":   "linux",
		"TargetArch": "amd64",
	}
	targets := []UncoveredTarget{
		{
			ID:         "target_1",
			FilePath:   "virt/kvm/kvm_main.c",
			LineNumber: 1234,
			FuncName:   "kvm_vm_ioctl",
		},
	}

	err := GenerateTaskFiles(tempDir, baseInputs, "https://repo.git", "commit123", targets)
	require.NoError(t, err)

	taskFile := filepath.Join(tempDir, "target_1.json")
	require.True(t, osutil.IsExist(taskFile))

	type taskInput struct {
		FilePath     string
		LineNumber   int
		KernelRepo   string
		KernelCommit string
		Image        string
		TargetOS     string
		TargetArch   string
	}
	inputs, err := osutil.ReadJSON[taskInput](taskFile)
	require.NoError(t, err)
	require.Equal(t, taskInput{
		FilePath:     "virt/kvm/kvm_main.c",
		LineNumber:   1234,
		KernelRepo:   "https://repo.git",
		KernelCommit: "commit123",
		Image:        "/path/to/image",
		TargetOS:     "linux",
		TargetArch:   "amd64",
	}, inputs)
}

func TestParsePathList(t *testing.T) {
	require.Nil(t, parsePathList(""))
	require.Equal(t, []string{"virt/kvm", "drivers/gpu"}, parsePathList("virt/kvm, drivers/gpu/, "))
}

func TestMatchesPrefix(t *testing.T) {
	require.True(t, matchesPrefix("virt/kvm/kvm_main.c", []string{"virt/kvm"}))
	require.True(t, matchesPrefix("virt/kvm/kvm_main.c", []string{"virt/kvm/"}))
	require.True(t, matchesPrefix("virt/kvm", []string{"virt/kvm"}))
	require.False(t, matchesPrefix("virt/kvm_fake/main.c", []string{"virt/kvm"}))
	require.False(t, matchesPrefix("fs/ext4/super.c", []string{"virt/kvm"}))
}

func TestPickLine(t *testing.T) {
	single := &cover.Block{FromLine: 42, ToLine: 42}
	require.Equal(t, 42, pickLine(single, nil))
	require.Equal(t, 42, pickLine(single, rand.New(rand.NewSource(1))))

	multi := &cover.Block{FromLine: 100, ToLine: 110}
	require.Equal(t, 105, pickLine(multi, nil))
	rnd := pickLine(multi, rand.New(rand.NewSource(1)))
	require.GreaterOrEqual(t, rnd, 100)
	require.LessOrEqual(t, rnd, 110)
}

func TestMatchFunc(t *testing.T) {
	tests := []struct {
		name string
		cfg  FilterConfig
		fn   string
		want bool
	}{
		{
			name: "exclude init - suffix",
			cfg:  FilterConfig{ExcludeInit: true},
			fn:   "sched_init",
			want: false,
		},
		{
			name: "exclude init - prefix",
			cfg:  FilterConfig{ExcludeInit: true},
			fn:   "init_sched",
			want: false,
		},
		{
			name: "exclude init - setup suffix",
			cfg:  FilterConfig{ExcludeInit: true},
			fn:   "sched_setup",
			want: false,
		},
		{
			name: "exclude init - normal func",
			cfg:  FilterConfig{ExcludeInit: true},
			fn:   "normal_sched",
			want: true,
		},
		{
			name: "include init",
			cfg:  FilterConfig{ExcludeInit: false},
			fn:   "sched_init",
			want: true,
		},
		{
			name: "func pattern match",
			cfg:  FilterConfig{FuncPattern: regexp.MustCompile(`.*read.*`)},
			fn:   "ext4_read_inode",
			want: true,
		},
		{
			name: "func pattern mismatch",
			cfg:  FilterConfig{FuncPattern: regexp.MustCompile(`.*read.*`)},
			fn:   "ext4_write_inode",
			want: false,
		},
		{
			name: "exclude func pattern match",
			cfg:  FilterConfig{ExcludeFuncPattern: regexp.MustCompile(`.*write.*`)},
			fn:   "ext4_write_inode",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, tt.cfg.matchFunc(tt.fn))
		})
	}
}

func TestUncoveredBlocksInvalidLines(t *testing.T) {
	cfg := FilterConfig{}
	fn := &cover.FuncCoverage{
		FuncName: "invalid_fn",
		Blocks: []*cover.Block{
			{FromLine: 0, ToLine: 0, HitCount: 0},
			{FromLine: -1, ToLine: -1, HitCount: 0},
		},
	}
	require.Empty(t, cfg.uncoveredBlocks(fn))
}
