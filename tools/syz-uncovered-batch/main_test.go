// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"math/rand/v2"
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
					"from_line": 2575,
					"to_line": 2575,
					"hit_count": 0
				}
			]
		},
		{
			"func_name": "kvm_partially_covered_fn",
			"blocks": [
				{
					"from_line": 3000,
					"to_line": 3000,
					"hit_count": 5
				},
				{
					"from_line": 3025,
					"to_line": 3025,
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
				{"from_line": 10, "to_line": 10, "hit_count": 0}
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
		cfg := filterConfig{
			paths:        []string{"virt/kvm"},
			excludePaths: []string{"virt/kvm/excluded"},
			filePattern:  regexp.MustCompile(`.*\.c$`),
			rng:          rand.New(rand.NewPCG(1, 2)),
		}
		repo, commit, targets, err := extractUncoveredTargets(strings.NewReader(sampleCoverageJSONL), cfg)
		require.NoError(t, err)
		require.Equal(t, "git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git", repo)
		require.Equal(t, "abdf623ddb75b24659018d3952d8f61937306ae5", commit)
		require.Equal(t, []uncoveredTarget{{
			ID:         "virt_kvm_kvm_main.c_kvm_uncovered_fn_2575",
			FilePath:   "virt/kvm/kvm_main.c",
			LineNumber: 2575,
		}}, targets)
	})

	t.Run("include covered funcs", func(t *testing.T) {
		cfg := filterConfig{
			paths:               []string{"virt/kvm"},
			excludePaths:        []string{"virt/kvm/excluded"},
			filePattern:         regexp.MustCompile(`.*\.c$`),
			includeCoveredFuncs: true,
			rng:                 rand.New(rand.NewPCG(1, 2)),
		}
		_, _, targets, err := extractUncoveredTargets(strings.NewReader(sampleCoverageJSONL), cfg)
		require.NoError(t, err)
		require.ElementsMatch(t, []uncoveredTarget{
			{
				ID:         "virt_kvm_kvm_main.c_kvm_uncovered_fn_2575",
				FilePath:   "virt/kvm/kvm_main.c",
				LineNumber: 2575,
			},
			{
				ID:         "virt_kvm_kvm_main.c_kvm_partially_covered_fn_3025",
				FilePath:   "virt/kvm/kvm_main.c",
				LineNumber: 3025,
			},
		}, targets)
	})

	t.Run("limit", func(t *testing.T) {
		cfg := filterConfig{
			paths:               []string{"virt/kvm"},
			excludePaths:        []string{"virt/kvm/excluded"},
			filePattern:         regexp.MustCompile(`.*\.c$`),
			includeCoveredFuncs: true,
			limit:               1,
			rng:                 rand.New(rand.NewPCG(1, 2)),
		}
		_, _, targets, err := extractUncoveredTargets(strings.NewReader(sampleCoverageJSONL), cfg)
		require.NoError(t, err)
		require.Len(t, targets, 1)
	})
}

func TestGenerateTaskFiles(t *testing.T) {
	tempDir := t.TempDir()
	baseInputs := map[string]any{
		"Image":      "/path/to/image",
		"TargetOS":   "linux",
		"TargetArch": "amd64",
	}
	targets := []uncoveredTarget{
		{
			ID:         "target_1",
			FilePath:   "virt/kvm/kvm_main.c",
			LineNumber: 1234,
		},
	}

	err := generateTaskFiles(tempDir, baseInputs, "https://repo.git", "commit123", targets)
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
	require.Equal(t, []string{"virt/kvm", "drivers/gpu"}, parsePathList("/virt/kvm, drivers/gpu/, "))
}

func TestMatchesPrefix(t *testing.T) {
	require.True(t, matchesPrefix("virt/kvm/kvm_main.c", []string{"virt/kvm"}))
	require.True(t, matchesPrefix("virt/kvm", []string{"virt/kvm"}))
	require.False(t, matchesPrefix("virt/kvm_fake/main.c", []string{"virt/kvm"}))
	require.False(t, matchesPrefix("fs/ext4/super.c", []string{"virt/kvm"}))
}

func TestMatchFunc(t *testing.T) {
	tests := []struct {
		name string
		cfg  filterConfig
		fn   string
		want bool
	}{
		{
			name: "exclude init - suffix",
			cfg:  filterConfig{excludeInit: true},
			fn:   "sched_init",
			want: false,
		},
		{
			name: "exclude init - prefix",
			cfg:  filterConfig{excludeInit: true},
			fn:   "init_sched",
			want: false,
		},
		{
			name: "exclude init - setup suffix",
			cfg:  filterConfig{excludeInit: true},
			fn:   "sched_setup",
			want: false,
		},
		{
			name: "exclude init - normal func",
			cfg:  filterConfig{excludeInit: true},
			fn:   "normal_sched",
			want: true,
		},
		{
			name: "include init",
			cfg:  filterConfig{excludeInit: false},
			fn:   "sched_init",
			want: true,
		},
		{
			name: "func pattern match",
			cfg:  filterConfig{funcPattern: regexp.MustCompile(`.*read.*`)},
			fn:   "ext4_read_inode",
			want: true,
		},
		{
			name: "func pattern mismatch",
			cfg:  filterConfig{funcPattern: regexp.MustCompile(`.*read.*`)},
			fn:   "ext4_write_inode",
			want: false,
		},
		{
			name: "exclude func pattern match",
			cfg:  filterConfig{excludeFuncPattern: regexp.MustCompile(`.*write.*`)},
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

func TestExtractTargetInvalidLine(t *testing.T) {
	cfg := filterConfig{rng: rand.New(rand.NewPCG(1, 2))}
	fn := &cover.FuncCoverage{
		FuncName: "invalid_fn",
		Blocks: []*cover.Block{
			{FromLine: 0, ToLine: 0, HitCount: 0},
			{FromLine: -1, ToLine: -1, HitCount: 0},
		},
	}
	require.Nil(t, cfg.extractTarget("drivers/gpu/test.c", fn))
}
