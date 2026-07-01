// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package mgrconfig

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseEnabledSyscalls(t *testing.T) {
	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64)
	require.NoError(t, err)

	tests := []struct {
		name   string
		mode   DescriptionsMode
		enable []string
		// TODO: add disable tests as well.
		expectEnabled  []string
		expectDisabled []string
	}{
		{
			name:           "wildcard, no snapshot",
			mode:           ManualDescriptions,
			enable:         []string{"test"},
			expectDisabled: []string{"test$snapshot_only"},
		},
		{
			name:          "wildcard, snapshot",
			mode:          ManualDescriptions | SnapshotDescriptions,
			enable:        []string{"test"},
			expectEnabled: []string{"test$snapshot_only"},
		},
		{
			name:          "no wildcard, no snapshot",
			mode:          ManualDescriptions,
			enable:        []string{"test$snapshot_only"},
			expectEnabled: []string{"test$snapshot_only"},
		},
		{
			name:          "no wildcard, snapshot",
			mode:          ManualDescriptions | SnapshotDescriptions,
			enable:        []string{"test$snapshot_only"},
			expectEnabled: []string{"test$snapshot_only"},
		},
		{
			name:   "automatic allowed",
			mode:   ManualDescriptions | AutoDescriptions,
			enable: []string{"test"},
			expectEnabled: []string{
				"test$automatic",
				"test$automatic_helper",
				"test$manual",
			},
		},
		{
			name:   "manual only",
			mode:   ManualDescriptions,
			enable: []string{"test"},
			expectEnabled: []string{
				"test$automatic_helper",
				"test$manual",
			},
			expectDisabled: []string{
				"test$automatic",
			},
		},
		{
			name:   "auto only",
			mode:   AutoDescriptions,
			enable: []string{"test"},
			expectEnabled: []string{
				"test$automatic",
				"test$automatic_helper",
			},
			expectDisabled: []string{
				"test$manual",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ids, err := ParseEnabledSyscalls(target, test.enable,
				nil, test.mode)
			require.NoError(t, err)
			for _, enabled := range test.expectEnabled {
				assert.Contains(t, ids, target.SyscallMap[enabled].ID)
			}
			for _, disabled := range test.expectDisabled {
				assert.NotContains(t, ids, target.SyscallMap[disabled].ID)
			}
		})
	}
}

func TestCompleteDescriptionsMode(t *testing.T) {
	data := []byte(`{
		"target": "linux/amd64",
		"type": "none",
		"workdir": "/tmp",
		"syzkaller": "testdata/syzkaller",
		"experimental": {
			"descriptions_mode": "invalid"
		}
	}`)
	_, err := LoadData(data)
	require.Error(t, err)
	require.Contains(t, err.Error(), `invalid descriptions_mode "invalid", must be one of: any, auto, manual`)
}

func TestBootTestsValidation(t *testing.T) {
	tempDir := t.TempDir()

	// Create dummy syzkaller structure.
	syzDir := filepath.Join(tempDir, "syzkaller")
	testDir := filepath.Join(syzDir, "sys", "linux", "test")
	err := os.MkdirAll(testDir, 0755)
	require.NoError(t, err)

	// Create a dummy test file.
	dummyTestFile := filepath.Join(testDir, "dummy_test")
	err = os.WriteFile(dummyTestFile, []byte(""), 0644)
	require.NoError(t, err)

	// Create another dummy test file.
	dummyTestFile2 := filepath.Join(testDir, "dummy_test2")
	err = os.WriteFile(dummyTestFile2, []byte(""), 0644)
	require.NoError(t, err)

	// Create a dummy directory.
	dummyDir := filepath.Join(testDir, "dummy_dir")
	err = os.Mkdir(dummyDir, 0755)
	require.NoError(t, err)

	// Create dummy binaries so Complete doesn't fail on them.
	binDir := filepath.Join(syzDir, "bin", "linux_amd64")
	err = os.MkdirAll(binDir, 0755)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(binDir, "syz-execprog"), []byte(""), 0755)
	require.NoError(t, err)
	err = os.WriteFile(filepath.Join(binDir, "syz-executor"), []byte(""), 0755)
	require.NoError(t, err)

	tests := []struct {
		name        string
		bootTests   []string
		expectError bool
		expectBoot  []string
	}{
		{
			name:        "relative path rejected",
			bootTests:   []string{"sys/linux/test/dummy_test"},
			expectError: true,
		},
		{
			name:        "directory traversal rejected",
			bootTests:   []string{"../dummy_test"},
			expectError: true,
		},
		{
			name:        "valid filename only",
			bootTests:   []string{"dummy_test"},
			expectError: false,
			expectBoot:  []string{"dummy_test"},
		},
		{
			name:        "wildcard match",
			bootTests:   []string{"dummy_*"},
			expectError: false,
			expectBoot:  []string{"dummy_test", "dummy_test2"},
		},
		{
			name:        "deduplication",
			bootTests:   []string{"dummy_*", "dummy_test"},
			expectError: false,
			expectBoot:  []string{"dummy_test", "dummy_test2"},
		},
		{
			name:        "wildcard matches only directories",
			bootTests:   []string{"dummy_dir"},
			expectError: true,
		},
		{
			name:        "non-existent test",
			bootTests:   []string{"non_existent"},
			expectError: true,
		},
		{
			name:        "wildcard no match",
			bootTests:   []string{"non_existent*"},
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultValues()
			cfg.RawTarget = "linux/amd64"
			cfg.Type = "none"
			cfg.Reproduce = false
			cfg.Workdir = tempDir
			cfg.Syzkaller = syzDir
			cfg.BootTests = tc.bootTests
			err := SetTargets(cfg)
			require.NoError(t, err)

			err = Complete(cfg)
			if tc.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectBoot, cfg.BootTests)
			}
		})
	}
}
