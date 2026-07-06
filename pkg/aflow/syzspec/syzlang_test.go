// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzspec

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCombineSyzPrograms(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name         string
		baseSeed     string
		generatedSyz string
		wantCombined string
		wantBaseLen  int
	}{
		{
			name:         "empty base seed",
			baseSeed:     "",
			generatedSyz: "r0 = openat(0x0, 0x0, 0x0)",
			wantCombined: "r0 = openat(0x0, 0x0, 0x0)",
			wantBaseLen:  0,
		},
		{
			name:         "single line base seed",
			baseSeed:     "syz_mount_image(0x0, 0x0)",
			generatedSyz: "r0 = openat(0x0, 0x0, 0x0)",
			wantCombined: "syz_mount_image(0x0, 0x0)\nr0 = openat(0x0, 0x0, 0x0)",
			wantBaseLen:  1,
		},
		{
			name:         "multiline base seed",
			baseSeed:     "line1\nline2\nline3",
			generatedSyz: "generated_call()",
			wantCombined: "line1\nline2\nline3\ngenerated_call()",
			wantBaseLen:  3,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gotCombined, gotBaseLen := CombineSyzPrograms(tc.baseSeed, tc.generatedSyz)
			require.Equal(t, tc.wantCombined, gotCombined)
			require.Equal(t, tc.wantBaseLen, gotBaseLen)
		})
	}
}

func TestBaseSeedCallCount(t *testing.T) {
	t.Parallel()

	count, err := BaseSeedCallCount(nil, "amd64")
	require.NoError(t, err)
	require.Equal(t, 0, count)

	count, err = BaseSeedCallCount([]byte(""), "amd64")
	require.NoError(t, err)
	require.Equal(t, 0, count)

	progData := []byte("getpid()\n")
	count, err = BaseSeedCallCount(progData, "amd64")
	require.NoError(t, err)
	require.Equal(t, 1, count)
}

func TestSyzFS(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	sysLinux := filepath.Join(tmpDir, "sys", "linux")
	sysLinuxTest := filepath.Join(sysLinux, "test")
	require.NoError(t, os.MkdirAll(sysLinuxTest, 0755))

	require.NoError(t, os.WriteFile(filepath.Join(sysLinux, "test.txt"), []byte("syscall_test()"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(sysLinux, "auto.txt"), []byte("auto"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(sysLinuxTest, "seed1.txt"), []byte("seed_data"), 0644))

	syzFS := NewSyzFS(tmpDir, "linux")
	require.NotNil(t, syzFS)
	require.Equal(t, "linux", syzFS.OSTarget())

	data, err := syzFS.ReadFile("test.txt")
	require.NoError(t, err)
	require.Equal(t, "syscall_test()", string(data))

	_, err = syzFS.ReadFile("auto.txt")
	require.Error(t, err)

	entries, err := syzFS.ReadDir(".")
	require.NoError(t, err)
	require.NotEmpty(t, entries)

	testEntries, err := syzFS.ReadDir("test")
	require.NoError(t, err)
	require.Len(t, testEntries, 1)
	require.Equal(t, "seed1.txt", testEntries[0].Name())
}

func TestBaseTestSeedLoad(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	sysLinux := filepath.Join(tmpDir, "sys", "linux")
	require.NoError(t, os.MkdirAll(sysLinux, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(sysLinux, "seed.txt"), []byte("seed content"), 0644))

	syzFS := NewSyzFS(tmpDir, "linux")

	t.Run("empty path", func(t *testing.T) {
		seed := BaseTestSeed{Path: ""}
		err := seed.Load(syzFS)
		require.NoError(t, err)
		require.Equal(t, "", seed.Data)
	})

	t.Run("nil syzFS", func(t *testing.T) {
		seed := BaseTestSeed{Path: "seed.txt"}
		err := seed.Load(nil)
		require.Error(t, err)
	})

	t.Run("successful load", func(t *testing.T) {
		seed := BaseTestSeed{Path: "seed.txt"}
		err := seed.Load(syzFS)
		require.NoError(t, err)
		require.Equal(t, "seed content", seed.Data)
	})

	t.Run("file not found", func(t *testing.T) {
		seed := BaseTestSeed{Path: "nonexistent.txt"}
		err := seed.Load(syzFS)
		require.Error(t, err)
	})
}
