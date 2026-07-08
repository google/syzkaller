// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzspec

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	_ "github.com/google/syzkaller/sys"
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

	tests := []struct {
		name     string
		progData []byte
		want     int
	}{
		{name: "nil data", progData: nil, want: 0},
		{name: "empty data", progData: []byte(""), want: 0},
		{name: "single call", progData: []byte("getpid()\n"), want: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			count, err := BaseSeedCallCount(tt.progData, "amd64")
			require.NoError(t, err)
			require.Equal(t, tt.want, count)
		})
	}
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

func TestIsAutoTxt(t *testing.T) {
	t.Parallel()

	tests := []struct {
		path string
		want bool
	}{
		{path: "auto.txt", want: true},
		{path: "auto.txt.const", want: true},
		{path: "test/auto.txt", want: true},
		{path: "test/auto.txt.const", want: true},
		{path: "sys/linux/auto.txt", want: true},
		{path: "/abs/path/sys/linux/auto.txt", want: true},
		{path: "sys.txt", want: false},
		{path: "auto.txt.foo", want: false},
		{path: "test/auto.txt.foo", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.want, IsAutoTxt(tt.path))
		})
	}
}

func TestCleanPath(t *testing.T) {
	t.Parallel()

	syzDir := "/tmp/mock_syzkaller"
	syzFS := NewSyzFS(syzDir, "linux")

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "empty path", input: "", expected: ""},
		{name: "bare description file", input: "sys.txt", expected: "sys.txt"},
		{name: "bare const file", input: "sys.txt.const", expected: "sys.txt.const"},
		{name: "virtual seed path", input: "test/syz_mount_0", expected: "test/syz_mount_0"},
		{name: "virtual skill path", input: "skills/kvm.md", expected: "skills/kvm.md"},
		{name: "local executor file", input: "executor/common.h", expected: "executor/common.h"},
		{name: "local docs file", input: "docs/linux/kernel.md", expected: "docs/linux/kernel.md"},
		{name: "sys/linux prefix", input: "sys/linux/sys.txt", expected: "sys.txt"},
		{name: "sys/linux test prefix", input: "sys/linux/test/seed1.txt", expected: "test/seed1.txt"},
		{name: "os target prefix", input: "linux/sys.txt", expected: "sys.txt"},
		{name: "sys prefix only", input: "sys/sys.txt", expected: "sys.txt"},
		{
			name:     "absolute path under repo root for description",
			input:    filepath.Join(syzDir, "sys", "linux", "sys.txt"),
			expected: "sys.txt",
		},
		{
			name:     "absolute path under repo root for test seed",
			input:    filepath.Join(syzDir, "sys", "linux", "test", "seed1.txt"),
			expected: "test/seed1.txt",
		},
		{
			name:     "absolute path under repo root for docs",
			input:    filepath.Join(syzDir, "docs", "linux", "syzlang", "skills", "kvm.md"),
			expected: "docs/linux/syzlang/skills/kvm.md",
		},
		{
			name:     "absolute path under repo root for executor",
			input:    filepath.Join(syzDir, "executor", "common.h"),
			expected: "executor/common.h",
		},
		{name: "relative traversal path", input: "../sys.txt", expected: "../sys.txt"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := syzFS.CleanPath(tt.input)
			require.Equal(t, tt.expected, got)
		})
	}
}

func TestSyzFS_VirtualFileSystem(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	sysLinux := filepath.Join(tmpDir, "sys", "linux")
	sysLinuxTest := filepath.Join(sysLinux, "test")
	skillsDir := filepath.Join(tmpDir, "docs", "linux", "syzlang", "skills")
	executorDir := filepath.Join(tmpDir, "executor")
	docsDir := filepath.Join(tmpDir, "docs")

	require.NoError(t, os.MkdirAll(sysLinuxTest, 0755))
	require.NoError(t, os.MkdirAll(skillsDir, 0755))
	require.NoError(t, os.MkdirAll(executorDir, 0755))

	// Setup mock files across virtual locations.
	require.NoError(t, os.WriteFile(filepath.Join(sysLinux, "sys.txt"), []byte("sys content"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(sysLinux, "sys.txt.const"), []byte("SYS_CONST = 1"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(sysLinuxTest, "seed1.txt"), []byte("seed data"), 0644))
	kvmDoc := "---\nname: kvm\ndescription: KVM Skill\n---\nKVM Body"
	require.NoError(t, os.WriteFile(filepath.Join(skillsDir, "kvm.md"), []byte(kvmDoc), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(skillsDir, "README.md"), []byte("# Skills README"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(executorDir, "common.h"), []byte("common header"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(docsDir, "guide.md"), []byte("guide doc"), 0644))

	syzFS := NewSyzFS(tmpDir, "linux")
	require.Equal(t, "linux", syzFS.OSTarget())
	require.Equal(t, tmpDir, syzFS.SyzkallerPath())

	// 1. Root description files.
	data, err := syzFS.ReadFile("sys.txt")
	require.NoError(t, err)
	require.Equal(t, "sys content", string(data))

	dataConst, err := syzFS.ReadFile("sys.txt.const")
	require.NoError(t, err)
	require.Equal(t, "SYS_CONST = 1", string(dataConst))

	// 2. Test seeds.
	dataSeed, err := syzFS.ReadFile("test/seed1.txt")
	require.NoError(t, err)
	require.Equal(t, "seed data", string(dataSeed))

	// 3. Subsystem skills.
	dataSkill, err := syzFS.ReadFile("skills/kvm.md")
	require.NoError(t, err)
	require.Contains(t, string(dataSkill), "KVM Body")

	dataSkillDirect, err := syzFS.ReadFile("docs/linux/syzlang/skills/kvm.md")
	require.NoError(t, err)
	require.Equal(t, dataSkill, dataSkillDirect)

	// 4. Executor headers.
	dataExec, err := syzFS.ReadFile("executor/common.h")
	require.NoError(t, err)
	require.Equal(t, "common header", string(dataExec))

	// 5. Docs.
	dataDoc, err := syzFS.ReadFile("docs/guide.md")
	require.NoError(t, err)
	require.Equal(t, "guide doc", string(dataDoc))

	// 6. Directory listings.
	entries, err := syzFS.ReadDir(".")
	require.NoError(t, err)
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	require.Contains(t, names, "sys.txt")
	require.Contains(t, names, "sys.txt.const")
	require.Contains(t, names, "test")

	testEntries, err := syzFS.ReadDir("test")
	require.NoError(t, err)
	require.Len(t, testEntries, 1)
	require.Equal(t, "seed1.txt", testEntries[0].Name())

	skillEntries, err := syzFS.ReadDir("skills")
	require.NoError(t, err)
	require.Len(t, skillEntries, 2)

	// 7. fs.Stat and fs.WalkDir compatibility.
	skillStat, err := fs.Stat(syzFS, "skills")
	require.NoError(t, err)
	require.True(t, skillStat.IsDir())

	testStat, err := fs.Stat(syzFS, "test")
	require.NoError(t, err)
	require.True(t, testStat.IsDir())

	var walked []string
	err = fs.WalkDir(syzFS, "skills", func(path string, d fs.DirEntry, err error) error {
		require.NoError(t, err)
		if !d.IsDir() {
			walked = append(walked, path)
		}
		return nil
	})
	require.NoError(t, err)
	slices.Sort(walked)
	require.Equal(t, []string{"skills/README.md", "skills/kvm.md"}, walked)

	// 8. Non-existent files.
	_, errMissing := syzFS.ReadFile("nonexistent.txt")
	require.Error(t, errMissing)

	_, errMissingSkill := syzFS.ReadFile("skills/nonexistent.md")
	require.Error(t, errMissingSkill)
}

func TestSyzFS_SecurityAndRestrictions(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	sysLinux := filepath.Join(tmpDir, "sys", "linux")
	sysLinuxTest := filepath.Join(sysLinux, "test")
	docsDir := filepath.Join(tmpDir, "docs")
	require.NoError(t, os.MkdirAll(sysLinuxTest, 0755))
	require.NoError(t, os.MkdirAll(docsDir, 0755))

	require.NoError(t, os.WriteFile(filepath.Join(sysLinux, "auto.txt"), []byte("auto"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(sysLinux, "auto.txt.const"), []byte("auto const"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(sysLinuxTest, "auto.txt"), []byte("auto in test"), 0644))

	syzFS := NewSyzFS(tmpDir, "linux")

	disallowedPaths := []struct {
		name string
		path string
	}{
		{name: "disallow auto.txt", path: "auto.txt"},
		{name: "disallow auto.txt.const", path: "auto.txt.const"},
		{name: "disallow auto.txt in subdirectories", path: "test/auto.txt"},
		{name: "disallow parent traversal", path: "../sys.txt"},
		{name: "disallow docs traversal", path: "docs/../passwd.md"},
		{name: "disallow executor traversal", path: "executor/../../etc/passwd"},
		{name: "disallow test traversal", path: "test/../../sys.txt"},
		{name: "disallow absolute path", path: "/etc/passwd"},
	}

	for _, tt := range disallowedPaths {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := syzFS.ReadFile(tt.path)
			require.Error(t, err)
		})
	}
}

func TestCorpusBucketSaveAndRead(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	bucket1Progs := map[string]string{
		"hash1": "syz_open(0x0, 0x0)",
		"hash2": "syz_read(0x0, 0x0)",
	}
	bucket2Progs := map[string]string{
		"hash3": "syz_write(0x0, 0x0)",
	}

	f1, err := SaveCorpusBucket(dir, 0, bucket1Progs)
	require.NoError(t, err)
	require.Equal(t, "bucket_000.json", f1)

	f2, err := SaveCorpusBucket(dir, 1, bucket2Progs)
	require.NoError(t, err)
	require.Equal(t, "bucket_001.json", f2)

	data := CorpusData{
		FunctionMap: map[string][]string{
			"kvm_ioctl": {"hash1", "hash2"},
		},
		SyscallMap: map[string][]string{
			"openat$kvm": {"hash1"},
			"ioctl$KVM":  {"hash2", "hash3"},
		},
		ProgToBucket: map[string]string{
			"hash1": f1,
			"hash2": f1,
			"hash3": f2,
		},
	}

	// Test ProgramsForFunction.
	require.Equal(t, []string{"hash1", "hash2"}, data.ProgramsForFunction("kvm_ioctl"))
	require.Empty(t, data.ProgramsForFunction("unknown_fn"))

	// Test ProgramsForSyscall.
	require.Equal(t, []string{"hash1", "hash2", "hash3"}, data.ProgramsForSyscall("kvm"))
	require.Equal(t, []string{"hash1"}, data.ProgramsForSyscall("openat"))
	require.Empty(t, data.ProgramsForSyscall("nonexistent"))

	// Test ReadPrograms.
	progs, err := data.ReadPrograms(dir, []string{"hash1", "hash3", "nonexistent"})
	require.NoError(t, err)
	require.Len(t, progs, 2)
	require.Equal(t, "syz_open(0x0, 0x0)", progs["hash1"])
	require.Equal(t, "syz_write(0x0, 0x0)", progs["hash3"])
}
