// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzspec

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/require"
)

func syzkallerRepoRoot(t *testing.T) string {
	_, filename, _, ok := runtime.Caller(0)
	require.True(t, ok)
	dir := filepath.Dir(filename)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("repository root with go.mod not found")
		}
		dir = parent
	}
}

func TestListSkills(t *testing.T) {
	tmpDir := t.TempDir()
	skillsDir := filepath.Join(tmpDir, "docs", "linux", "syzlang", "skills")
	require.NoError(t, os.MkdirAll(skillsDir, 0755))
	kvmContent := "---\nname: kvm\ndescription: KVM Virtualization and Guest Constraints (x86/amd64 Focus)\n---\n# KVM"
	require.NoError(t, os.WriteFile(filepath.Join(skillsDir, "kvm.md"), []byte(kvmContent), 0644))

	sysFS := NewSyzFS(tmpDir, targets.Linux)
	skills, err := sysFS.ListSkills()
	require.NoError(t, err)
	require.NotEmpty(t, skills)

	var kvmSkill *SkillInfo
	for i := range skills {
		if skills[i].Name == "kvm" {
			kvmSkill = &skills[i]
			break
		}
	}
	require.NotNil(t, kvmSkill)
	require.Equal(t, "KVM Virtualization and Guest Constraints (x86/amd64 Focus)", kvmSkill.Description)
}

func TestSkillPathResolution(t *testing.T) {
	tmpDir := t.TempDir()
	skillsDir := filepath.Join(tmpDir, "docs", "linux", "syzlang", "skills")
	require.NoError(t, os.MkdirAll(skillsDir, 0755))
	kvmContent := "---\nname: kvm\ndescription: KVM Virtualization\n---\nKVM Virtualization"
	require.NoError(t, os.WriteFile(filepath.Join(skillsDir, "kvm.md"), []byte(kvmContent), 0644))

	sysFS := NewSyzFS(tmpDir, targets.Linux)
	data1, err1 := sysFS.ReadFile("skills/kvm.md")
	require.NoError(t, err1)
	require.Contains(t, string(data1), "KVM Virtualization")

	data2, err2 := sysFS.ReadFile("docs/linux/syzlang/skills/kvm.md")
	require.NoError(t, err2)
	require.Equal(t, data1, data2)

	_, errInvalid := sysFS.ReadFile("skills/../passwd.md")
	require.Error(t, errInvalid)
}

func TestRealSubsystemSkills(t *testing.T) {
	repoRoot := syzkallerRepoRoot(t)
	skillsDir := filepath.Join(repoRoot, "docs", "linux", "syzlang", "skills")
	entries, err := os.ReadDir(skillsDir)
	require.NoError(t, err)
	require.NotEmpty(t, entries)

	sysFS := NewSyzFS(repoRoot, targets.Linux)
	skills, err := sysFS.ListSkills()
	require.NoError(t, err)
	require.NotEmpty(t, skills)

	skillMap := make(map[string]string)
	for _, sk := range skills {
		skillMap[sk.Name] = sk.Description
	}

	skillCount := 0
	for _, ent := range entries {
		if ent.IsDir() || ent.Name() == "README.md" || !strings.HasSuffix(ent.Name(), ".md") {
			continue
		}
		skillCount++
		expectedName := strings.TrimSuffix(ent.Name(), ".md")

		data, err := sysFS.ReadFile("skills/" + ent.Name())
		require.NoError(t, err, "failed to read skill %s via SyzFS", ent.Name())

		name, desc, ok := parseYAMLFrontmatter(data)
		require.True(t, ok, "skill %s must have valid YAML frontmatter", ent.Name())
		require.Equal(t, expectedName, name, "frontmatter name in %s must match filename", ent.Name())
		require.NotEmpty(t, desc, "frontmatter description in %s must not be empty", ent.Name())

		require.Contains(t, skillMap, expectedName, "skill %s should be listed by ListSkills()", ent.Name())
		require.Equal(t, desc, skillMap[expectedName])
	}
	require.GreaterOrEqual(t, skillCount, 5, "expected at least 5 subsystem skills")
}

func TestParseYAMLFrontmatter(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantName string
		wantDesc string
		wantOK   bool
	}{
		{
			name: "valid frontmatter",
			input: `---
name: usb
description: USB Subsystem Constraints
---
# Body text`,
			wantName: "usb",
			wantDesc: "USB Subsystem Constraints",
			wantOK:   true,
		},
		{
			name: "no frontmatter",
			input: `# Just body text
some content`,
			wantName: "",
			wantDesc: "",
			wantOK:   false,
		},
		{
			name:     "empty input",
			input:    "",
			wantName: "",
			wantDesc: "",
			wantOK:   false,
		},
		{
			name: "horizontal rule without frontmatter",
			input: `# Just body text
some content
---
name: fake
description: fake
---
more content`,
			wantName: "",
			wantDesc: "",
			wantOK:   false,
		},
		{
			name: "unclosed frontmatter",
			input: `---
name: usb
description: USB Subsystem Constraints
# Body text`,
			wantName: "",
			wantDesc: "",
			wantOK:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotName, gotDesc, gotOK := parseYAMLFrontmatter([]byte(tt.input))
			require.Equal(t, tt.wantOK, gotOK)
			require.Equal(t, tt.wantName, gotName)
			require.Equal(t, tt.wantDesc, gotDesc)
		})
	}
}
