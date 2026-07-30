// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzspec

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/require"
)

func TestListSkills(t *testing.T) {
	tmpDir := t.TempDir()
	skillsDir := filepath.Join(tmpDir, "docs", "linux", "skills")
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

func TestResolveSkillPath(t *testing.T) {
	tmpDir := t.TempDir()
	skillsDir := filepath.Join(tmpDir, "docs", "linux", "skills")
	require.NoError(t, os.MkdirAll(skillsDir, 0755))
	kvmContent := "---\nname: kvm\ndescription: KVM Virtualization\n---\nKVM Virtualization"
	require.NoError(t, os.WriteFile(filepath.Join(skillsDir, "kvm.md"), []byte(kvmContent), 0644))

	sysFS := NewSyzFS(tmpDir, targets.Linux)
	data1, err1 := sysFS.ReadFile("skills/kvm.md")
	require.NoError(t, err1)
	require.Contains(t, string(data1), "KVM Virtualization")

	data2, err2 := sysFS.ReadFile("linux/skills/kvm.md")
	require.NoError(t, err2)
	require.Equal(t, data1, data2)

	data3, err3 := sysFS.ReadFile("kvm.md")
	require.NoError(t, err3)
	require.Equal(t, data1, data3)

	_, errInvalid := sysFS.ReadFile("skills/../passwd.md")
	require.Error(t, errInvalid)
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
