// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package seedgen

import (
	"bytes"
	"testing"
	"text/template"

	"github.com/google/syzkaller/docs"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/symbolizer"
	"github.com/stretchr/testify/require"
)

func TestParsePC(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "hex with 0x prefix",
			input: "0xffffffff80000000",
			want:  "0xffffffff80000000",
		},
		{
			name:  "hex without 0x prefix",
			input: "ffffffff80000000",
			want:  "0xffffffff80000000",
		},
		{
			name:  "raw uint (decimal string matching 0xffffffff80000000)",
			input: "18446744071562067968",
			want:  "0xffffffff80000000",
		},
		{
			name:  "hex with 0x prefix and spaces",
			input: "  0xffffffff80000000  ",
			want:  "0xffffffff80000000",
		},
		{
			name:  "small decimal uint",
			input: "12345",
			want:  "0x3039",
		},
		{
			name:    "invalid input",
			input:   "not_a_number",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := ParsePCArgs{RawPC: tt.input}
			got, err := parsePCAction(nil, args)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.want, got.PC)
			}
		})
	}
}

func TestResolveLineToPCAction(t *testing.T) {
	// Test missing parameters error.
	_, err := resolveLineToPCAction(nil, ResolveLineToPCArgs{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "both FilePath and LineNumber must be provided")

	// Test invalid line number error.
	_, err = resolveLineToPCAction(nil, ResolveLineToPCArgs{FilePath: "fs/ext4/super.c", LineNumber: 0})
	require.Error(t, err)
	require.Contains(t, err.Error(), "both FilePath and LineNumber must be provided")
}

func TestMatchDwarfFile(t *testing.T) {
	kd := &mgrconfig.KernelDirs{}
	require.True(t, matchDwarfFile("arch/x86/kvm/vmx/sgx.h", "arch/x86/kvm/vmx/sgx.h", kd))
	require.True(t, matchDwarfFile("/build/kernel/arch/x86/kvm/vmx/sgx.h", "arch/x86/kvm/vmx/sgx.h", kd))
	require.False(t, matchDwarfFile("fs/ext4/super.c", "fs/ext4/inode.c", kd))
}

func TestMatchCandidatePCs(t *testing.T) {
	cleanTargetFile := "virt/kvm/kvm_main.c"
	kd := &mgrconfig.KernelDirs{}

	// Mock line table.
	lineTable := []lineEntry{
		{addr: 0x100, line: 5290},
		{addr: 0x110, line: 5289},
		{addr: 0x120, line: 5290},
		{addr: 0x130, line: 5314},
	}

	// Mock PC to Frames.
	pcToFrames := map[uint64][]symbolizer.Frame{
		0x100: { // Failure path.
			{PC: 0x100, File: "virt/kvm/kvm_main.c", Line: 5290},
		},
		0x120: { // Success path.
			{PC: 0x120, File: "virt/kvm/kvm_main.c", Line: 5290},
		},
		0x999: { // Completely unrelated line/file.
			{PC: 0x999, File: "fs/ext4/inode.c", Line: 100},
		},
	}

	// Test case 1: targetLine = 5295.
	// 0x100 interval: next is 0x110 (Line 5289). Range [5290, 5289) -> does not contain 5295.
	// 0x120 interval: next is 0x130 (Line 5314). Range [5290, 5314) -> contains 5295.
	// So only 0x120 should be matched.
	pcs, err := matchCandidatePCs(pcToFrames, lineTable, cleanTargetFile, kd, 5295)
	require.NoError(t, err)
	require.Equal(t, []uint64{0x120}, pcs)

	// Test case 2: Fallback when no interval contains targetLine.
	// targetLine = 5320 (after all line table entries).
	// Both 0x100 and 0x120 have lStart <= 5320.
	// The best (closest preceding) line is 5290.
	// So both should be returned as fallback.
	pcs, err = matchCandidatePCs(pcToFrames, lineTable, cleanTargetFile, kd, 5320)
	require.NoError(t, err)
	require.ElementsMatch(t, []uint64{0x100, 0x120}, pcs)
}

func TestGeneratorAgentPromptRendering(t *testing.T) {
	tmpl, err := template.New("prompt").Parse(GeneratorAgent.Prompt)
	require.NoError(t, err)

	var buf bytes.Buffer
	data := map[string]any{
		"File":                   "arch/x86/kvm/vmx/vmx.c",
		"Line":                   1234,
		"FunctionName":           "vmx_vcpu_run",
		"PC":                     "0xffffffff81001234",
		"FunctionSource":         "void vmx_vcpu_run() { ... }",
		"DescriptionFilesPrompt": "Description files available: dev_kvm.txt, dev_kvm_amd64.txt",
		"DocSyzOS":               docs.SyzOS,
	}

	err = tmpl.Execute(&buf, data)
	require.NoError(t, err)
	rendered := buf.String()

	require.Contains(t, rendered, "Target File: arch/x86/kvm/vmx/vmx.c")
	require.Contains(t, rendered, "Document about SyzOS setup:")
	require.Contains(t, rendered, "SYZOS Technical Documentation")
}
