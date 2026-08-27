// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package seedgen

import (
	"bytes"
	"testing"
	"text/template"

	"github.com/google/syzkaller/docs"
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
				require.Equal(t, []string{tt.want}, got.PCs)
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

	// Test unsupported target arch error.
	_, err = resolveLineToPCAction(nil, ResolveLineToPCArgs{
		FilePath:   "fs/ext4/super.c",
		LineNumber: 100,
		TargetArch: "unsupported_arch",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported target linux/unsupported_arch")
}

func TestGeneratorAgentPromptRendering(t *testing.T) {
	tmpl, err := template.New("prompt").Parse(GeneratorAgent.Prompt)
	require.NoError(t, err)

	var buf bytes.Buffer
	data := map[string]any{
		"File":                   "arch/x86/kvm/vmx/vmx.c",
		"Line":                   1234,
		"FunctionName":           "vmx_vcpu_run",
		"PCs":                    []string{"0xffffffff81001234"},
		"FunctionSource":         "void vmx_vcpu_run() { ... }",
		"DescriptionFilesPrompt": "Description files available: dev_kvm.txt, dev_kvm_amd64.txt",
		"DocSyzOS":               docs.SyzOS,
		"EnvironmentPrompt":      "Target OS: linux\nTarget Arch: amd64\nVM Type: qemu\n",
	}

	err = tmpl.Execute(&buf, data)
	require.NoError(t, err)
	rendered := buf.String()

	require.Contains(t, rendered, "Target File: arch/x86/kvm/vmx/vmx.c")
	require.Contains(t, rendered, "Target PCs: 0xffffffff81001234")
	require.Contains(t, rendered, "Target Environment:")
	require.Contains(t, rendered, "Target OS: linux")
	require.Contains(t, rendered, "Target Arch: amd64")
	require.Contains(t, rendered, "VM Type: qemu")
	require.Contains(t, rendered, "Document about SyzOS setup:")
	require.Contains(t, rendered, "SYZOS Technical Documentation")
}

func TestVerifyPCAndLoopStateAction(t *testing.T) {
	tests := []struct {
		name string
		args VerifyPCAndLoopStateArgs
		want VerifyPCAndLoopStateResult
	}{
		{
			name: "judge stopped preserves last failed id and sets summary",
			args: VerifyPCAndLoopStateArgs{
				JudgeStopped:                true,
				FailedHistorySummary:        "looping in tool calls",
				LastFailedExecutionCachedID: "prev-cached-id",
			},
			want: VerifyPCAndLoopStateResult{
				ContinueLoop:                "yes",
				PCReached:                   false,
				LastFailedHistorySummary:    "looping in tool calls",
				LastFailedExecutionCachedID: "prev-cached-id",
			},
		},
		{
			name: "generator give up terminates loop",
			args: VerifyPCAndLoopStateArgs{
				GeneratorGiveUp:      true,
				FailedHistorySummary: "stale summary",
			},
			want: VerifyPCAndLoopStateResult{
				ContinueLoop: "",
				PCReached:    false,
			},
		},
		{
			name: "execution failed to reach pc updates last failed id",
			args: VerifyPCAndLoopStateArgs{
				ExecutionCachedID:    "cached-attempt-1",
				PCs:                  []string{"0x1000"},
				FailedHistorySummary: "summary",
			},
			want: VerifyPCAndLoopStateResult{
				ContinueLoop:                "yes",
				PCReached:                   false,
				LastFailedExecutionCachedID: "cached-attempt-1",
				LastFailedHistorySummary:    "summary",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := verifyPCAndLoopStateAction(nil, tt.args)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}
