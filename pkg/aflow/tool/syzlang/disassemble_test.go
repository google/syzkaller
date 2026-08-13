// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzlang

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/stretchr/testify/require"
)

func TestDisassembleContextValidation(t *testing.T) {
	ctx := aflow.NewTestContext(t)
	state := reproduceState{}

	// No PC provided.
	_, err := disassembleContext(ctx, state, DisassembleContextArgs{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "no PC provided")

	// Invalid hex PC format.
	_, err = disassembleContext(ctx, state, DisassembleContextArgs{PCs: []string{"invalid_hex"}})
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid pc format")

	// Invalid hex PC format in PCs slice.
	_, err = disassembleContext(ctx, state, DisassembleContextArgs{PCs: []string{"0xffffff", "bad_pc"}})
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid pc format")
}

func TestComputeAddressBounds(t *testing.T) {
	tests := []struct {
		name      string
		pc        uint64
		wantStart uint64
		wantStop  uint64
	}{
		{
			name:      "normal",
			pc:        0x1000,
			wantStart: 0xe00,
			wantStop:  0x1200,
		},
		{
			name:      "underflow",
			pc:        0x100,
			wantStart: 0x0,
			wantStop:  0x300,
		},
		{
			name:      "underflow boundary",
			pc:        0x200,
			wantStart: 0x0,
			wantStop:  0x400,
		},
		{
			name:      "overflow",
			pc:        ^uint64(0) - 0x100,
			wantStart: ^uint64(0) - 0x300,
			wantStop:  ^uint64(0),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotStart, gotStop := computeAddressBounds(tt.pc)
			require.Equal(t, tt.wantStart, gotStart)
			require.Equal(t, tt.wantStop, gotStop)
		})
	}
}

func TestDisassembleTargetIdxClosestResolution(t *testing.T) {
	// Build a mock objdump output with 150 lines:
	// addresses from 0x1000 upwards by 4 bytes.
	var lines []string
	for i := range 150 {
		addr := uint64(0x1000 + i*4)
		lines = append(lines, fmt.Sprintf("%x:\tnop", addr))
	}
	out := strings.Join(lines, "\n")

	// Target PC is 0x1185 (0x1184 + 1), which is not an exact instruction address.
	// The closest instruction address < 0x1185 is 0x1184 (line index 97).
	// With the snippet centered around line 97 (+/- 50 lines, i.e. lines 47..147),
	// lines near line 0 (0x1000:) should NOT be included,
	// and lines near line 97 (0x1184:) MUST be included.
	pc := uint64(0x1185)
	snippet := formatDisassemblySnippet(out, []uint64{pc})

	require.Contains(t, snippet, "1184:\tnop", "snippet should contain the closest preceding instruction")
	require.NotContains(t, snippet, "1000:\tnop", "snippet should NOT be centered around the first line")
}

func TestDisassembleSnippetExactMatchAndCandidates(t *testing.T) {
	lines := []string{
		"; source line 1",
		"1000:\tmov %rax, %rbx",
		"1004:\tadd $1, %rax",
		"1008:\tret",
	}
	out := strings.Join(lines, "\n")

	// Exact match with candidates.
	snippet := formatDisassemblySnippet(out, []uint64{0x1004, 0x1008})
	require.Contains(t, snippet, "1004:\tadd $1, %rax  <-- TARGET PC")
	require.Contains(t, snippet, "1008:\tret  <-- CANDIDATE TARGET PC")
	require.Contains(t, snippet, "Candidate Target PCs: 0x1004, 0x1008")
	require.NotContains(t, snippet, "WARNING: Missing debug symbols")
}

func TestDisassembleSnippetEmptyPCs(t *testing.T) {
	out := "1000:\tnop"
	snippet := formatDisassemblySnippet(out, nil)
	require.Equal(t, out, snippet)

	_, err := doDisassembleContext(nil, "", "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "no target PC provided")
}

func TestDisassembleSnippetMissingDebugSymbols(t *testing.T) {
	lines := []string{
		"1000:\tmov %rax, %rbx",
		"1004:\tret",
	}
	out := strings.Join(lines, "\n")
	snippet := formatDisassemblySnippet(out, []uint64{0x1000})
	require.Contains(t, snippet, "WARNING: Missing debug symbols")
}
