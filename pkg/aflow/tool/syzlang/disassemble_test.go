// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzlang

import (
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
	_, err = disassembleContext(ctx, state, DisassembleContextArgs{PC: "invalid_hex"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid pc format")

	// Invalid hex PC format in PCs slice.
	_, err = disassembleContext(ctx, state, DisassembleContextArgs{PCs: []string{"0xffffff", "bad_pc"}})
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid pc format")
}
