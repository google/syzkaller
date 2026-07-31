// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package backend

import (
	"testing"

	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/require"
)

func TestPreviousNextInstructionPC(t *testing.T) {
	for os, arches := range targets.List {
		if os == targets.TestOS {
			continue
		}
		for _, target := range arches {
			target := targets.Get(target.OS, target.Arch)
			t.Run(target.OS+"-"+target.Arch, func(t *testing.T) {
				const startPC = uint64(0x80000104)

				prev := PreviousInstructionPC(target, "", startPC)
				next := NextInstructionPC(target, "", prev)
				require.Equal(t, startPC, next)

				// Test gVisor VM mode which should leave PCs unchanged.
				require.Equal(t, startPC, PreviousInstructionPC(target, targets.GVisor, startPC))
				require.Equal(t, startPC, NextInstructionPC(target, targets.GVisor, startPC))
			})
		}
	}
}

func TestARMInstructionPC(t *testing.T) {
	target := targets.Get(targets.Linux, targets.ARM)
	require.NotNil(t, target)

	const pc = uint64(0x80000104)
	prev := PreviousInstructionPC(target, "", pc)
	require.Equal(t, uint64(0x80000100), prev)
	next := NextInstructionPC(target, "", prev)
	require.Equal(t, pc, next)

	// Check an unaligned PC.
	const oddPC = uint64(0x80000105)
	require.Equal(t, uint64(0x80000101), PreviousInstructionPC(target, "", oddPC))
	require.Equal(t, oddPC, NextInstructionPC(target, "", PreviousInstructionPC(target, "", oddPC)))
}
