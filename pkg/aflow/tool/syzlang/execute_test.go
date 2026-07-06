// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzlang

import (
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/stretchr/testify/require"
)

func TestExecuteSeed_DeserializeErrors(t *testing.T) {
	tests := []struct {
		name    string
		program string
	}{
		{
			name:    "double quotes",
			program: `openat(0xffffffffffffff9c, "hello", 0x0, 0x0)`,
		},
		{
			name: "multi-line statement",
			program: `openat(0xffffffffffffff9c,
0x0, 0x0)`,
		},
		{
			name:    "inline comment",
			program: `openat(0xffffffffffffff9c, # inline comment`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := &aflow.Context{}
			state := reproduceState{
				TargetOS:   "linux",
				TargetArch: "amd64",
			}
			args := ExecuteSeedArgs{
				ReproSyz: tc.program,
			}
			_, err := executeSeed(ctx, state, args)
			require.Error(t, err)
			require.Contains(t, err.Error(), deserializationErrorHelp)
		})
	}
}
