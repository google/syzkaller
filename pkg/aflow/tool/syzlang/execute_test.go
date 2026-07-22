// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzlang

import (
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/crash"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/prog"
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

func TestFormatCallErrors(t *testing.T) {
	calls := []*prog.Call{
		{Meta: &prog.Syscall{Name: "syz_usb_connect"}},
		{Meta: &prog.Syscall{Name: "openat"}},
		{Meta: &prog.Syscall{Name: "read"}},
	}

	execFinished := flatrpc.CallFlagExecuted | flatrpc.CallFlagFinished
	execStarted := flatrpc.CallFlagExecuted
	unexec := flatrpc.CallFlag(0)

	tests := []struct {
		name           string
		baseCallsCount int
		callErrors     []crash.CallError
		want           []CallError
		wantErr        string
	}{
		{
			name:           "base call failure",
			baseCallsCount: 1,
			callErrors: []crash.CallError{
				{Flags: execFinished, Errno: 22},
				{Flags: execFinished, Errno: 0},
				{Flags: execFinished, Errno: 0},
			},
			wantErr: "base test seed failed at syscall index 0",
		},
		{
			name:           "normal errno formatting",
			baseCallsCount: 1,
			callErrors: []crash.CallError{
				{Flags: execFinished, Errno: 0},
				{Flags: execFinished, Errno: 22},
				{Flags: execFinished, Errno: 0},
			},
			want: []CallError{
				{Index: 0, CallName: "openat", Errno: 22, Error: "invalid argument"},
			},
		},
		{
			name:           "unexecuted and timed out calls",
			baseCallsCount: 0,
			callErrors: []crash.CallError{
				{Flags: execStarted, Errno: 998},
				{Flags: unexec, Errno: 998},
			},
			want: []CallError{
				{Index: 0, CallName: "syz_usb_connect", Errno: 998, Error: "call execution timed out or hung"},
				{Index: 1, CallName: "openat", Errno: 998, Error: "call unexecuted (executor halted on an earlier call)"},
			},
		},
		{
			name:           "mix of finished errno, timed out, and unexecuted",
			baseCallsCount: 0,
			callErrors: []crash.CallError{
				{Flags: execFinished, Errno: 22},
				{Flags: execStarted, Errno: 998},
				{Flags: unexec, Errno: 998},
			},
			want: []CallError{
				{Index: 0, CallName: "syz_usb_connect", Errno: 22, Error: "invalid argument"},
				{Index: 1, CallName: "openat", Errno: 998, Error: "call execution timed out or hung"},
				{Index: 2, CallName: "read", Errno: 998, Error: "call unexecuted (executor halted on an earlier call)"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := formatCallErrors(tt.callErrors, tt.baseCallsCount, calls)
			if tt.wantErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}
