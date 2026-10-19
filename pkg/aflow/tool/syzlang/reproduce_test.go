// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzlang

import (
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/crash"
	"github.com/stretchr/testify/assert"
)

func TestReproduce(t *testing.T) {
	tests := []struct {
		name      string
		syzProg   string
		wantError string
	}{
		{
			name:      "empty program",
			syzProg:   "",
			wantError: "syz program cannot be empty",
		},
		{
			name:      "valid program",
			syzProg:   `getrlimit(0x0, 0x0)`,
			wantError: "",
		},
		{
			name: "invalid syntax",
			syzProg: `r0 = openat(0xffffffffffffff9c
ioctl(r0, 0x4c80, 0x0)`,
			wantError: "unexpected eof",
		},
		{
			name:      "unknown syscall",
			syzProg:   `foo(0x1, 0x2)`,
			wantError: "unknown syscall foo",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			state := reproduceState{Target: crash.Target{TargetOS: "linux", TargetArch: "amd64"}}
			_, err := reproduce(&aflow.Context{}, state, ReproduceArgs{
				ReproSyz: tc.syzProg,
			})
			if tc.wantError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestReproduceTargetConfigVMArch(t *testing.T) {
	state := reproduceState{Target: crash.Target{TargetArch: "386", TargetVMArch: "amd64"}}
	cfg := state.targetConfig("none")
	assert.Equal(t, "386", cfg.TargetArch)
	assert.Equal(t, "amd64", cfg.VMArch())
	assert.Equal(t, "none", cfg.Sandbox)
}
