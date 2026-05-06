// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzlang

import (
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
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
			_, err := reproduce(&aflow.Context{}, reproduceState{}, ReproduceArgs{
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
