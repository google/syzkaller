// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzlang

import (
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/stretchr/testify/assert"
)

func TestFormat(t *testing.T) {
	tests := []struct {
		name          string
		syzProg       string
		wantError     bool
		wantCanonical string
	}{
		{
			name:          "valid program",
			syzProg:       `getrlimit   (  0x0,0x0   )`,
			wantError:     false,
			wantCanonical: "getrlimit(0x0, 0x0)\n",
		},
		{
			name: "invalid syntax",
			syzProg: `r0 = openat(0xffffffffffffff9c
ioctl(r0, 0x4c80, 0x0)`,
			wantError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := format(&aflow.Context{}, FormatArgs{
				ReproSyz: tc.syzProg,
			})
			if tc.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.wantCanonical, got.ReproSyz)
			}
		})
	}
}
