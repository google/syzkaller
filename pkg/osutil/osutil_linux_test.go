// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package osutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseMemAvailable(t *testing.T) {
	tests := []struct {
		name    string
		meminfo string
		want    uint64
		wantErr string
	}{
		{
			name:    "valid",
			meminfo: "MemTotal:       32768000 kB\nMemFree:         1024 kB\nMemAvailable:   16384000 kB\n",
			want:    16384000 << 10,
		},
		{
			name:    "missing",
			meminfo: "MemTotal:       32768000 kB\nMemFree:         1024 kB\n",
			wantErr: "MemAvailable not found",
		},
		{
			name:    "empty_value",
			meminfo: "MemTotal:       32768000 kB\nMemAvailable:\n",
			wantErr: "MemAvailable not found",
		},
		{
			name:    "malformed",
			meminfo: "MemAvailable:   lots kB\n",
			wantErr: "failed to parse MemAvailable",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseMemAvailable(tc.meminfo)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
