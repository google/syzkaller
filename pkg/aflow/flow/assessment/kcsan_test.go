// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package assessment

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateKCSANOutputs(t *testing.T) {
	tests := []struct {
		name    string
		in      kcsanOutputs
		want    kcsanOutputs
		wantErr bool
	}{
		{
			name: "benign empty",
			in:   kcsanOutputs{Benign: true},
			want: kcsanOutputs{Benign: true},
		},
		{
			name: "benign clears FailureDetectableBy",
			in:   kcsanOutputs{Benign: true, FailureDetectableBy: "kasan"},
			want: kcsanOutputs{Benign: true},
		},
		{
			name: "harmful kasan",
			in:   kcsanOutputs{Benign: false, FailureDetectableBy: "kasan"},
			want: kcsanOutputs{Benign: false, FailureDetectableBy: "kasan"},
		},
		{
			name: "harmful kmsan",
			in:   kcsanOutputs{Benign: false, FailureDetectableBy: "kmsan"},
			want: kcsanOutputs{Benign: false, FailureDetectableBy: "kmsan"},
		},
		{
			name: "harmful any",
			in:   kcsanOutputs{Benign: false, FailureDetectableBy: "any"},
			want: kcsanOutputs{Benign: false, FailureDetectableBy: "any"},
		},
		{
			name: "harmful user",
			in:   kcsanOutputs{Benign: false, FailureDetectableBy: "user"},
			want: kcsanOutputs{Benign: false, FailureDetectableBy: "user"},
		},
		{
			name: "harmful none",
			in:   kcsanOutputs{Benign: false, FailureDetectableBy: "none"},
			want: kcsanOutputs{Benign: false, FailureDetectableBy: "none"},
		},
		{
			name:    "harmful missing",
			in:      kcsanOutputs{Benign: false},
			wantErr: true,
		},
		{
			name:    "harmful invalid",
			in:      kcsanOutputs{Benign: false, FailureDetectableBy: "kcsan"},
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := validateKCSANOutputs(nil, struct{}{}, tc.in)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}
