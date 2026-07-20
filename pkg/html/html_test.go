// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package html

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFormatRepro(t *testing.T) {
	tests := []struct {
		hasC   bool
		hasSyz bool
		want   string
	}{
		{false, false, ""},
		{false, true, "syz"},
		{true, false, "C"},
		{true, true, "syz, C"},
	}
	for _, tc := range tests {
		got := formatRepro(tc.hasC, tc.hasSyz)
		require.Equal(t, tc.want, got, "formatRepro(%t, %t)", tc.hasC, tc.hasSyz)
	}
}
