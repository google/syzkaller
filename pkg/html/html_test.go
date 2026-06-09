// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package html

import (
	"testing"

	"github.com/google/syzkaller/dashboard/dashapi"
)

func TestFormatReproLevel(t *testing.T) {
	tests := []struct {
		level dashapi.ReproLevel
		want  string
	}{
		{dashapi.ReproLevelNone, ""},
		{dashapi.ReproLevelSyz, "syz"},
		{dashapi.ReproLevelC, "syz, C"},
		{dashapi.ReproLevelCOnly, "C"},
	}

	for _, test := range tests {
		got := formatReproLevel(test.level)
		if got != test.want {
			t.Errorf("formatReproLevel(%v) = %q; want %q", test.level, got, test.want)
		}
	}
}
