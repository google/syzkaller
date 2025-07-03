// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"testing"
)

func TestImpactScore(t *testing.T) {
	tests := []struct {
		name     string
		title    string
		expected int
	}{
		{
			name:     "unknown",
			title:    "KGSAN: ",
			expected: -1,
		},
		{
			name:     "unknown KASAN",
			title:    "KASAN: unknown",
			expected: -1,
		},
		{
			name:     "known Hang",
			title:    "BUG: soft lockup in some function",
			expected: 2,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := TitleToImpact(test.title)
			if got != test.expected {
				t.Errorf("report.TitleToImpact(%q) = %d, want %d", test.title, got, test.expected)
			}
		})
	}
}
