// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"slices"
	"testing"

	"github.com/google/syzkaller/pkg/report/crash"
)

const testHangTitle = "BUG: soft lockup in some function"
const testKASANInvalidFreeTitle = "KASAN: invalid-free"

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
			title:    testHangTitle,
			expected: 1, // lowest priority we can think about
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := TitlesToImpact(test.title)
			if got != test.expected {
				t.Errorf("report.TitlesToImpact(%q) = %d, want %d", test.title, got, test.expected)
			}
		})
	}
}

func TestTitlesToImpact2(t *testing.T) {
	got := TitlesToImpact(testHangTitle, testKASANInvalidFreeTitle)
	if got == 1 { // lowest priority we can think about (crash.Hang)
		t.Errorf("report.TitlesToImpact(%q, %q) = %d, want %d",
			testHangTitle, testKASANInvalidFreeTitle,
			got, len(impactOrder)-slices.Index(impactOrder, crash.KASANInvalidFree))
	}
}
