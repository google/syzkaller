// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package stats

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func getTestStats() *Stats {
	return &Stats{
		TotalMismatches: 11,
		Calls: map[string]*CallStats{
			"foo": {"foo", 2, 8},
			"bar": {"bar", 5, 6},
			"tar": {"tar", 3, 4},
			"biz": {"biz", 0, 2},
		},
	}
}

func TestReportCallStats(t *testing.T) {
	tests := []struct {
		name, call, report string
	}{
		{
			name:   "report for unsupported call",
			call:   "read",
			report: "",
		},
		{
			name: "report for supported call",
			call: "foo",
			report: "statistics for foo:\n" +
				"\t↳ mismatches of foo / occurrences of foo: 2 / 8 (25.00 %)\n" +
				"\t↳ mismatches of foo / total number of mismatches: 2 / 11 (18.18 %)\n",
		},
	}

	for _, test := range tests {
		s := getTestStats()
		t.Run(test.name, func(t *testing.T) {
			got, want := s.ReportCallStats(test.call), test.report
			if diff := cmp.Diff(got, want); diff != "" {
				t.Errorf("s.ReportCallStats mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestReportGlobalStats(t *testing.T) {
	s := getTestStats()
	out := bytes.Buffer{}
	s.ReportGlobalStats(&out)
	got, want := out.String(),
		"total number of mismatches / total number of calls "+
			"executed: 11 / 20 (55.00 %)\n\n"+
			"statistics for bar:\n"+
			"\t↳ mismatches of bar / occurrences of bar: 5 / 6 (83.33 %)\n"+
			"\t↳ mismatches of bar / total number of mismatches: 5 / 11 (45.45 %)\n\n"+
			"statistics for tar:\n"+
			"\t↳ mismatches of tar / occurrences of tar: 3 / 4 (75.00 %)\n"+
			"\t↳ mismatches of tar / total number of mismatches: 3 / 11 (27.27 %)\n\n"+
			"statistics for foo:\n"+
			"\t↳ mismatches of foo / occurrences of foo: 2 / 8 (25.00 %)\n"+
			"\t↳ mismatches of foo / total number of mismatches: 2 / 11 (18.18 %)\n\n"

	if diff := cmp.Diff(got, want); diff != "" {
		t.Errorf("s.ReportGlobalStats mismatch (-want +got):\n%s", diff)
	}
}
