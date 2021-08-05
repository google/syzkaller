// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
package main

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func dummyStats() *Stats {
	return &Stats{
		TotalProgs:       24,
		TotalMismatches:  10,
		FlakyProgs:       4,
		MismatchingProgs: 6,
		Calls: map[string]*CallStats{
			"foo": {"foo", 2, 8, map[ReturnState]bool{
				returnState(1, 7): true,
				returnState(3, 7): true}},
			"bar": {"bar", 5, 6, map[ReturnState]bool{
				crashedReturnState(): true,
				returnState(10, 7):   true,
				returnState(22, 7):   true}},
			"tar": {"tar", 3, 4, map[ReturnState]bool{
				returnState(31, 7): true,
				returnState(17, 7): true,
				returnState(5, 7):  true}},
			"biz": {"biz", 0, 2, map[ReturnState]bool{}},
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
				"\t↳ mismatches of foo / total number of mismatches: 2 / 10 (20.00 %)\n" +
				"\t↳ 2 distinct states identified: " +
				"[\"Flags: 7, Errno: 1 (operation not permitted)\" \"Flags: 7, Errno: 3 (no such process)\"]\n",
		},
	}

	for _, test := range tests {
		s := dummyStats()
		t.Run(test.name, func(t *testing.T) {
			got, want := s.ReportCallStats(test.call), test.report
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("s.ReportCallStats mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestReportGlobalStats(t *testing.T) {
	s := dummyStats()
	out := bytes.Buffer{}
	s.ReportGlobalStats(&out, float64(10))
	got, want := out.String(),
		"total number of mismatches / total number of calls "+
			"executed: 10 / 20 (50.00 %)\n\n"+
			"programs / minute: 2.40\n\n"+
			"true mismatching programs: 6 / total number of programs: 24 (25.00 %)\n"+
			"flaky programs: 4 / total number of programs: 24 (16.67 %)\n\n"+
			"statistics for bar:\n"+
			"\t↳ mismatches of bar / occurrences of bar: 5 / 6 (83.33 %)\n"+
			"\t↳ mismatches of bar / total number of mismatches: 5 / 10 (50.00 %)\n"+
			"\t↳ 3 distinct states identified: "+
			"[\"Crashed\" \"Flags: 7, Errno: 10 (no child processes)\" "+
			"\"Flags: 7, Errno: 22 (invalid argument)\"]\n\n"+
			"statistics for tar:\n"+
			"\t↳ mismatches of tar / occurrences of tar: 3 / 4 (75.00 %)\n"+
			"\t↳ mismatches of tar / total number of mismatches: 3 / 10 (30.00 %)\n"+
			"\t↳ 3 distinct states identified: "+
			"[\"Flags: 7, Errno: 17 (file exists)\" "+
			"\"Flags: 7, Errno: 31 (too many links)\" "+
			"\"Flags: 7, Errno: 5 (input/output error)\"]\n\n"+
			"statistics for foo:\n"+
			"\t↳ mismatches of foo / occurrences of foo: 2 / 8 (25.00 %)\n"+
			"\t↳ mismatches of foo / total number of mismatches: 2 / 10 (20.00 %)\n"+
			"\t↳ 2 distinct states identified: "+
			"[\"Flags: 7, Errno: 1 (operation not permitted)\" \"Flags: 7, Errno: 3 (no such process)\"]\n\n"

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("s.ReportGlobalStats mismatch (-want +got):\n%s", diff)
	}
}
