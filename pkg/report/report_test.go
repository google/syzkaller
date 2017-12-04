// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"fmt"
	"strings"
	"testing"
)

func TestReplace(t *testing.T) {
	tests := []struct {
		where  string
		start  int
		end    int
		what   string
		result string
	}{
		{"0123456789", 3, 5, "abcdef", "012abcdef56789"},
		{"0123456789", 3, 5, "ab", "012ab56789"},
		{"0123456789", 3, 3, "abcd", "012abcd3456789"},
		{"0123456789", 0, 2, "abcd", "abcd23456789"},
		{"0123456789", 0, 0, "ab", "ab0123456789"},
		{"0123456789", 10, 10, "ab", "0123456789ab"},
		{"0123456789", 8, 10, "ab", "01234567ab"},
		{"0123456789", 5, 5, "", "0123456789"},
		{"0123456789", 3, 8, "", "01289"},
		{"0123456789", 3, 8, "ab", "012ab89"},
		{"0123456789", 0, 5, "a", "a56789"},
		{"0123456789", 5, 10, "ab", "01234ab"},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("%+v", test), func(t *testing.T) {
			result := replace([]byte(test.where), test.start, test.end, []byte(test.what))
			if test.result != string(result) {
				t.Errorf("want '%v', got '%v'", test.result, string(result))
			}
		})
	}
}

type ParseTest struct {
	Log       string
	Desc      string
	Corrupted bool
}

func testParse(t *testing.T, os string, tests []ParseTest) {
	reporter, err := NewReporter(os, "", "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	initialTests := tests[:]
	for _, test := range initialTests {
		if strings.Index(test.Log, "\r\n") != -1 {
			continue
		}
		test.Log = strings.Replace(test.Log, "\n", "\r\n", -1)
		tests = append(tests, test)
	}
	for _, test := range tests {
		rep := reporter.Parse([]byte(test.Log))
		containsCrash := reporter.ContainsCrash([]byte(test.Log))
		expectCrash := (test.Desc != "")
		if expectCrash && !containsCrash {
			t.Fatalf("ContainsCrash did not find crash:\n%v", test.Log)
		}
		if !expectCrash && containsCrash {
			t.Fatalf("ContainsCrash found unexpected crash:\n%v", test.Log)
		}
		if rep != nil && rep.Title == "" {
			t.Fatalf("found crash, but title is empty '%v' in:\n%v", test.Desc, test.Log)
		}
		title, corrupted := "", false
		if rep != nil {
			title = rep.Title
			corrupted = rep.Corrupted
		}
		if title == "" && test.Desc != "" {
			t.Fatalf("did not find crash message '%v' in:\n%v", test.Desc, test.Log)
		}
		if title != "" && test.Desc == "" {
			t.Fatalf("found bogus crash message '%v' in:\n%v", title, test.Log)
		}
		if title != "" && len(rep.Report) == 0 {
			t.Fatalf("found crash message %q but report is empty:\n%v", title, test.Log)
		}
		if title != test.Desc {
			t.Fatalf("extracted bad crash message:\n%+q\nwant:\n%+q", title, test.Desc)
		}
		if corrupted && !test.Corrupted {
			t.Fatalf("incorrectly marked report as corrupted: '%v'\n%v", title, test.Log)
		}
		if !corrupted && test.Corrupted {
			t.Fatalf("failed to mark report as corrupted: '%v'\n%v", title, test.Log)
		}
	}
}
