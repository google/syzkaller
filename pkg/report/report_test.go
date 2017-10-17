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

func testParse(t *testing.T, os string, tests map[string]string) {
	reporter, err := NewReporter(os, "", "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for log, crash := range tests {
		if strings.Index(log, "\r\n") != -1 {
			continue
		}
		tests[strings.Replace(log, "\n", "\r\n", -1)] = crash
	}
	for log, crash := range tests {
		containsCrash := reporter.ContainsCrash([]byte(log))
		expectCrash := (crash != "")
		if expectCrash && !containsCrash {
			t.Fatalf("ContainsCrash did not find crash")
		}
		if !expectCrash && containsCrash {
			t.Fatalf("ContainsCrash found unexpected crash")
		}
		desc, _, _, _ := reporter.Parse([]byte(log))
		if desc == "" && crash != "" {
			t.Fatalf("did not find crash message '%v' in:\n%v", crash, log)
		}
		if desc != "" && crash == "" {
			t.Fatalf("found bogus crash message '%v' in:\n%v", desc, log)
		}
		if desc != crash {
			t.Fatalf("extracted bad crash message:\n%+q\nwant:\n%+q", desc, crash)
		}
	}
}
