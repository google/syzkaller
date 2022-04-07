// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"errors"
	"fmt"
	"testing"

	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/report"
)

func TestAggregateTestResults(t *testing.T) {
	tests := []struct {
		results []error
		title   string
		err     error
	}{
		{
			results: []error{nil, nil, nil},
			title:   "",
			err:     nil,
		},
		{
			results: []error{
				&instance.CrashError{Report: &report.Report{Title: "title1"}},
				&instance.CrashError{Report: &report.Report{Title: "title2"}},
				&instance.CrashError{Report: &report.Report{Title: "title3"}},
			},
			title: "title1",
			err:   nil,
		},
		{
			results: []error{
				nil,
				&instance.CrashError{Report: &report.Report{Title: "title2"}},
				nil,
			},
			title: "title2",
			err:   nil,
		},
		{
			results: []error{
				&instance.TestError{Title: "test error1"},
				&instance.CrashError{Report: &report.Report{Title: "title2"}},
				&instance.TestError{Title: "test error2"},
			},
			title: "title2",
			err:   nil,
		},
		{
			results: []error{
				&instance.TestError{Title: "test error1"},
				&instance.TestError{Title: "test error2"},
				nil,
			},
			title: "",
			err:   nil,
		},
		{
			results: []error{
				&instance.TestError{Title: "test error1"},
				&instance.TestError{Title: "test error2"},
				&instance.TestError{Title: "test error3", Output: []byte("output")},
			},
			title: "",
			err:   errors.New("test error3\n\noutput"),
		},
		{
			results: []error{
				errors.New("infra error1"),
				errors.New("infra error2"),
				&instance.TestError{Title: "test error", Report: &report.Report{
					Title:  "report title",
					Report: []byte("report body"),
					Output: []byte("output"),
				}},
			},
			title: "",
			err:   errors.New("report title\n\nreport body\n\noutput"),
		},
		{
			results: []error{
				errors.New("infra error1"),
				errors.New("infra error2"),
				errors.New("infra error3"),
			},
			title: "",
			err:   errors.New("infra error3"),
		},
		{
			results: []error{
				&instance.CrashError{Report: &report.Report{Title: "title1"}},
				&instance.CrashError{Report: &report.Report{
					Title:  "title2",
					Report: []byte("report"),
				}},
				&instance.CrashError{Report: &report.Report{Title: "title3"}},
			},
			title: "title2",
			err:   nil,
		},
	}
	for i, test := range tests {
		rep, err := aggregateTestResults(test.results)
		if fmt.Sprint(err) != fmt.Sprint(test.err) {
			t.Errorf("test #%v: got err: %q, want: %q", i, err, test.err)
		}
		got := ""
		if rep != nil {
			got = rep.Title
		}
		if got != test.title {
			t.Errorf("test #%v: got title: %q, want: %q", i, got, test.title)
		}
	}
}
