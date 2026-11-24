// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"errors"
	"fmt"
	"net/mail"
	"testing"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/stretchr/testify/assert"
)

func TestAggregateTestResults(t *testing.T) {
	tests := []struct {
		results []instance.EnvTestResult
		title   string
		err     error
		rawOut  []byte
	}{
		{
			results: []instance.EnvTestResult{{}, {}, {RawOutput: []byte{1, 2, 3}}},
			title:   "",
			err:     nil,
			rawOut:  []byte{1, 2, 3},
		},
		{
			results: []instance.EnvTestResult{
				{Error: &instance.CrashError{Report: &report.Report{Title: "title1"}}},
				{Error: &instance.CrashError{Report: &report.Report{Title: "title2"}}},
				{Error: &instance.CrashError{Report: &report.Report{Title: "title3"}}},
			},
			title: "title1",
			err:   nil,
		},
		{
			results: []instance.EnvTestResult{
				{},
				{Error: &instance.CrashError{Report: &report.Report{Title: "title2"}}},
				{},
			},
			title: "title2",
			err:   nil,
		},
		{
			results: []instance.EnvTestResult{
				{Error: &instance.TestError{Title: "test error1"}},
				{Error: &instance.CrashError{Report: &report.Report{Title: "title2"}}},
				{Error: &instance.TestError{Title: "test error2"}},
			},
			title: "title2",
			err:   nil,
		},
		{
			results: []instance.EnvTestResult{
				{Error: &instance.TestError{Title: "test error1"}},
				{Error: &instance.TestError{Title: "test error2"}},
				{},
			},
			title: "",
			err:   nil,
		},
		{
			results: []instance.EnvTestResult{
				{Error: &instance.TestError{Title: "test error1"}},
				{Error: &instance.TestError{Title: "test error2"}},
				{Error: &instance.TestError{Title: "test error3", Output: []byte("output")}},
			},
			title: "",
			err:   errors.New("test error3\n\noutput"),
		},
		{
			results: []instance.EnvTestResult{
				{Error: errors.New("infra error1")},
				{Error: errors.New("infra error2")},
				{
					Error: &instance.TestError{
						Title: "test error",
						Report: &report.Report{
							Title:  "report title",
							Report: []byte("report body"),
							Output: []byte("output"),
						},
					},
				},
			},
			title: "",
			err:   errors.New("report title\n\nreport body\n\noutput"),
		},
		{
			results: []instance.EnvTestResult{
				{Error: errors.New("infra error1")},
				{Error: errors.New("infra error2")},
				{Error: errors.New("infra error3")},
			},
			title: "",
			err:   errors.New("infra error3"),
		},
		{
			results: []instance.EnvTestResult{
				{Error: &instance.CrashError{Report: &report.Report{Title: "title1"}}},
				{Error: &instance.CrashError{
					Report: &report.Report{
						Title:  "title2",
						Report: []byte("report"),
					}},
					RawOutput: []byte{2, 3, 4},
				},
				{Error: &instance.CrashError{Report: &report.Report{Title: "title3"}}},
			},
			title:  "title2",
			err:    nil,
			rawOut: []byte{2, 3, 4},
		},
	}
	for i, test := range tests {
		rep, err := aggregateTestResults(test.results)
		if fmt.Sprint(err) != fmt.Sprint(test.err) {
			t.Errorf("test #%v: got err: %q, want: %q", i, err, test.err)
		}
		got := ""
		if rep != nil && rep.report != nil {
			got = rep.report.Title
		}
		if got != test.title {
			t.Errorf("test #%v: got title: %q, want: %q", i, got, test.title)
		}
		var gotOutput []byte
		if rep != nil {
			gotOutput = rep.rawOutput
		}
		if !bytes.Equal(test.rawOut, gotOutput) {
			t.Errorf("test #%v: got raw out: %q, want: %q", i, gotOutput, test.rawOut)
		}
	}
}

func TestFillJobDoneCrash(t *testing.T) {
	rep := &report.Report{
		Title:      "KASAN: slab-use-after-free in foo",
		AltTitles:  []string{"alt1"},
		Report:     []byte("report body"),
		GuiltyFile: "net/core/dev.c",
		Recipients: vcs.Recipients{
			{Address: mail.Address{Address: "dev@kernel.org"}, Type: vcs.To},
			{Address: mail.Address{Address: "list@vger.kernel.org"}, Type: vcs.Cc},
		},
		Corrupted:  true,
		Suppressed: true,
	}
	resp := &dashapi.JobDoneReq{}
	fillJobDoneCrash(resp, rep)

	assert.Equal(t, rep.Title, resp.CrashTitle)
	assert.Equal(t, rep.AltTitles, resp.CrashAltTitles)
	assert.Equal(t, rep.Report, resp.CrashReport)
	assert.Equal(t, rep.Recipients.ToDash(), resp.CrashRecipients)
	assert.Equal(t, []string{"net/core/dev.c"}, resp.CrashGuiltyFiles)
	assert.True(t, resp.CrashCorrupted)
	assert.True(t, resp.CrashSuppressed)

	emptyResp := &dashapi.JobDoneReq{}
	fillJobDoneCrash(emptyResp, &report.Report{Title: "BUG: test"})
	assert.Nil(t, emptyResp.CrashGuiltyFiles)
	assert.False(t, emptyResp.CrashCorrupted)
	assert.False(t, emptyResp.CrashSuppressed)
}
