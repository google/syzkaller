// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package crash

import (
	"testing"

	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/report"
	"github.com/stretchr/testify/require"
)

func TestAggregateTestResults(t *testing.T) {
	// Dummy crash reporter for tests.
	crashReporter, err := report.NewReporter(&mgrconfig.Config{
		Derived: mgrconfig.Derived{
			TargetOS:   "linux",
			TargetArch: "amd64",
		},
	})
	require.NoError(t, err)

	tests := []struct {
		name              string
		results           []instance.EnvTestResult
		expectedReport    *report.Report
		expectedBootError bool
	}{
		{
			name: "single_crash",
			results: []instance.EnvTestResult{
				{Error: &instance.CrashError{Report: &report.Report{Title: "bug A", Report: []byte("stack A")}}},
			},
			expectedReport: &report.Report{Title: "bug A", Report: []byte("stack A")},
		},
		{
			name: "multiple_crashes_same_title",
			results: []instance.EnvTestResult{
				{Error: &instance.CrashError{Report: &report.Report{Title: "bug A", Report: []byte("stack A1")}}},
				{Error: &instance.CrashError{Report: &report.Report{Title: "bug A", Report: []byte("stack A2")}}},
				{Error: &instance.CrashError{Report: &report.Report{Title: "bug A", Report: []byte("stack A3")}}},
			},
			expectedReport: &report.Report{Title: "bug A", Report: []byte("stack A1")},
		},
		{
			name: "flaky_crash",
			results: []instance.EnvTestResult{
				{Error: nil},
				{Error: &instance.CrashError{Report: &report.Report{Title: "bug A", Report: []byte("stack A")}}},
				{Error: nil},
			},
			expectedReport: &report.Report{Title: "bug A", Report: []byte("stack A")},
		},
		{
			name: "multiple_crash_types_majority_wins",
			results: []instance.EnvTestResult{
				{Error: &instance.CrashError{Report: &report.Report{Title: "bug B", Report: []byte("stack B")}}},
				{Error: &instance.CrashError{Report: &report.Report{Title: "bug A", Report: []byte("stack A")}}},
				{Error: nil},
				{Error: &instance.CrashError{Report: &report.Report{Title: "bug B", Report: []byte("stack B")}}},
			},
			expectedReport: &report.Report{Title: "bug B", Report: []byte("stack B")},
		},
		{
			name: "no_crashes_but_boot_errors",
			results: []instance.EnvTestResult{
				{Error: &instance.TestError{Boot: true, Title: "boot error 1"}},
				{Error: &instance.TestError{Boot: true, Title: "boot error 2"}},
				{Error: nil},
			},
			expectedBootError: true,
		},
		{
			name: "all_ok",
			results: []instance.EnvTestResult{
				{Error: nil},
				{Error: nil},
				{Error: nil},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, err := aggregateTestResults(tc.results, crashReporter, "", "amd64")
			require.NoError(t, err)

			if tc.expectedReport != nil {
				require.NotNil(t, res.Report)
				require.Equal(t, tc.expectedReport.Title, res.Report.Title)
				if len(tc.expectedReport.Report) > 0 {
					require.Contains(t, string(res.Report.Report), string(tc.expectedReport.Report))
				}
			} else if tc.expectedBootError {
				require.NotEmpty(t, res.BootError)
				require.Nil(t, res.Report)
			} else {
				require.Nil(t, res.Report)
				require.Empty(t, res.BootError)
			}
		})
	}
}
