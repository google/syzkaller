// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package crash

import (
	"testing"

	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/symbolizer"
	"github.com/google/syzkaller/sys/targets"
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
			args := ReproduceArgs{
				TargetArch: "amd64",
			}
			res, err := aggregateTestResults(tc.results, crashReporter, args)
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

type mockSymbolizer struct {
	recordedPCs []uint64
}

func (m *mockSymbolizer) Symbolize(bin string, pcs ...uint64) ([]symbolizer.Frame, error) {
	m.recordedPCs = append(m.recordedPCs, pcs...)
	var frames []symbolizer.Frame
	for _, pc := range pcs {
		frames = append(frames, symbolizer.Frame{
			PC:   pc,
			Func: "mockFunc",
			File: "mock_file.c",
			Line: 1,
		})
	}
	return frames, nil
}

func (m *mockSymbolizer) Close() {}

func TestSymbolize(t *testing.T) {
	oldMakeSymbolizer := makeSymbolizer
	defer func() { makeSymbolizer = oldMakeSymbolizer }()

	mock := &mockSymbolizer{}
	makeSymbolizer = func(target *targets.Target) symbolizer.Symbolizer {
		return mock
	}

	args := ReproduceArgs{
		TargetArch: "amd64",
		Type:       "qemu",
	}
	// amd64 instruction length is 5.
	// So 0x1005 should be shifted to 0x1000.
	coverage := [][]uint64{{0x1005, 0x2005}}

	res, err := symbolize(args, coverage)
	require.NoError(t, err)

	require.Len(t, mock.recordedPCs, 2)
	require.Contains(t, mock.recordedPCs, uint64(0x1000))
	require.Contains(t, mock.recordedPCs, uint64(0x2000))

	require.Len(t, res, 1)
	require.Len(t, res[0], 2)
	require.Equal(t, uint64(0x1000), res[0][0].PC)
	require.Equal(t, uint64(0x2000), res[0][1].PC)
}
