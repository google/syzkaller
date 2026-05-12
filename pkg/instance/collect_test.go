// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package instance

import (
	"errors"
	"fmt"
	"testing"

	"github.com/google/syzkaller/pkg/report"
	"github.com/stretchr/testify/require"
)

type mockRunner struct {
	responses []EnvTestResult
	idx       int
}

func (m *mockRunner) Test(numVMs int) ([]EnvTestResult, error) {
	var batch []EnvTestResult
	for range numVMs {
		if m.idx >= len(m.responses) {
			return nil, fmt.Errorf("ran out of responses")
		}
		batch = append(batch, m.responses[m.idx])
		m.idx++
	}
	return batch, nil
}

func TestCollectRuns(t *testing.T) {
	tests := []struct {
		name             string
		responses        []EnvTestResult
		opts             CollectRunsOpts
		expectedValid    int
		expectErr        bool
		expectErrMessage string
	}{
		{
			name: "all_successful",
			responses: []EnvTestResult{
				{RawOutput: []byte("1")},
				{RawOutput: []byte("2")},
				{RawOutput: []byte("3")},
			},
			opts: CollectRunsOpts{
				WantValid: 3,
				MaxTotal:  6,
				MaxVMs:    3,
			},
			expectedValid: 3,
		},
		{
			name: "recover_from_infra_errors",
			responses: []EnvTestResult{
				{Error: &TestError{Infra: true}},
				{RawOutput: []byte("1")},
				{Error: errors.New("unknown error treated as infra")},
				{RawOutput: []byte("2")},
				{RawOutput: []byte("3")},
			},
			opts: CollectRunsOpts{
				WantValid: 3,
				MaxTotal:  6,
				MaxVMs:    2,
			},
			expectedValid: 3,
		},
		{
			name: "fail_with_too_many_infra_errors",
			responses: []EnvTestResult{
				{Error: &TestError{Infra: true}},
				{Error: &TestError{Infra: true}},
				{Error: &TestError{Infra: true}},
				{Error: &TestError{Infra: true}},
				{Error: &TestError{Infra: true}},
				{Error: &TestError{Infra: true}},
			},
			opts: CollectRunsOpts{
				WantValid: 3,
				MaxTotal:  6,
				MaxVMs:    3,
			},
			expectErr:     true,
			expectedValid: 0,
		},
		{
			name: "mix_of_crashes_and_infra",
			responses: []EnvTestResult{
				{Error: &TestError{Infra: true}},
				{Error: &CrashError{Report: &report.Report{Title: "crash1"}}},
				{Error: &TestError{Infra: true}},
				{Error: &CrashError{Report: &report.Report{Title: "crash2"}}},
				{Error: &CrashError{Report: &report.Report{Title: "crash3"}}},
			},
			opts: CollectRunsOpts{
				WantValid: 3,
				MaxTotal:  6,
				MaxVMs:    1, // Test sequential.
			},
			expectedValid: 3,
		},
		{
			name: "stop_at_max_total",
			responses: []EnvTestResult{
				{Error: &TestError{Infra: true}},
				{RawOutput: []byte("1")},
				{Error: &TestError{Infra: true}},
				{RawOutput: []byte("2")},
			},
			opts: CollectRunsOpts{
				WantValid: 3,
				MaxTotal:  4, // Stop after 4 total.
				MaxVMs:    4, // Test high parallelism.
			},
			expectErr:     true,
			expectedValid: 2, // We still return what we collected so far if it errors out.
		},
		{
			name: "invalid_opts_fails_fast",
			responses: []EnvTestResult{
				{RawOutput: []byte("1")},
			},
			opts: CollectRunsOpts{
				WantValid: 3,
				MaxTotal:  2, // Invalid: MaxTotal < WantValid.
				MaxVMs:    1,
			},
			expectErr:        true,
			expectErrMessage: "collectRuns: MaxTotal (2) cannot be less than WantValid (3)",
			expectedValid:    0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runner := &mockRunner{responses: tc.responses}

			validResults, err := CollectRuns(runner.Test, tc.opts)
			if tc.expectErr {
				require.Error(t, err)
				if tc.expectErrMessage != "" {
					require.Contains(t, err.Error(), tc.expectErrMessage)
				}
				require.Len(t, validResults, tc.expectedValid)
			} else {
				require.NoError(t, err)
				require.Len(t, validResults, tc.expectedValid)
			}
		})
	}
}
