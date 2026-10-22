// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package instance

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/syzkaller/pkg/report"
	"github.com/stretchr/testify/assert"
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
		expectErrIs      error
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
			expectErrIs:   ErrTooManyInfraErrors,
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
			expectErrIs:   ErrTooManyInfraErrors,
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
			// Use synctest to not actually wait for the backoff.
			synctest.Test(t, func(t *testing.T) {
				runner := &mockRunner{responses: tc.responses}

				validResults, err := CollectRuns(t.Context(), runner.Test, tc.opts)
				if tc.expectErr {
					require.Error(t, err)
					if tc.expectErrIs != nil {
						require.ErrorIs(t, err, tc.expectErrIs)
					}
					if tc.expectErrMessage != "" {
						require.Contains(t, err.Error(), tc.expectErrMessage)
					}
					require.Len(t, validResults, tc.expectedValid)
				} else {
					require.NoError(t, err)
					require.Len(t, validResults, tc.expectedValid)
				}
			})
		})
	}
}

func TestCollectRunsSmallerBatches(t *testing.T) {
	// The attempt runs fewer VMs than requested (e.g. the VM pool is smaller).
	calls := 0
	validResults, err := CollectRuns(t.Context(), func(int) ([]EnvTestResult, error) {
		calls++
		return []EnvTestResult{{RawOutput: []byte("ok")}}, nil
	}, CollectRunsOpts{
		WantValid: 3,
		MaxTotal:  3,
		MaxVMs:    3,
	})
	require.NoError(t, err)
	assert.Len(t, validResults, 3)
	assert.Equal(t, 3, calls)
}

func TestCollectRunsNoResults(t *testing.T) {
	attempts := 0
	_, err := CollectRuns(t.Context(), func(int) ([]EnvTestResult, error) {
		attempts++
		return nil, nil
	}, CollectRunsOpts{
		WantValid: 1,
		MaxTotal:  3,
		MaxVMs:    1,
	})
	require.Error(t, err)
	assert.Equal(t, 1, attempts)
}

func TestCollectRunsCancel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		runner := &mockRunner{responses: []EnvTestResult{
			{Error: &TestError{Infra: true}},
			{RawOutput: []byte("1")},
		}}
		start := time.Now()
		_, err := CollectRuns(ctx, func(numVMs int) ([]EnvTestResult, error) {
			// Cancel the context during the first batch, we must not wait for the backoff.
			cancel()
			return runner.Test(numVMs)
		}, CollectRunsOpts{
			WantValid: 1,
			MaxTotal:  2,
			MaxVMs:    1,
		})
		require.ErrorIs(t, err, context.Canceled)
		assert.Equal(t, 1, runner.idx)
		assert.Zero(t, time.Since(start))
	})
}

func TestCollectRunsBackoff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		runner := &mockRunner{responses: []EnvTestResult{
			{Error: &TestError{Infra: true}}, // We back off only after this one.
			{RawOutput: []byte("1")},
			{Error: &CrashError{Report: &report.Report{Title: "crash"}}},
			{RawOutput: []byte("3")},
		}}
		start := time.Now()
		validResults, err := CollectRuns(t.Context(), runner.Test, CollectRunsOpts{
			WantValid: 3,
			MaxTotal:  4,
			MaxVMs:    1,
		})
		require.NoError(t, err)
		assert.Len(t, validResults, 3)
		// Inside the synctest bubble, time only advances while we wait for the backoff.
		assert.Equal(t, infraErrorBackoff, time.Since(start))
	})
}
