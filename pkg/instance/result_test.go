// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package instance

import (
	"fmt"
	"testing"

	"github.com/google/syzkaller/pkg/report"
	"github.com/stretchr/testify/assert"
)

func TestAggregateTestResults(t *testing.T) {
	tests := []struct {
		name    string
		results []EnvTestResult
		want    int // Index of the expected result in input array.
		wantErr error
	}{
		{
			name:    "empty",
			results: []EnvTestResult{},
			wantErr: fmt.Errorf("no env test runs"),
		},
		{
			name: "single success",
			results: []EnvTestResult{
				{RawOutput: []byte("log")},
			},
			want: 0,
		},
		{
			name: "success over error",
			results: []EnvTestResult{
				{Error: fmt.Errorf("failed")},
				{RawOutput: []byte("success")},
			},
			want: 1,
		},
		{
			name: "crash over success",
			results: []EnvTestResult{
				{RawOutput: []byte("success")},
				{Error: &CrashError{}},
			},
			want: 1,
		},
		{
			name: "crash over error",
			results: []EnvTestResult{
				{Error: fmt.Errorf("failed")},
				{Error: &CrashError{}},
			},
			want: 1,
		},
		{
			name: "crash with report over crash",
			results: []EnvTestResult{
				{Error: &CrashError{}},
				{Error: &CrashError{Report: &report.Report{Report: []byte("report")}}},
			},
			want: 1,
		},
		{
			name: "first crash wins if equal",
			results: []EnvTestResult{
				{Error: &CrashError{Report: &report.Report{Title: "crash 1", Report: []byte("report")}}},
				{Error: &CrashError{Report: &report.Report{Title: "crash 2", Report: []byte("report")}}},
			},
			want: 0,
		},
		{
			name: "crash over test error",
			results: []EnvTestResult{
				{Error: &TestError{Title: "test failed"}},
				{Error: &CrashError{Report: &report.Report{Title: "crash"}}},
			},
			want: 1,
		},
		{
			name: "test error over other error (because it is later)",
			results: []EnvTestResult{
				{Error: fmt.Errorf("unknown error")},
				{Error: &TestError{Title: "test failed"}},
			},
			want: 1,
		},
		{
			name: "last success wins if equal",
			results: []EnvTestResult{
				{RawOutput: []byte("success 1")},
				{RawOutput: []byte("success 2")},
			},
			want: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := AggregateTestResults(tt.results)
			if tt.wantErr != nil {
				assert.Equal(t, tt.wantErr, err)
				return
			}
			assert.NoError(t, err)
			assert.Same(t, &tt.results[tt.want], got)
		})
	}
}
