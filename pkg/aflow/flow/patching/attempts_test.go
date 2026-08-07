// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package patching

import (
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/stretchr/testify/require"
)

func TestRecordFailedAttempt(t *testing.T) {
	ctx := &aflow.Context{}

	// Test no error.
	res, err := recordFailedAttemptImpl(ctx, recordFailedAttemptArgs{
		TestError:      "",
		FailedAttempts: []FailedAttempt{{Strategy: "old"}},
	})
	require.NoError(t, err)
	require.Equal(t, 1, len(res.FailedAttempts))

	// Test with error.
	res, err = recordFailedAttemptImpl(ctx, recordFailedAttemptArgs{
		TestError:        "build failed",
		PatchExplanation: "try this",
		PatchDiff:        "+ foo()",
		FailedAttempts:   []FailedAttempt{{Strategy: "old"}},
	})
	require.NoError(t, err)
	attempts := res.FailedAttempts
	require.Equal(t, 2, len(attempts))
	require.Equal(t, "try this", attempts[1].Strategy)
	require.Equal(t, "+ foo()", attempts[1].Diff)
	require.Equal(t, "build failed", attempts[1].Error)
}

func TestViewFailedAttemptsTool(t *testing.T) {
	ctx := &aflow.Context{}
	state := struct {
		FailedAttempts []FailedAttempt
	}{
		FailedAttempts: []FailedAttempt{
			{
				Strategy: "strategy 1",
				Diff:     "diff 1",
				Error:    "error 1",
			},
			{
				Strategy: "strategy 2",
				Diff:     "diff 2",
				Error:    "error 2",
			},
		},
	}

	// Test summary (AttemptIndex = 0)
	res, err := viewFailedAttemptsToolImpl(ctx, state, viewFailedAttemptsArgs{AttemptIndex: 0})
	require.NoError(t, err)
	result := res.Result
	require.Contains(t, result, "There are 2 previous failed attempts")
	require.Contains(t, result, "Attempt 1:")
	require.Contains(t, result, "strategy 1")
	require.Contains(t, result, "Attempt 2:")
	require.Contains(t, result, "strategy 2")

	// Test specific attempt (AttemptIndex = 1)
	res, err = viewFailedAttemptsToolImpl(ctx, state, viewFailedAttemptsArgs{AttemptIndex: 1})
	require.NoError(t, err)
	result = res.Result
	require.Contains(t, result, "Attempt 1")
	require.Contains(t, result, "strategy 1")
	require.Contains(t, result, "diff 1")
	require.Contains(t, result, "error 1")

	// Test out of bounds attempt (AttemptIndex = 3)
	res, err = viewFailedAttemptsToolImpl(ctx, state, viewFailedAttemptsArgs{AttemptIndex: 3})
	require.NoError(t, err)
	result = res.Result
	require.Contains(t, result, "Note: the specified attempt index (3) is not found.")
	require.Contains(t, result, "There are 2 previous failed attempts")
}
