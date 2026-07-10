// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzlang

import (
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/stretchr/testify/require"
)

type mockCachedExecution struct {
	BaseTestSeed string
	GeneratedSyz string
}

func TestCodeFixerValidatedOutputs(t *testing.T) {
	ctx := aflow.NewTestContext(t)

	// Create a mock cached execution.
	mockExec := mockCachedExecution{
		BaseTestSeed: "base_seed",
		GeneratedSyz: "line 1\nline 2 modified\nline 3\nline 4\n",
	}

	_, cachedID, err := aflow.CacheObject(ctx, "repro", "test-run", func() (mockCachedExecution, error) {
		return mockExec, nil
	})
	require.NoError(t, err)

	args := CodeFixerArgs{
		SyzProgram: "line 1\nline 2\nline 3\n",
	}
	res := CodeFixerResult{
		ExecutionCachedID: cachedID,
	}

	gotRes, err := validateCodeFixerOutputs(ctx, struct{}{}, args, res)
	require.NoError(t, err)
	require.Equal(t, mockExec.GeneratedSyz, gotRes.Program)

	// Check the unified diff.
	expectedDiff := `--- original
+++ fixed
@@ -1,3 +1,4 @@
 line 1
-line 2
+line 2 modified
 line 3
+line 4
`
	require.Equal(t, expectedDiff, gotRes.ProgramDiff)
}

func TestCodeFixerValidatedOutputs_NoDiff(t *testing.T) {
	tests := []struct {
		name       string
		syzProgram string
	}{
		{
			name:       "with trailing newline",
			syzProgram: "line 1\nline 2\nline 3\n",
		},
		{
			name:       "without trailing newline",
			syzProgram: "line 1\nline 2\nline 3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := aflow.NewTestContext(t)
			mockExec := mockCachedExecution{
				BaseTestSeed: "base_seed",
				GeneratedSyz: "line 1\nline 2\nline 3\n",
			}

			_, cachedID, err := aflow.CacheObject(ctx, "repro", "test-run", func() (mockCachedExecution, error) {
				return mockExec, nil
			})
			require.NoError(t, err)

			args := CodeFixerArgs{
				SyzProgram: tt.syzProgram,
			}
			res := CodeFixerResult{
				ExecutionCachedID: cachedID,
			}

			gotRes, err := validateCodeFixerOutputs(ctx, struct{}{}, args, res)
			require.NoError(t, err)
			require.Equal(t, mockExec.GeneratedSyz, gotRes.Program)
			require.Empty(t, gotRes.ProgramDiff)
		})
	}
}
