// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package reproc

import (
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/stretchr/testify/assert"
)

func TestFormatCFunc(t *testing.T) {
	ctx := aflow.NewTestContext(t)
	args := FormatCArgs{CandidateReproC: "int main() { return 0; }"}
	res, err := FormatCFunc(ctx, args)
	assert.NoError(t, err)
	assert.NotEmpty(t, res.FormattedReproC)
}

func TestTruncateLogFunc(t *testing.T) {
	ctx := aflow.NewTestContext(t)
	args := TruncateLogArgs{
		ConsoleOutput:        "line1\nline2\nline3",
		CandidateCrashReport: "report",
	}
	res, err := TruncateLogFunc(ctx, args)
	assert.NoError(t, err)
	assert.Equal(t, "line1\nline2\nline3", res.TruncatedConsoleOutput)
	assert.Equal(t, "report", res.TruncatedCrashReport)
}

func TestLoopControllerFunc(t *testing.T) {
	ctx := aflow.NewTestContext(t)

	// Case 1: Success.
	args := LoopControllerArgs{
		Feedback:             "good",
		TitleMatches:         true,
		CandidateReproduced:  true,
		FormattedReproC:      "code",
		CandidateBugTitle:    "title",
		CandidateCrashReport: "report",
	}
	res, err := LoopControllerFunc(ctx, args)
	assert.NoError(t, err)
	assert.Equal(t, "", res.ContinueSignal)
	assert.Equal(t, "code", res.ReproC)
	assert.True(t, res.Reproduced)

	// Case 2: Collision.
	args = LoopControllerArgs{
		Feedback:            "collision",
		TitleMatches:        false,
		CandidateReproduced: true,
		CandidateBugTitle:   "wrong title",
	}
	res, err = LoopControllerFunc(ctx, args)
	assert.NoError(t, err)
	assert.Equal(t, "continue", res.ContinueSignal)
	assert.Contains(t, res.OracleFeedback, "Collision detected")

	// Case 3: Successful Probe Run.
	args = LoopControllerArgs{
		Feedback:            "probe successful",
		IsProbe:             true,
		TestError:           "",
		CandidateReproduced: false,
		ProbeSuccessful:     false,
	}
	res, err = LoopControllerFunc(ctx, args)
	assert.NoError(t, err)
	assert.True(t, res.ProbeSuccessful)

	// Case 4: Failed Probe Run due to compilation or run error.
	args = LoopControllerArgs{
		Feedback:            "probe failed",
		IsProbe:             true,
		TestError:           "compilation failed",
		CandidateReproduced: false,
		ProbeSuccessful:     false,
	}
	res, err = LoopControllerFunc(ctx, args)
	assert.NoError(t, err)
	assert.False(t, res.ProbeSuccessful)

	// Case 5: Preserve previously successful ProbeSuccessful state.
	args = LoopControllerArgs{
		Feedback:            "new run",
		IsProbe:             false,
		CandidateReproduced: false,
		ProbeSuccessful:     true,
	}
	res, err = LoopControllerFunc(ctx, args)
	assert.NoError(t, err)
	assert.True(t, res.ProbeSuccessful)
}

func TestExtractCCode(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "with c block",
			input:    "Here is the code:\n```c\nint main() { return 0; }\n```\nHope it works.",
			expected: "int main() { return 0; }\n",
		},
		{
			name:     "with plain block",
			input:    "Here is the code:\n```\nint main() { return 0; }\n```\nHope it works.",
			expected: "int main() { return 0; }\n",
		},
		{
			name:     "no block",
			input:    "int main() { return 0; }",
			expected: "int main() { return 0; }",
		},
		{
			name:     "multiple blocks",
			input:    "```c\nblock 1\n```\n```c\nblock 2\n```",
			expected: "block 1\n",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := extractCCode(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}
