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
	assert.Equal(t, "good", res.EquivalenceAnalysis)

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
		Feedback:             "probe successful",
		IsProbe:              true,
		TestError:            "",
		CandidateReproduced:  false,
		ProbePassed:          true,
		CapabilitiesVerified: false,
	}
	res, err = LoopControllerFunc(ctx, args)
	assert.NoError(t, err)
	assert.True(t, res.CapabilitiesVerified)

	// Case 4: Failed Probe Run due to compilation or run error.
	args = LoopControllerArgs{
		Feedback:             "probe failed",
		IsProbe:              true,
		TestError:            "compilation failed",
		CandidateReproduced:  false,
		ProbePassed:          false,
		CapabilitiesVerified: false,
	}
	res, err = LoopControllerFunc(ctx, args)
	assert.NoError(t, err)
	assert.False(t, res.CapabilitiesVerified)

	// Case 5: Preserve previously successful ProbeSuccessful state.
	args = LoopControllerArgs{
		Feedback:             "new run",
		IsProbe:              false,
		CandidateReproduced:  false,
		CapabilitiesVerified: true,
	}
	res, err = LoopControllerFunc(ctx, args)
	assert.NoError(t, err)
	assert.True(t, res.CapabilitiesVerified)

	// Case 6: Terminal error propagation.
	args = LoopControllerArgs{
		Feedback:            "hard environment failure",
		IsProbe:             true,
		CandidateReproduced: false,
		TerminalError:       "missing /dev/kvm",
	}
	res, err = LoopControllerFunc(ctx, args)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "terminal environment failure: missing /dev/kvm")
	assert.Equal(t, "", res.ContinueSignal)
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

func TestValidateOracleOutputs(t *testing.T) {
	ctx := aflow.NewTestContext(t)

	// Case 1: Probe phase, success.
	state := OracleValidationState{IsProbe: true}
	res := OracleResult{ProbePassed: true}
	_, err := validateOracleOutputs(ctx, state, res)
	assert.NoError(t, err)

	// Case 2: Probe phase, failure without feedback or terminal error -> should fail validation.
	res = OracleResult{ProbePassed: false}
	_, err = validateOracleOutputs(ctx, state, res)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "you must provide Feedback explaining what failed")

	// Case 3: Probe phase, failure with feedback -> success.
	res = OracleResult{ProbePassed: false, Feedback: "some feedback"}
	_, err = validateOracleOutputs(ctx, state, res)
	assert.NoError(t, err)

	// Case 4: Probe phase, terminal error set but ProbePassed is true -> should fail validation.
	res = OracleResult{ProbePassed: true, TerminalError: "missing /dev/kvm"}
	_, err = validateOracleOutputs(ctx, state, res)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "TerminalError is set, so ProbePassed must be false")

	// Case 5: Repro phase, reproduced and matched -> success.
	state = OracleValidationState{IsProbe: false, CandidateReproduced: true}
	res = OracleResult{TitleMatches: true}
	_, err = validateOracleOutputs(ctx, state, res)
	assert.NoError(t, err)

	// Case 6: Repro phase, reproduced but collision without feedback -> should fail validation.
	res = OracleResult{TitleMatches: false}
	_, err = validateOracleOutputs(ctx, state, res)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "collision detected")
	assert.Contains(t, err.Error(), "you must provide Feedback")

	// Case 7: Repro phase, reproduced but collision with feedback -> success.
	res = OracleResult{TitleMatches: false, Feedback: "collision feedback"}
	_, err = validateOracleOutputs(ctx, state, res)
	assert.NoError(t, err)

	// Case 8: Repro phase, not reproduced and no feedback/terminal error -> should fail validation.
	state = OracleValidationState{IsProbe: false, CandidateReproduced: false}
	res = OracleResult{}
	_, err = validateOracleOutputs(ctx, state, res)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "reproduction failed")
	assert.Contains(t, err.Error(), "you must provide Feedback")
}
