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
		ShouldContinue:       false,
		TitleMatches:         true,
		CandidateReproduced:  true,
		CandidateReproC:      "code",
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
		ShouldContinue:      false,
		TitleMatches:        false,
		CandidateReproduced: true,
		CandidateBugTitle:   "wrong title",
	}
	res, err = LoopControllerFunc(ctx, args)
	assert.NoError(t, err)
	assert.Equal(t, "continue", res.ContinueSignal)
	assert.Contains(t, res.OracleFeedback, "Collision detected")
}
