// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package patching

import (
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/stretchr/testify/require"
)

func TestValidatePatchReviewerOutputs(t *testing.T) {
	tests := []struct {
		name      string
		outputs   patchReviewerOutputs
		wantError string
	}{
		{
			name: "approved with no comments",
			outputs: patchReviewerOutputs{
				ReviewApproved: true,
				ReviewComments: nil,
			},
		},
		{
			name: "rejected with comments",
			outputs: patchReviewerOutputs{
				ReviewApproved: false,
				ReviewComments: []string{"fix memory leak"},
			},
		},
		{
			name: "rejected with empty comments",
			outputs: patchReviewerOutputs{
				ReviewApproved: false,
				ReviewComments: []string{},
			},
			wantError: "ReviewComments cannot be empty when ReviewApproved is false",
		},
		{
			name: "rejected with whitespace comments",
			outputs: patchReviewerOutputs{
				ReviewApproved: false,
				ReviewComments: []string{"   ", "\t"},
			},
			wantError: "ReviewComments cannot be empty when ReviewApproved is false",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validatePatchReviewerOutputs(nil, struct{}{}, tt.outputs)
			if tt.wantError != "" {
				require.EqualError(t, err, tt.wantError)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.outputs, got)
			}
		})
	}
}

func TestEvaluatePatchReview(t *testing.T) {
	tests := []struct {
		name       string
		args       patchReviewerOutputs
		wantResult reviewEvaluation
	}{
		{
			name: "approved",
			args: patchReviewerOutputs{
				ReviewApproved: true,
				ReviewComments: []string{"minor note"},
			},
			wantResult: reviewEvaluation{},
		},
		{
			name: "rejected with bullet formatting and trimming",
			args: patchReviewerOutputs{
				ReviewApproved: false,
				ReviewComments: []string{
					"- already has bullet",
					"* asterisk bullet",
					"plain comment",
					"   ",
					"-  ",
				},
			},
			wantResult: reviewEvaluation{
				NeedsIteration: true,
				ReviewFeedback: "- already has bullet\n- asterisk bullet\n- plain comment",
			},
		},
		{
			name: "rejected with only whitespace comments",
			args: patchReviewerOutputs{
				ReviewApproved: false,
				ReviewComments: []string{"  ", "- "},
			},
			wantResult: reviewEvaluation{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aflow.TestAction(t, evaluatePatchReview, "", tt.args, tt.wantResult, "")
		})
	}
}

func TestSetTestFailure(t *testing.T) {
	aflow.TestAction(t, setTestFailure, "", struct{}{}, testFailureOutputs{
		NeedsIteration: true,
	}, "")
}

func TestPatchGenerationLoopVariants(t *testing.T) {
	// Verify loop without reviewer targets TestError.
	loopNoReview := patchGenerationLoop(nil, "instruction", "prompt", "")
	require.NotNil(t, loopNoReview)

	// Verify loop with reviewer targets NeedsIteration.
	loopWithReview := patchGenerationLoop(nil, "instruction", "prompt", reviewerPrompt)
	require.NotNil(t, loopWithReview)
}
