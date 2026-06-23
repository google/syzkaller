// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"slices"
	"testing"
)

func TestContextModelNames(t *testing.T) {
	tests := []struct {
		name     string
		llmModel string
		model    ModelType
		want     []string
	}{
		{
			name:  "resolves good balanced model pool",
			model: GoodBalancedModel,
			want:  []string{gemini3FlashPreview, gemini35Flash},
		},
		{
			name:  "resolves best expensive model pool",
			model: BestExpensiveModel,
			want:  []string{gemini31ProPreview},
		},
		{
			name:  "falls back to raw string for unrecognized model type",
			model: "custom-model",
			want:  []string{"custom-model"},
		},
		{
			name:  "resolves comma separated mixed models",
			model: "best-expensive,custom-model,good-balanced",
			want:  []string{"best-expensive", "custom-model", "good-balanced"},
		},
		{
			name:     "respects context level override",
			llmModel: "override-model",
			model:    GoodBalancedModel,
			want:     []string{"override-model"},
		},
		{
			name:     "respects context level override even for unrecognized model type",
			llmModel: "override-model",
			model:    "custom-model",
			want:     []string{"override-model"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := &Context{
				llmModel: tc.llmModel,
			}
			got := ctx.modelNames(tc.model)
			if !slices.Equal(got, tc.want) {
				t.Errorf("ctx.modelNames(%v) = %v, want %v", tc.model, got, tc.want)
			}
		})
	}
}
