// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"testing"
)

func TestModelNameResolution(t *testing.T) {
	tests := []struct {
		name     string
		llmModel string
		model    ModelType
		want     string
	}{
		{
			name:  "resolves good balanced model",
			model: GoodBalancedModel,
			want:  gemini3FlashPreview,
		},
		{
			name:  "resolves best expensive model",
			model: BestExpensiveModel,
			want:  gemini31ProPreview,
		},
		{
			name:  "falls back to raw string for unrecognized model type",
			model: "custom-model",
			want:  "custom-model",
		},
		{
			name:     "respects context level override",
			llmModel: "override-model",
			model:    GoodBalancedModel,
			want:     "override-model",
		},
		{
			name:     "respects context level override even for unrecognized model type",
			llmModel: "override-model",
			model:    "custom-model",
			want:     "override-model",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := &Context{
				llmModel: tc.llmModel,
			}
			got := ctx.modelName(tc.model)
			if got != tc.want {
				t.Errorf("ctx.modelName(%q) = %q, want %q", tc.model, got, tc.want)
			}
		})
	}
}
