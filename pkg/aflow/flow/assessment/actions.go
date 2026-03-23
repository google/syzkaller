// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package assessmenet

import (
	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/email"
)

var formatExplanation = aflow.NewFuncAction("format-explanation", formatExplanationFunc)

type formatExplanationArgs struct {
	ExplanationRaw string
}

type formatExplanationResult struct {
	Explanation string
}

func formatExplanationFunc(ctx *aflow.Context, args formatExplanationArgs) (formatExplanationResult, error) {
	return formatExplanationResult{Explanation: email.WordWrap(args.ExplanationRaw, 80)}, nil
}
