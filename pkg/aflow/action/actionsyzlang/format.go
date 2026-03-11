// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package actionsyzlang

import (
	"fmt"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

var Format = aflow.NewFuncAction("syzlang-format", formatActionFunc)

type FormatArgs struct {
	CandidateReproSyz string
}

type FormatResult struct {
	ReproSyz string
}

func formatActionFunc(ctx *aflow.Context, args FormatArgs) (FormatResult, error) {
	pt, err := prog.GetTarget("linux", "amd64")
	if err != nil {
		return FormatResult{}, err
	}
	p, err := pt.Deserialize([]byte(args.CandidateReproSyz), prog.Strict)
	if err != nil {
		return FormatResult{}, fmt.Errorf("failed to deserialize syzkaller program: %w", err)
	}

	return FormatResult{ReproSyz: string(p.Serialize())}, nil
}
