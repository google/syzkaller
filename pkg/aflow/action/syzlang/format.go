// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzlang

import (
	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

// Format is a pipeline action that takes a syz program, validates it, and formats it to canonical form.
var Format = aflow.NewFuncAction("repro-format", format)

type FormatArgs struct {
	ReproSyz string `jsonschema:"Syz program to format."`
}

type FormatResult struct {
	ReproSyz string `jsonschema:"Canonical syz program representation."`
}

func format(ctx *aflow.Context, args FormatArgs) (FormatResult, error) {
	pt, err := prog.GetTarget("linux", "amd64")
	if err != nil {
		return FormatResult{}, err
	}
	p, err := pt.Deserialize([]byte(args.ReproSyz), prog.Strict)
	if err != nil {
		return FormatResult{}, err
	}
	return FormatResult{ReproSyz: string(p.Serialize())}, nil
}
