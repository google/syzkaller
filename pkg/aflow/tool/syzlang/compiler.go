// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzlang

import (
	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

var ToolSyzCompilerCheck = aflow.NewFuncTool("syz-compiler-check", compilerCheck, `
Tool is used to verify the syz program correctness.
`)

type CompilerCheckArgs struct {
	CandidateSyzlang string `jsonschema:"Syz program to verify."`
}

type CompilerCheckResult struct {
	CompilerSuccess  bool   `jsonschema:"Success signal."`
	CompilerErrors   string `jsonschema:"Error description on failure."`
	CanonicalSyzlang string `jsonschema:"Canonical syz program representation."`
}

func compilerCheck(ctx *aflow.Context, state struct{}, args CompilerCheckArgs) (CompilerCheckResult, error) {
	pt, err := prog.GetTarget("linux", "amd64")
	if err != nil {
		return CompilerCheckResult{CompilerSuccess: false, CompilerErrors: err.Error()}, nil
	}
	p, err := pt.Deserialize([]byte(args.CandidateSyzlang), prog.Strict)
	if err != nil {
		return CompilerCheckResult{CompilerSuccess: false, CompilerErrors: err.Error()}, nil
	}
	return CompilerCheckResult{CompilerSuccess: true, CanonicalSyzlang: string(p.Serialize())}, nil
}
