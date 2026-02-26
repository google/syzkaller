// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package crash

import (
	"regexp"
	"strings"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

var SyzCompilerCheck = aflow.NewFuncAction("syz-compiler-check", compilerCheck)

type CompilerCheckArgs struct {
	CandidateSyzlang string
}

type CompilerCheckResult struct {
	CompilerSuccess bool
	CompilerErrors  string
}

func compilerCheck(ctx *aflow.Context, args CompilerCheckArgs) (CompilerCheckResult, error) {
	pt, err := prog.GetTarget("linux", "amd64")
	if err != nil {
		return CompilerCheckResult{CompilerSuccess: false, CompilerErrors: err.Error()}, nil
	}
	_, err = pt.Deserialize([]byte(args.CandidateSyzlang), prog.Strict)
	if err != nil {
		return CompilerCheckResult{CompilerSuccess: false, CompilerErrors: err.Error()}, nil
	}
	return CompilerCheckResult{CompilerSuccess: true}, nil
}

var ExtractSyzCode = aflow.NewFuncAction("extract-syz-code", extractSyzCode)

type ExtractSyzCodeArgs struct {
	RawSyzlang string
}

type ExtractSyzCodeResult struct {
	CandidateSyzlang string
}

func extractSyzCode(ctx *aflow.Context, args ExtractSyzCodeArgs) (ExtractSyzCodeResult, error) {
	code := args.RawSyzlang
	// If the code is inside a markdown block, extract it.
	if match := reSyzBlock.FindStringSubmatch(code); match != nil {
		code = match[1]
	} else if match := reCodeBlock.FindStringSubmatch(code); match != nil {
		code = match[1]
	}
	code = strings.TrimSpace(code)
	return ExtractSyzCodeResult{CandidateSyzlang: code}, nil
}

var (
	reSyzBlock  = regexp.MustCompile("(?s)```(?:ex-?)?syz(?:kaller|lang)?\\n(.*?)```")
	reCodeBlock = regexp.MustCompile("(?s)```\\n(.*?)```")
)
