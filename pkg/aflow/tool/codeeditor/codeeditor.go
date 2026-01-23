// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package codeeditor

import (
	"github.com/google/syzkaller/pkg/aflow"
)

var Tool = aflow.NewFuncTool("codeeditor", codeeditor, `
The tool does one code edit to form the final patch.
The tool should be called mutiple times to do all required changes one-by-one,
but avoid changing the same lines multiple times.
Note: You will not see your edits via the codesearch tool.
Note: The current code snippet should reflect the previous changes.
`)

type state struct {
	KernelScratchSrc string
}

type args struct {
	SourceFile  string `jsonschema:"Full source file path."`
	CurrentCode string `jsonschema:"The current code to replace verbatim with new lines, but without line numbers."`
	NewCode     string `jsonschema:"New code to replace the current code snippet."`
}

func codeeditor(ctx *aflow.Context, state state, args args) (struct{}, error) {
	// TODO: check that the SourceFile is not escaping.
	// If SourceFile is incorrect, or CurrentCode is not matched, return aflow.BadCallError
	// with an explanation. Say that it needs to increase context if CurrentCode is not matched.
	// Try to do as fuzzy match for CurrentCode as possible (strip line numbers,
	// ignore white-spaces, etc).
	// Should we accept a reference line number, or function name to disambiguate in the case
	// of multiple matches?
	return struct{}{}, nil
}
