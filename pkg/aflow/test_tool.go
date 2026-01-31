// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestTool runs the given tool on provided initState/initArgs and compares results/error
// with the provided wantResults/wantError.
// wantResults can be either the tool return struct, or a function that accepts the tool
// return struct. In the latter case, the function is executed with the actual results,
// and is supposed to do assertions on the value.
func TestTool(t *testing.T, tool Tool, initState, initArgs, wantResults any, wantError string) {
	type tester interface {
		testVerify(t *testing.T, ctx *verifyContext, state, args, results any) (
			map[string]any, map[string]any, func(map[string]any))
	}
	vctx := newVerifyContext()
	state, args, resultChecker := tool.(tester).testVerify(t, vctx, initState, initArgs, wantResults)
	require.NoError(t, vctx.finalize())
	// Just ensure it does not crash.
	_ = tool.declaration()
	// We don't init all fields, init more, if necessary.
	ctx := &Context{
		state: state,
	}
	defer ctx.close()
	gotResults, err := tool.execute(ctx, args)
	gotError := ""
	if err != nil {
		gotError = err.Error()
	}
	require.Equal(t, wantError, gotError)
	resultChecker(gotResults)
}

func FuzzTool(t *testing.T, tool Tool, initState, initArgs any) (map[string]any, error) {
	type toolFuzzer interface {
		checkFuzzTypes(t *testing.T, state, args any) (map[string]any, map[string]any)
	}
	state, args := tool.(toolFuzzer).checkFuzzTypes(t, initState, initArgs)
	ctx := &Context{
		state: state,
	}
	defer ctx.close()
	return tool.execute(ctx, args)
}
