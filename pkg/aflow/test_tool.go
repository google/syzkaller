// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTool(t *testing.T, tool Tool, initState, initArgs, wantResults any, wantError string) {
	type toolTester interface {
		checkTestTypes(t *testing.T, ctx *verifyContext, state, args, results any) (
			map[string]any, map[string]any, map[string]any)
	}
	vctx := newVerifyContext()
	state, args, results := tool.(toolTester).checkTestTypes(t, vctx, initState, initArgs, wantResults)
	tool.verify(vctx)
	if err := vctx.finalize(); err != nil {
		t.Fatal(err)
	}
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
	require.Equal(t, results, gotResults)
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
