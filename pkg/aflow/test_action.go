// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/aflow/trajectory"
	"github.com/stretchr/testify/require"
)

func TestAction(t *testing.T, a Action, workdir string, initArgs, wantResults any, wantError string) {
	type tester interface {
		testVerify(t *testing.T, ctx *verifyContext, args, results any) (
			map[string]any, map[string]any, func(map[string]any) map[string]any)
	}
	vctx := newVerifyContext()
	args, results, extractOutputs := a.(tester).testVerify(t, vctx, initArgs, wantResults)
	require.NoError(t, vctx.finalize())
	// We don't init all fields, init more, if necessary.
	ctx := &Context{
		state:   args,
		Workdir: workdir,
		onEvent: func(*trajectory.Span) error { return nil },
		stubContext: stubContext{
			timeNow: time.Now,
		},
	}
	defer ctx.close()
	err := a.execute(ctx)
	gotResults := map[string]any{}
	gotError := ""
	if err != nil {
		gotError = err.Error()
	} else {
		gotResults = extractOutputs(ctx.state)
	}
	require.Equal(t, wantError, gotError)
	require.Equal(t, results, gotResults)
}
