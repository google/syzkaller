// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"errors"
	"fmt"
	"testing"
)

func TestTry(t *testing.T) {
	type actionArgs struct{}

	t.Run("BadCallErrorCaught", func(t *testing.T) {
		type inputs struct{}
		type flowOutputs struct {
			CatchVal string
			Error    string
		}
		type catchOutputs struct {
			CatchVal string
		}
		doAction := NewFuncAction("do-bad-call", func(ctx *Context, args actionArgs) (struct{}, error) {
			return struct{}{}, BadCallError("judge stopped execution")
		})
		catchAction := NewFuncAction("catch-action", func(ctx *Context, args actionArgs) (catchOutputs, error) {
			return catchOutputs{CatchVal: "caught"}, nil
		})

		testFlow[inputs, flowOutputs](t, map[string]any{}, map[string]any{
			"CatchVal": "caught",
			"Error":    "judge stopped execution",
		}, &Try{
			Do:       doAction,
			Catch:    catchAction,
			ErrorVar: "Error",
		}, nil, nil)
	})

	t.Run("FatalFlowErrorNotCaught", func(t *testing.T) {
		type inputs struct{}
		type flowOutputs struct {
			CatchVal string
			Error    string
		}
		type catchOutputs struct {
			CatchVal string
		}
		doAction := NewFuncAction("do-fatal-error", func(ctx *Context, args actionArgs) (struct{}, error) {
			return struct{}{}, FlowError(fmt.Errorf("fatal kernel build error"))
		})
		catchAction := NewFuncAction("catch-action", func(ctx *Context, args actionArgs) (catchOutputs, error) {
			return catchOutputs{CatchVal: "should not be reached"}, nil
		})

		testFlow[inputs, flowOutputs](t, map[string]any{}, "fatal kernel build error", &Try{
			Do:       doAction,
			Catch:    catchAction,
			ErrorVar: "Error",
		}, nil, nil)
	})

	t.Run("GenericErrorNotCaught", func(t *testing.T) {
		type inputs struct{}
		type flowOutputs struct {
			CatchVal string
			Error    string
		}
		type catchOutputs struct {
			CatchVal string
		}
		doAction := NewFuncAction("do-generic-error", func(ctx *Context, args actionArgs) (struct{}, error) {
			return struct{}{}, errors.New("infrastructure failure")
		})
		catchAction := NewFuncAction("catch-action", func(ctx *Context, args actionArgs) (catchOutputs, error) {
			return catchOutputs{CatchVal: "should not be reached"}, nil
		})

		testFlow[inputs, flowOutputs](t, map[string]any{}, "infrastructure failure", &Try{
			Do:       doAction,
			Catch:    catchAction,
			ErrorVar: "Error",
		}, nil, nil)
	})

	t.Run("SuccessNoCatch", func(t *testing.T) {
		type inputs struct{}
		type flowOutputs struct {
			DoVal string
			Error string
		}
		type doOutputs struct {
			DoVal string
		}
		doAction := NewFuncAction("do-success", func(ctx *Context, args actionArgs) (doOutputs, error) {
			return doOutputs{DoVal: "success"}, nil
		})
		catchAction := NewFuncAction("catch-action", func(ctx *Context, args actionArgs) (struct{}, error) {
			return struct{}{}, nil
		})

		testFlow[inputs, flowOutputs](t, map[string]any{}, map[string]any{
			"DoVal": "success",
			"Error": "",
		}, &Try{
			Do:       doAction,
			Catch:    catchAction,
			ErrorVar: "Error",
		}, nil, nil)
	})
}
