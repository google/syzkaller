// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"testing"
)

func TestIf(t *testing.T) {
	type outputs struct {
		Done string
	}
	type actionArgs struct{}
	type actionResults struct {
		Done string
	}

	action := NewFuncAction("if-body", func(ctx *Context, args actionArgs) (actionResults, error) {
		return actionResults{"done"}, nil
	})

	t.Run("StringTrue", func(t *testing.T) {
		type inputs struct{ Cond string }
		testFlow[inputs, outputs](t, map[string]any{"Cond": "yes"}, map[string]any{"Done": "done"},
			&If{Condition: "Cond", Do: action}, nil, nil)
	})

	t.Run("StringFalse", func(t *testing.T) {
		type inputs struct{ Cond string }
		testFlow[inputs, outputs](t, map[string]any{"Cond": ""}, map[string]any{"Done": ""},
			&If{Condition: "Cond", Do: action}, nil, nil)
	})

	t.Run("BoolTrue", func(t *testing.T) {
		type inputs struct{ Cond bool }
		testFlow[inputs, outputs](t, map[string]any{"Cond": true}, map[string]any{"Done": "done"},
			&If{Condition: "Cond", Do: action}, nil, nil)
	})

	t.Run("BoolFalse", func(t *testing.T) {
		type inputs struct{ Cond bool }
		testFlow[inputs, outputs](t, map[string]any{"Cond": false}, map[string]any{"Done": ""},
			&If{Condition: "Cond", Do: action}, nil, nil)
	})

	t.Run("IntTrue", func(t *testing.T) {
		type inputs struct{ Cond int }
		testFlow[inputs, outputs](t, map[string]any{"Cond": 42}, map[string]any{"Done": "done"},
			&If{Condition: "Cond", Do: action}, nil, nil)
	})

	t.Run("IntFalse", func(t *testing.T) {
		type inputs struct{ Cond int }
		testFlow[inputs, outputs](t, map[string]any{"Cond": 0}, map[string]any{"Done": ""},
			&If{Condition: "Cond", Do: action}, nil, nil)
	})
}

func TestIfErrors(t *testing.T) {
	testRegistrationError[struct{}, struct{}](t,
		"flow test: action If: Condition must not be empty",
		&Flow{Root: &If{
			Do: NewFuncAction("body", func(ctx *Context, args struct{}) (struct{}, error) {
				return struct{}{}, nil
			}),
		}})

	testRegistrationError[struct{}, struct{}](t,
		"flow test: action If: no input Cond",
		&Flow{Root: &If{
			Condition: "Cond",
			Do: NewFuncAction("body", func(ctx *Context, args struct{}) (struct{}, error) {
				return struct{}{}, nil
			}),
		}})
}
