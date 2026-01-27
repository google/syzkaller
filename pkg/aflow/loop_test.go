// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"testing"
)

func TestDoWhile(t *testing.T) {
	type inputs struct {
		Bug string
	}
	type outputs struct {
		Diff string
	}
	type patchArgs struct {
		Bug       string
		Diff      string
		TestError string
	}
	type patchResults struct {
		Patch string
	}
	type testArgs struct {
		Patch string
	}
	type testResults struct {
		Diff      string
		TestError string
	}
	iter := 0
	testFlow[inputs, outputs](t, map[string]any{"Bug": "bug"}, map[string]any{"Diff": "diff"},
		&DoWhile{
			Do: Pipeline(
				NewFuncAction("patch-generator", func(ctx *Context, args patchArgs) (patchResults, error) {
					iter++
					if iter <= 2 {
						return patchResults{"bad"}, nil
					}
					return patchResults{"good"}, nil
				}),
				NewFuncAction("patch-tester", func(ctx *Context, args testArgs) (testResults, error) {
					if args.Patch == "bad" {
						return testResults{TestError: "error"}, nil
					}
					return testResults{Diff: "diff"}, nil
				}),
			),
			While:         "TestError",
			MaxIterations: 10,
		},
		nil,
	)
}

func TestDoWhileErrors(t *testing.T) {
	testRegistrationError[struct{}, struct{}](t,
		"flow test: action body: no input Missing, available inputs: []",
		Pipeline(
			&DoWhile{
				Do: NewFuncAction("body", func(ctx *Context, args struct {
					Missing string
				}) (struct{}, error) {
					return struct{}{}, nil
				}),
				While:         "Condition",
				MaxIterations: 10,
			},
		))

	testRegistrationError[struct{ Input string }, struct{}](t,
		"flow test: action DoWhile: While must not be empty",
		Pipeline(
			&DoWhile{
				Do: NewFuncAction("body", func(ctx *Context, args struct {
					Input string
				}) (struct{}, error) {
					return struct{}{}, nil
				}),
				MaxIterations: 10,
			},
		))

	type output struct {
		Output1 string
		Output2 string
	}
	testRegistrationError[struct{}, struct{}](t,
		"flow test: action body: output Output2 is unused",
		Pipeline(
			&DoWhile{
				Do: NewFuncAction("body", func(ctx *Context, args struct{}) (output, error) {
					return output{}, nil
				}),
				While:         "Output1",
				MaxIterations: 10,
			},
		))
	testRegistrationError[struct{}, struct{}](t,
		"flow test: action DoWhile: bad MaxIterations value 0, should be within [1, 1000]",
		Pipeline(
			&DoWhile{
				Do: NewFuncAction("body", func(ctx *Context, args struct{}) (output, error) {
					return output{}, nil
				}),
				While: "Output1",
			},
		))
}

func TestDoWhileMaxIters(t *testing.T) {
	type actionResults struct {
		Error string
	}
	testFlow[struct{}, struct{}](t, nil, "DoWhile loop is going in cycles for 3 iterations",
		&DoWhile{
			Do: NewFuncAction("nop", func(ctx *Context, args struct{}) (actionResults, error) {
				return actionResults{"failed"}, nil
			}),
			While:         "Error",
			MaxIterations: 3,
		},
		nil,
	)
}
