// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"fmt"
	"strings"
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
		nil,
	)
}

func TestDoWhileErrors(t *testing.T) {
	testRegistrationError[struct{}, struct{}](t,
		"flow test: action body: no input Missing, available inputs: []",
		&Flow{Root: &DoWhile{
			Do: NewFuncAction("body", func(ctx *Context, args struct {
				Missing string
			}) (struct{}, error) {
				return struct{}{}, nil
			}),
			While:         "Condition",
			MaxIterations: 10,
		}})

	testRegistrationError[struct{ Input string }, struct{}](t,
		"flow test: action DoWhile: While must not be empty",
		&Flow{Root: &DoWhile{
			Do: NewFuncAction("body", func(ctx *Context, args struct {
				Input string
			}) (struct{}, error) {
				return struct{}{}, nil
			}),
			MaxIterations: 10,
		}})

	type output struct {
		Output1 string
		Output2 string
	}
	testRegistrationError[struct{}, struct{}](t,
		"flow test: action body: output Output2 is unused",
		&Flow{Root: &DoWhile{
			Do: NewFuncAction("body", func(ctx *Context, args struct{}) (output, error) {
				return output{}, nil
			}),
			While:         "Output1",
			MaxIterations: 10,
		}})

	testRegistrationError[struct{}, struct{}](t,
		"flow test: action DoWhile: bad MaxIterations value 0, should be within [1, 1000]",
		&Flow{Root: &DoWhile{
			Do: NewFuncAction("body", func(ctx *Context, args struct{}) (output, error) {
				return output{}, nil
			}),
			While: "Output1",
		}})
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
		nil,
	)
}

func TestForEach(t *testing.T) {
	type inputs struct {
		List []string
	}
	type outputs struct {
		Result []string
	}

	t.Run("Basic", func(t *testing.T) {
		type actionArgs struct {
			Item   string
			Result []string
		}
		type actionResults struct {
			Result []string
		}
		testFlow[inputs, outputs](t,
			map[string]any{"List": []string{"a", "b", "c"}},
			map[string]any{"Result": []string{"A", "B", "C"}},
			Pipeline(
				&ForEach{
					List: "List",
					Item: "Item",
					Do: NewFuncAction("process-item", func(ctx *Context, args actionArgs) (actionResults, error) {
						res := args.Result
						res = append(res, strings.ToUpper(args.Item))
						return actionResults{res}, nil
					}),
				},
			),
			nil,
			nil,
		)
	})
}

func TestForEachErrors(t *testing.T) {
	testRegistrationError[struct{}, struct{}](t,
		"flow test: action ForEach: List must not be empty",
		&Flow{Root: &ForEach{
			Item: "Item",
			Do: NewFuncAction("body", func(ctx *Context, args struct{ Item string }) (struct{}, error) {
				return struct{}{}, nil
			}),
		}})

	testRegistrationError[struct{}, struct{}](t,
		"flow test: action ForEach: Item must not be empty",
		&Flow{Root: &ForEach{
			List: "List",
			Do: NewFuncAction("body", func(ctx *Context, args struct{ Item string }) (struct{}, error) {
				return struct{}{}, nil
			}),
		}})

	testRegistrationError[struct{}, struct{}](t,
		"flow test: action ForEach: no input List",
		&Flow{Root: &ForEach{
			List: "List",
			Item: "Item",
			Do: NewFuncAction("body", func(ctx *Context, args struct{ Item string }) (struct{}, error) {
				return struct{}{}, nil
			}),
		}})

	testRegistrationError[struct{ List string }, struct{}](t,
		"flow test: action ForEach: input List has wrong type: want slice, has string",
		&Flow{Root: &ForEach{
			List: "List",
			Item: "Item",
			Do: NewFuncAction("body", func(ctx *Context, args struct{ Item string }) (struct{}, error) {
				return struct{}{}, nil
			}),
		}})

	testRegistrationError[struct{ List []string }, struct{}](t,
		"flow test: action ForEach: item Item is unused",
		&Flow{Root: &ForEach{
			List: "List",
			Item: "Item",
			Do: NewFuncAction("body", func(ctx *Context, args struct{}) (struct{}, error) {
				return struct{}{}, nil
			}),
		}})
}

// TestNestedDoWhileVarLeak verifies that variables produced in a nested loop
// do not cause a panic on re-entry in subsequent outer loop iterations.
func TestNestedDoWhileVarLeak(t *testing.T) {
	type actionResults struct {
		Continue      string
		InnerContinue string
	}
	outerIter := 0
	testFlow[struct{}, struct{}](t, nil, map[string]any{},
		&DoWhile{
			MaxIterations: 2,
			While:         "Continue",
			Do: Pipeline(
				NewFuncAction("outer-action", func(ctx *Context, args struct{}) (actionResults, error) {
					outerIter++
					if outerIter < 2 {
						return actionResults{Continue: "yes", InnerContinue: ""}, nil
					}
					return actionResults{Continue: "", InnerContinue: ""}, nil
				}),
				&DoWhile{
					MaxIterations: 1,
					While:         "InnerContinue",
					Do: Pipeline(
						NewFuncAction("inner-action", func(ctx *Context, args struct{}) (struct{ Leaked string }, error) {
							return struct{ Leaked string }{Leaked: "val"}, nil
						}),
						NewFuncAction("consumer-action", func(ctx *Context, args struct{ Leaked string }) (struct{}, error) {
							return struct{}{}, nil
						}),
					),
				},
			),
		},
		nil,
		nil,
	)
}

// TestNestedDoWhileOutput verifies that variables produced inside a nested loop
// are visible to actions in the outer loop after the inner loop finishes.
func TestNestedDoWhileOutput(t *testing.T) {
	type actionResults struct {
		Continue string
	}
	type outerActionArgs struct {
		Leaked string
	}
	testFlow[struct{}, struct{}](t, nil, map[string]any{},
		&DoWhile{
			MaxIterations: 1,
			While:         "Continue",
			Do: Pipeline(
				&DoWhile{
					MaxIterations: 1,
					While:         "InnerContinue",
					Do: Pipeline(
						NewFuncAction("inner-action", func(ctx *Context, args struct{}) (struct {
							InnerContinue string
							Leaked        string
						}, error) {
							return struct {
								InnerContinue string
								Leaked        string
							}{InnerContinue: "", Leaked: "val"}, nil
						}),
					),
				},
				NewFuncAction("outer-consumer", func(ctx *Context, args outerActionArgs) (actionResults, error) {
					if args.Leaked != "val" {
						return actionResults{Continue: ""}, fmt.Errorf("expected Leaked to be 'val', got %q", args.Leaked)
					}
					return actionResults{Continue: ""}, nil
				}),
			),
		},
		nil,
		nil,
	)
}

// TestLoopVarDefinedOutside verifies that the framework detects and errors out
// if a loop tries to produce a variable that was already defined outside the loop.
func TestLoopVarDefinedOutside(t *testing.T) {
	type actionResults struct {
		Leaked string
	}
	testRegistrationError[struct{}, struct{}](t,
		"flow test: action loop-action: output Leaked is already set by init-action",
		&Flow{Root: Pipeline(
			NewFuncAction("init-action", func(ctx *Context, args struct{}) (actionResults, error) {
				return actionResults{Leaked: "val1"}, nil
			}),
			&DoWhile{
				MaxIterations: 1,
				While:         "Continue",
				Do: Pipeline(
					NewFuncAction("loop-action", func(ctx *Context, args struct{}) (struct {
						Continue string
						Leaked   string
					}, error) {
						return struct {
							Continue string
							Leaked   string
						}{Continue: "", Leaked: "val2"}, nil
					}),
				),
			},
		)},
	)
}
