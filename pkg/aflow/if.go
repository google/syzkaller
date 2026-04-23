// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"fmt"
	"reflect"
)

// If represents conditional execution: if (cond != "") { body }.
type If struct {
	// Condition variable name. It should be a string state variable.
	Cond string
	// Action to execute if the condition is non-empty.
	Do Action
}

func (a *If) execute(ctx *Context) error {
	condVal, ok := ctx.state[a.Cond].(string)
	if !ok {
		return fmt.Errorf("if: condition %q is not a string", a.Cond)
	}
	if condVal == "" {
		return nil // Skip.
	}
	return a.Do.execute(ctx)
}

func (a *If) verify(ctx *verifyContext) {
	ctx.requireNotEmpty("If", "Cond", a.Cond)
	ctx.requireInput("If", a.Cond, reflect.TypeFor[string]())

	// The body executes in the same context.
	a.Do.verify(ctx)
}
