// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"fmt"
	"maps"
	"reflect"
	"slices"
)

type verifyContext struct {
	actions map[string]bool
	state   map[string]*varState
	models  map[string]bool
	err     error
}

type varState struct {
	action string
	typ    reflect.Type
	used   bool
}

func (ctx *verifyContext) errorf(who, msg string, args ...any) {
	noteError(&ctx.err, fmt.Sprintf("action %v: %v", who, msg), args...)
}

func (ctx *verifyContext) requireNotEmpty(who, name, value string) {
	if value == "" {
		ctx.errorf(who, "%v must not be empty", name)
	}
}

func (ctx *verifyContext) requireInput(who, name string, typ reflect.Type) {
	state := ctx.state[name]
	if state == nil {
		ctx.errorf(who, "no input %v, available inputs: %v",
			name, slices.Collect(maps.Keys(ctx.state)))
		return
	}
	if typ != state.typ {
		ctx.errorf(who, "input %v has wrong type: want %v, has %v",
			name, typ, state.typ)
	}
	state.used = true
}

func (ctx *verifyContext) provideOutput(who, name string, typ reflect.Type, unique bool) {
	state := ctx.state[name]
	if state != nil {
		if unique {
			ctx.errorf(who, "output %v is already set", name)
		} else if typ != state.typ {
			ctx.errorf(who, "output %v changes type: %v -> %v",
				name, state.typ, typ)
		} else if !state.used {
			ctx.errorf(state.action, "output %v is unused", name)
		}
	}
	ctx.state[name] = &varState{
		action: who,
		typ:    typ,
	}
}

func (ctx *verifyContext) finalize() error {
	for name, state := range ctx.state {
		if !state.used {
			ctx.errorf(state.action, "output %v is unused", name)
		}
	}
	return ctx.err
}

func noteError(errp *error, msg string, args ...any) {
	if *errp == nil {
		*errp = fmt.Errorf(msg, args...)
	}
}

func requireInputs[T any](ctx *verifyContext, who string) {
	for name, typ := range foreachFieldOf[T]() {
		ctx.requireInput(who, name, typ)
	}
}

func provideOutputs[T any](ctx *verifyContext, who string) {
	for name, typ := range foreachFieldOf[T]() {
		ctx.provideOutput(who, name, typ, true)
	}
}

func provideArrayOutputs[T any](ctx *verifyContext, who string) {
	for name, typ := range foreachFieldOf[T]() {
		ctx.provideOutput(who, name, reflect.SliceOf(typ), true)
	}
}

func requireSchema[T any](ctx *verifyContext, who, what string) {
	if _, err := schemaFor[T](); err != nil {
		ctx.errorf(who, "%v: %v", what, err)
	}
}
