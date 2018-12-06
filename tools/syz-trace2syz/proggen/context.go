// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package proggen

import (
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/tools/syz-trace2syz/parser"
)

// Context stores metadata related to a syzkaller program
type Context struct {
	ReturnCache       returnCache
	Prog              *prog.Prog
	CurrentStraceCall *parser.Syscall
	CurrentSyzCall    *prog.Call
	CurrentStraceArg  parser.IrType
	Target            *prog.Target
	Tracker           *memoryTracker
	CallSelector      *CallSelector
}

func newContext(target *prog.Target, selector *CallSelector) *Context {
	return &Context{
		ReturnCache:  newRCache(),
		Tracker:      newTracker(),
		Target:       target,
		CallSelector: selector,
		Prog: &prog.Prog{
			Target: target,
		},
	}
}

// FillOutMemory assigns addresses to pointer arguments.
func (ctx *Context) FillOutMemory() error {
	return ctx.Tracker.fillOutPtrArgs(ctx.Prog)
}
