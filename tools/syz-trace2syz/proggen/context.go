// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package proggen

import (
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/tools/syz-trace2syz/parser"
)

// Context stores metadata related to a syzkaller program
type Context struct {
	pg                *prog.ProgGen
	ReturnCache       returnCache
	CurrentStraceCall *parser.Syscall
	CurrentSyzCall    *prog.Call
	CurrentStraceArg  parser.IrType
	Target            *prog.Target
	callSelector      *callSelector
}

func newContext(target *prog.Target) *Context {
	return &Context{
		pg:           prog.MakeProgGen(target),
		ReturnCache:  newRCache(),
		Target:       target,
		callSelector: newCallSelector(),
	}
}
