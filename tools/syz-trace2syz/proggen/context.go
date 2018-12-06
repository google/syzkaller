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

func newContext(target *prog.Target, selector *CallSelector) (ctx *Context) {
	ctx = &Context{}
	ctx.ReturnCache = newRCache()
	ctx.CurrentStraceCall = nil
	ctx.Tracker = newTracker()
	ctx.CurrentStraceArg = nil
	ctx.Target = target
	ctx.CallSelector = selector
	ctx.Prog = new(prog.Prog)
	ctx.Prog.Target = target
	return
}

// FillOutMemory determines how much memory to allocate for arguments in a program
// And generates an mmap c to do the allocation.This mmap is prepended to prog.Calls
func (ctx *Context) FillOutMemory() error {
	return ctx.Tracker.fillOutPtrArgs(ctx.Prog)
}
