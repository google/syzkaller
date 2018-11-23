// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package proggen

import (
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/tools/syz-trace2syz/parser"
)

func parseMemoryCall(ctx *Context) *prog.Call {
	syzCall := ctx.CurrentSyzCall
	straceCall := ctx.CurrentStraceCall

	switch straceCall.CallName {
	case "mmap":
		return parseMmap(syzCall.Meta, straceCall, ctx)
	case "mremap":
		return parseMremap(syzCall.Meta, straceCall, ctx)
	case "msync":
		return parseMsync(syzCall.Meta, straceCall, ctx)
	case "mprotect":
		return parseMprotect(syzCall.Meta, straceCall, ctx)
	case "munmap":
		return parseMunmap(syzCall.Meta, straceCall, ctx)
	case "madvise":
		return parseMadvise(syzCall.Meta, straceCall, ctx)
	case "mlock":
		return parseMlock(syzCall.Meta, straceCall, ctx)
	case "munlock":
		return parseMunlock(syzCall.Meta, straceCall, ctx)
	case "shmat":
		return parseShmat(syzCall.Meta, straceCall, ctx)
	}
	return nil
}

func parseMmap(mmap *prog.Syscall, syscall *parser.Syscall, ctx *Context) *prog.Call {
	call := &prog.Call{
		Meta: mmap,
		Ret:  prog.MakeReturnArg(mmap.Ret),
	}
	ctx.CurrentSyzCall = call
	pageSize := ctx.Target.PageSize

	length := (parseLength(syscall.Args[1], ctx) + pageSize - 1) / pageSize * pageSize // RoundUp PageSize
	log.Logf(3, "mmap call: %#v requires %d memory", syscall, length)
	addrArg, start := parseAddr(length, mmap.Args[0], syscall.Args[0], ctx)
	lengthArg := prog.MakeConstArg(mmap.Args[1], length)
	protArg := parseFlags(mmap.Args[2], syscall.Args[2], ctx, false)
	flagArg := parseFlags(mmap.Args[3], syscall.Args[3], ctx, true)
	fdArg := parseFd(mmap.Args[4], syscall.Args[4], ctx)

	call.Args = []prog.Arg{
		addrArg,
		lengthArg,
		protArg,
		flagArg,
		fdArg,
		prog.MakeConstArg(mmap.Args[5], 0),
	}
	ctx.Tracker.createMapping(call, len(ctx.Prog.Calls), call.Args[0], start, start+length)
	return call
}

func parseMremap(mremap *prog.Syscall, syscall *parser.Syscall, ctx *Context) *prog.Call {
	call := &prog.Call{
		Meta: mremap,
		Ret:  prog.MakeReturnArg(mremap.Ret),
	}
	ctx.CurrentSyzCall = call

	oldAddrArg, start := parseAddr(ctx.Target.PageSize, mremap.Args[0], syscall.Args[0], ctx)
	oldSz := parseLength(syscall.Args[1], ctx)
	newSz := parseLength(syscall.Args[2], ctx)
	oldSzArg := prog.MakeConstArg(mremap.Args[1], oldSz)
	newSzArg := prog.MakeConstArg(mremap.Args[2], newSz)
	flagArg := parseFlags(mremap.Args[3], syscall.Args[3], ctx, true)
	var destAddrArg prog.Arg
	var destAddr uint64
	if len(syscall.Args) > 4 {
		destAddrArg, destAddr = parseAddr(ctx.Target.PageSize, mremap.Args[4], syscall.Args[4], ctx)
	} else {
		straceAddrArg := parser.NewIntsType([]int64{syscall.Ret})
		destAddrArg, destAddr = parseAddr(ctx.Target.PageSize, mremap.Args[4], straceAddrArg, ctx)
	}
	addDependency(start, oldSz, oldAddrArg, ctx)
	call.Args = []prog.Arg{
		oldAddrArg,
		oldSzArg,
		newSzArg,
		flagArg,
		destAddrArg,
	}
	// All mmaps have fixed mappings in syzkaller
	ctx.Tracker.createMapping(call, len(ctx.Prog.Calls), call.Args[4], destAddr, destAddr+newSz)
	return call
}

func parseMsync(msync *prog.Syscall, syscall *parser.Syscall, ctx *Context) *prog.Call {
	var length uint64
	call := &prog.Call{
		Meta: msync,
		Ret:  prog.MakeReturnArg(msync.Ret),
	}
	ctx.CurrentSyzCall = call

	addrArg, address := parseAddr(ctx.Target.PageSize, msync.Args[0], syscall.Args[0], ctx)
	length = parseLength(syscall.Args[1], ctx)
	lengthArg := prog.MakeConstArg(msync.Args[1], length)
	protArg := parseFlags(msync.Args[2], syscall.Args[2], ctx, false)
	addDependency(address, length, addrArg, ctx)
	call.Args = []prog.Arg{
		addrArg,
		lengthArg,
		protArg,
	}
	return call
}

func parseMprotect(mprotect *prog.Syscall, syscall *parser.Syscall, ctx *Context) *prog.Call {
	call := &prog.Call{
		Meta: mprotect,
		Ret:  prog.MakeReturnArg(mprotect.Ret),
	}
	ctx.CurrentSyzCall = call

	addrArg, address := parseAddr(ctx.Target.PageSize, mprotect.Args[0], syscall.Args[0], ctx)
	length := parseLength(syscall.Args[1], ctx)
	lengthArg := prog.MakeConstArg(mprotect.Args[1], length)
	protArg := parseFlags(mprotect.Args[2], syscall.Args[2], ctx, false)
	addDependency(address, length, addrArg, ctx)
	call.Args = []prog.Arg{
		addrArg,
		lengthArg,
		protArg,
	}
	return call
}

func parseMunmap(munmap *prog.Syscall, syscall *parser.Syscall, ctx *Context) *prog.Call {
	call := &prog.Call{
		Meta: munmap,
		Ret:  prog.MakeReturnArg(munmap.Ret),
	}
	ctx.CurrentSyzCall = call

	addrArg, address := parseAddr(ctx.Target.PageSize, munmap.Args[0], syscall.Args[0], ctx)
	length := parseLength(syscall.Args[1], ctx)
	lengthArg := prog.MakeConstArg(munmap.Args[1], length)
	addDependency(address, length, addrArg, ctx)
	call.Args = []prog.Arg{
		addrArg,
		lengthArg,
	}
	return call
}

func parseMadvise(madvise *prog.Syscall, syscall *parser.Syscall, ctx *Context) *prog.Call {
	call := &prog.Call{
		Meta: madvise,
		Ret:  prog.MakeReturnArg(madvise.Ret),
	}
	ctx.CurrentSyzCall = call

	addrArg, address := parseAddr(ctx.Target.PageSize, madvise.Args[0], syscall.Args[0], ctx)
	length := parseLength(syscall.Args[1], ctx)
	lengthArg := prog.MakeConstArg(madvise.Args[1], length)
	var adviceArg prog.Arg
	switch a := syscall.Args[2].(type) {
	case parser.Expression:
		adviceArg = prog.MakeConstArg(madvise.Args[2], a.Eval(ctx.Target))
	default:
		log.Fatalf("Madvise advice arg is not expression")
	}
	addDependency(address, length, addrArg, ctx)
	call.Args = []prog.Arg{
		addrArg,
		lengthArg,
		adviceArg,
	}
	return call
}

func parseMlock(mlock *prog.Syscall, syscall *parser.Syscall, ctx *Context) *prog.Call {
	call := &prog.Call{
		Meta: mlock,
		Ret:  prog.MakeReturnArg(mlock.Ret),
	}
	ctx.CurrentSyzCall = call

	addrArg, address := parseAddr(ctx.Target.PageSize, mlock.Args[0], syscall.Args[0], ctx)
	length := parseLength(syscall.Args[1], ctx)
	flagArg := prog.MakeConstArg(mlock.Args[1], length)
	addDependency(address, length, addrArg, ctx)
	call.Args = []prog.Arg{
		addrArg,
		flagArg,
	}
	return call
}

func parseMunlock(munlock *prog.Syscall, syscall *parser.Syscall, ctx *Context) *prog.Call {
	call := &prog.Call{
		Meta: munlock,
		Ret:  prog.MakeReturnArg(munlock.Ret),
	}
	ctx.CurrentSyzCall = call
	addrArg, address := parseAddr(ctx.Target.PageSize, munlock.Args[0], syscall.Args[0], ctx)
	length := parseLength(syscall.Args[1], ctx)
	flagArg := prog.MakeConstArg(munlock.Args[1], length)
	addDependency(address, length, addrArg, ctx)
	call.Args = []prog.Arg{
		addrArg,
		flagArg,
	}
	return call
}

func parseShmat(shmat *prog.Syscall, syscall *parser.Syscall, ctx *Context) *prog.Call {
	// Shmat will create a shared memory map which we should track.
	// If the second argument is NULL then shmat will create the memory map and
	// store it at that address if successful.

	shmid := uint64(0)
	var fd prog.Arg

	call := &prog.Call{
		Meta: shmat,
		Ret:  prog.MakeReturnArg(shmat.Ret),
	}
	ctx.CurrentSyzCall = call

	if arg := ctx.ReturnCache.get(shmat.Args[0], syscall.Args[0]); arg != nil {
		switch a := arg.Type().(type) {
		case *prog.ResourceType:
			fd = prog.MakeResultArg(shmat.Args[0], arg.(*prog.ResultArg), a.Default())
		default:
			log.Fatalf("Expected first argument of Shmat to be resource type. Got: %s", a.Name())
		}
	} else {
		switch a := syscall.Args[0].(type) {
		case parser.Expression:
			shmid = a.Eval(ctx.Target)
		default:
			shmid = 0
		}
		fd = prog.MakeResultArg(shmat.Args[0], nil, shmid)
	}

	addrArg, address := parseAddr(ctx.Target.PageSize, shmat.Args[1], syscall.Args[1], ctx)
	flags := parseFlags(shmat.Args[2], syscall.Args[2], ctx, false)

	call.Args = []prog.Arg{
		fd,
		addrArg,
		flags,
	}
	// Cache the mapped address since it is a resource type as well
	call.Ret = prog.MakeReturnArg(shmat.Ret)
	straceRet := parser.NewIntsType([]int64{syscall.Ret})
	ctx.ReturnCache.cache(call.Ret.Type(), straceRet, call.Ret)

	length := uint64(4096)
	if req := ctx.Tracker.findShmRequest(shmid); req != nil {
		length = req.getSize()
	}
	ctx.Tracker.createMapping(call, len(ctx.Prog.Calls), call.Args[1], address, address+length)
	return call
}

func parseAddr(length uint64, syzType prog.Type, traceType parser.IrType, ctx *Context) (prog.Arg, uint64) {
	defAddrStart := (ctx.Target.NumPages - 2) * ctx.Target.PageSize
	switch a := traceType.(type) {
	case *parser.PointerType:
		var addrStart uint64
		if a.IsNull() {
			// Anonymous MMAP
			addrStart = uint64(ctx.CurrentStraceCall.Ret)
			return prog.MakeVmaPointerArg(syzType, defAddrStart, length), addrStart
		}
		return prog.MakeVmaPointerArg(syzType, defAddrStart, length), a.Address
	case parser.Expression:
		addrStart := a.Eval(ctx.Target)
		return prog.MakeVmaPointerArg(syzType, defAddrStart, length), addrStart
	default:
		log.Fatalf("Failed to parse mmap")
	}
	return nil, 0
}

func addDependency(start, length uint64, addr prog.Arg, ctx *Context) {
	if mapping := ctx.Tracker.findLatestOverlappingVMA(start); mapping != nil {
		dependsOn := make(map[*prog.Call]int)
		dependsOn[mapping.getCall()] = mapping.getCallIdx()
		for _, dep := range mapping.getUsedBy() {
			dependsOn[ctx.Prog.Calls[dep.Callidx]] = dep.Callidx
		}
		ctx.DependsOn[ctx.CurrentSyzCall] = dependsOn
		dep := newMemDependency(len(ctx.Prog.Calls), addr, start, start+length)
		mapping.addDependency(dep)
	}

}

func parseLength(straceType parser.IrType, ctx *Context) uint64 {
	switch a := straceType.(type) {
	case parser.Expression:
		return a.Eval(ctx.Target)
	default:
		log.Fatalf("Parsing Mmap length but type is not expression")
	}
	return 0
}

func parseFlags(syzType prog.Type, straceType parser.IrType, ctx *Context, mapFlag bool) prog.Arg {
	switch a := straceType.(type) {
	case parser.Expression:
		if mapFlag {
			val := a.Eval(ctx.Target)
			return prog.MakeConstArg(syzType, val)
		}
		return prog.MakeConstArg(syzType, a.Eval(ctx.Target))

	default:
		log.Fatalf("Parsing Flags")
	}
	return nil
}

func parseFd(syzType prog.Type, straceType parser.IrType, ctx *Context) prog.Arg {
	log.Logf(3, "Parsing file descriptor for call: %s", ctx.CurrentStraceCall.CallName)
	if arg := ctx.ReturnCache.get(syzType, straceType); arg != nil {
		log.Logf(3, "File descriptor: %s in the cache", straceType.String())
		switch a := syzType.(type) {
		case *prog.ResourceType:
			return prog.MakeResultArg(arg.Type(), arg.(*prog.ResultArg), a.Default())
		default:
			log.Fatalf("Parsing fd for memory call. Expected resource type. Got: %s", a.String())
		}
	}
	switch a := straceType.(type) {
	case parser.Expression:
		return prog.MakeResultArg(syzType, nil, a.Eval(ctx.Target))
	default:
		log.Fatalf("Failed to Parse Fd because type is not Expression")
	}
	return nil
}
