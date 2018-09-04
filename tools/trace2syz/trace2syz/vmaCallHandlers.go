package trace2syz

import (
	//"fmt"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
)

const (
	pageSize   = 4096
	MapFixed   = "MAP_FIXED"
	RemapFixed = "MREMAP_FIXED"
)

func ParseMemoryCall(ctx *Context) *prog.Call {
	syzCall := ctx.CurrentSyzCall
	straceCall := ctx.CurrentStraceCall
	if straceCall.CallName == "mmap" {
		return ParseMmap(syzCall.Meta, straceCall, ctx)
	} else if straceCall.CallName == "mremap" {
		return ParseMremap(syzCall.Meta, straceCall, ctx)
	} else if straceCall.CallName == "msync" {
		return ParseMsync(syzCall.Meta, straceCall, ctx)
	} else if straceCall.CallName == "mprotect" {
		return ParseMprotect(syzCall.Meta, straceCall, ctx)
	} else if straceCall.CallName == "munmap" {
		return ParseMunmap(syzCall.Meta, straceCall, ctx)
	} else if straceCall.CallName == "madvise" {
		return ParseMadvise(syzCall.Meta, straceCall, ctx)
	} else if straceCall.CallName == "mlock" {
		return ParseMlock(syzCall.Meta, straceCall, ctx)
	} else if straceCall.CallName == "munlock" {
		return ParseMunlock(syzCall.Meta, straceCall, ctx)
	} else if straceCall.CallName == "shmat" {
		return ParseShmat(syzCall.Meta, straceCall, ctx)
	}
	return nil
}

func ParseMmap(mmap *prog.Syscall, syscall *Syscall, ctx *Context) *prog.Call {
	call := &prog.Call{
		Meta: mmap,
		Ret:  prog.MakeReturnArg(mmap.Ret),
	}
	ctx.CurrentSyzCall = call

	length := (ParseLength(syscall.Args[1], ctx)/pageSize + 1) * pageSize
	log.Logf(3, "mmap call: %#v requires %d memory", syscall, length)
	addrArg, start := ParseAddr(length, mmap.Args[0], syscall.Args[0], ctx)
	lengthArg := prog.MakeConstArg(mmap.Args[1], length)
	protArg := ParseFlags(mmap.Args[2], syscall.Args[2], ctx, false)
	flagArg := ParseFlags(mmap.Args[3], syscall.Args[3], ctx, true)
	fdArg := ParseFd(mmap.Args[4], syscall.Args[4], ctx)

	call.Args = []prog.Arg{
		addrArg,
		lengthArg,
		protArg,
		flagArg,
		fdArg,
		prog.MakeConstArg(mmap.Args[5], 0),
	}
	//All mmaps have fixed mappings in syzkaller
	ctx.State.Tracker.createMapping(call, len(ctx.Prog.Calls), call.Args[0], start, start+length)
	return call
}

func ParseMremap(mremap *prog.Syscall, syscall *Syscall, ctx *Context) *prog.Call {
	call := &prog.Call{
		Meta: mremap,
		Ret:  prog.MakeReturnArg(mremap.Ret),
	}
	ctx.CurrentSyzCall = call

	oldAddrArg, start := ParseAddr(pageSize, mremap.Args[0], syscall.Args[0], ctx)
	oldSz := ParseLength(syscall.Args[1], ctx)
	newSz := ParseLength(syscall.Args[2], ctx)
	oldSzArg := prog.MakeConstArg(mremap.Args[1], oldSz)
	newSzArg := prog.MakeConstArg(mremap.Args[2], newSz)
	flagArg := ParseFlags(mremap.Args[3], syscall.Args[3], ctx, true)
	var destAddrArg prog.Arg
	var destAddr uint64
	if len(syscall.Args) > 4 {
		destAddrArg, destAddr = ParseAddr(pageSize, mremap.Args[4], syscall.Args[4], ctx)
	} else {
		straceAddrArg := newExpression(newIntType(syscall.Ret))
		destAddrArg, destAddr = ParseAddr(pageSize, mremap.Args[4], straceAddrArg, ctx)
	}
	AddDependency(start, oldSz, oldAddrArg, ctx)
	call.Args = []prog.Arg{
		oldAddrArg,
		oldSzArg,
		newSzArg,
		flagArg,
		destAddrArg,
	}
	//All mmaps have fixed mappings in syzkaller
	ctx.State.Tracker.createMapping(call, len(ctx.Prog.Calls), call.Args[4], destAddr, destAddr+newSz)
	return call
}

func ParseMsync(msync *prog.Syscall, syscall *Syscall, ctx *Context) *prog.Call {
	var length uint64
	call := &prog.Call{
		Meta: msync,
		Ret:  prog.MakeReturnArg(msync.Ret),
	}
	ctx.CurrentSyzCall = call

	addrArg, address := ParseAddr(pageSize, msync.Args[0], syscall.Args[0], ctx)
	length = ParseLength(syscall.Args[1], ctx)
	lengthArg := prog.MakeConstArg(msync.Args[1], length)
	protArg := ParseFlags(msync.Args[2], syscall.Args[2], ctx, false)
	AddDependency(address, length, addrArg, ctx)
	call.Args = []prog.Arg{
		addrArg,
		lengthArg,
		protArg,
	}
	return call
}

func ParseMprotect(mprotect *prog.Syscall, syscall *Syscall, ctx *Context) *prog.Call {
	call := &prog.Call{
		Meta: mprotect,
		Ret:  prog.MakeReturnArg(mprotect.Ret),
	}
	ctx.CurrentSyzCall = call

	addrArg, address := ParseAddr(pageSize, mprotect.Args[0], syscall.Args[0], ctx)
	length := ParseLength(syscall.Args[1], ctx)
	lengthArg := prog.MakeConstArg(mprotect.Args[1], length)
	protArg := ParseFlags(mprotect.Args[2], syscall.Args[2], ctx, false)
	AddDependency(address, length, addrArg, ctx)
	call.Args = []prog.Arg{
		addrArg,
		lengthArg,
		protArg,
	}
	return call
}

func ParseMunmap(munmap *prog.Syscall, syscall *Syscall, ctx *Context) *prog.Call {
	call := &prog.Call{
		Meta: munmap,
		Ret:  prog.MakeReturnArg(munmap.Ret),
	}
	ctx.CurrentSyzCall = call

	addrArg, address := ParseAddr(pageSize, munmap.Args[0], syscall.Args[0], ctx)
	length := ParseLength(syscall.Args[1], ctx)
	lengthArg := prog.MakeConstArg(munmap.Args[1], length)
	AddDependency(address, length, addrArg, ctx)
	call.Args = []prog.Arg{
		addrArg,
		lengthArg,
	}
	return call
}

func ParseMadvise(madvise *prog.Syscall, syscall *Syscall, ctx *Context) *prog.Call {
	call := &prog.Call{
		Meta: madvise,
		Ret:  prog.MakeReturnArg(madvise.Ret),
	}
	ctx.CurrentSyzCall = call

	addrArg, address := ParseAddr(pageSize, madvise.Args[0], syscall.Args[0], ctx)
	length := ParseLength(syscall.Args[1], ctx)
	lengthArg := prog.MakeConstArg(madvise.Args[1], length)
	var adviceArg prog.Arg
	switch a := syscall.Args[2].(type) {
	case *expression:
		adviceArg = prog.MakeConstArg(madvise.Args[2], a.Eval(ctx.Target))
	default:
		panic("Madvise advice arg is not expression")
	}
	AddDependency(address, length, addrArg, ctx)
	call.Args = []prog.Arg{
		addrArg,
		lengthArg,
		adviceArg,
	}
	return call
}

func ParseMlock(mlock *prog.Syscall, syscall *Syscall, ctx *Context) *prog.Call {
	call := &prog.Call{
		Meta: mlock,
		Ret:  prog.MakeReturnArg(mlock.Ret),
	}
	ctx.CurrentSyzCall = call

	addrArg, address := ParseAddr(pageSize, mlock.Args[0], syscall.Args[0], ctx)
	length := ParseLength(syscall.Args[1], ctx)
	flagArg := prog.MakeConstArg(mlock.Args[1], length)
	AddDependency(address, length, addrArg, ctx)
	call.Args = []prog.Arg{
		addrArg,
		flagArg,
	}
	return call
}

func ParseMunlock(munlock *prog.Syscall, syscall *Syscall, ctx *Context) *prog.Call {
	call := &prog.Call{
		Meta: munlock,
		Ret:  prog.MakeReturnArg(munlock.Ret),
	}
	ctx.CurrentSyzCall = call
	addrArg, address := ParseAddr(pageSize, munlock.Args[0], syscall.Args[0], ctx)
	length := ParseLength(syscall.Args[1], ctx)
	flagArg := prog.MakeConstArg(munlock.Args[1], length)
	AddDependency(address, length, addrArg, ctx)
	call.Args = []prog.Arg{
		addrArg,
		flagArg,
	}
	return call
}

func ParseShmat(shmat *prog.Syscall, syscall *Syscall, ctx *Context) *prog.Call {
	/*
	* Shmat will create a shared memory map which we should track.
	* If the second argument is NULL then shmat will create the memory map and
	* store it at that address if successful.
	 */

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
			log.Fatalf("Expected first argument of Shmat to be resource type. Got: %s\n", a.Name())
		}
	} else {
		switch a := syscall.Args[0].(type) {
		case *expression:
			shmid = a.Eval(ctx.Target)
		default:
			shmid = 0
		}
		fd = prog.MakeResultArg(shmat.Args[0], nil, shmid)
	}

	addrArg, address := ParseAddr(pageSize, shmat.Args[1], syscall.Args[1], ctx)
	flags := ParseFlags(shmat.Args[2], syscall.Args[2], ctx, false)

	call.Args = []prog.Arg{
		fd,
		addrArg,
		flags,
	}
	//Cache the mapped address since it is a resource type as well
	call.Ret = prog.MakeReturnArg(shmat.Ret)
	straceRet := newExpression(newIntType(syscall.Ret))
	ctx.ReturnCache.cache(call.Ret.Type(), straceRet, call.Ret)

	length := uint64(4096)
	if req := ctx.State.Tracker.findShmRequest(shmid); req != nil {
		length = req.getSize()
	}
	ctx.State.Tracker.createMapping(call, len(ctx.Prog.Calls), call.Args[1], address, address+length)
	return call
}

func ParseAddr(length uint64, syzType prog.Type, traceType irType, ctx *Context) (prog.Arg, uint64) {
	defAddrStart := (ctx.Target.NumPages - 2) * ctx.Target.PageSize
	switch a := traceType.(type) {
	case *pointerType:
		var addrStart uint64
		if a.IsNull() {
			//Anonymous MMAP
			addrStart = uint64(ctx.CurrentStraceCall.Ret)
			return prog.MakeVmaPointerArg(syzType, defAddrStart, length), addrStart
		}
		return prog.MakeVmaPointerArg(syzType, defAddrStart, length), a.Address
	case *expression:
		addrStart := a.Eval(ctx.Target)
		return prog.MakeVmaPointerArg(syzType, defAddrStart, length), addrStart
	default:
		panic("Failed to parse mmap")
	}
}

func AddDependency(start, length uint64, addr prog.Arg, ctx *Context) {
	if mapping := ctx.State.Tracker.findLatestOverlappingVMA(start); mapping != nil {
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

func ParseLength(straceType irType, ctx *Context) uint64 {
	switch a := straceType.(type) {
	case *expression:
		return a.Eval(ctx.Target)
	default:
		panic("Parsing Mmap length but type is not expression")
	}
}

func ParseFlags(syzType prog.Type, straceType irType, ctx *Context, mapFlag bool) prog.Arg {
	switch a := straceType.(type) {
	case *expression:
		if mapFlag {
			val := a.Eval(ctx.Target) | GetFixedFlag(ctx)
			return prog.MakeConstArg(syzType, val)
		}
		return prog.MakeConstArg(syzType, a.Eval(ctx.Target))

	default:
		panic("Parsing Flags")
	}
}

func ParseFd(syzType prog.Type, straceType irType, ctx *Context) prog.Arg {
	log.Logf(3, "Parsing file descriptor for call: %s\n", ctx.CurrentStraceCall.CallName)
	if arg := ctx.ReturnCache.get(syzType, straceType); arg != nil {
		log.Logf(3, "File descriptor: %s in the cache\n", straceType.String())
		switch a := syzType.(type) {
		case *prog.ResourceType:
			return prog.MakeResultArg(arg.Type(), arg.(*prog.ResultArg), a.Default())
		default:
			log.Fatalf("Parsing fd for memory call. Expected resource type. Got: %s", a.String())
		}
	}
	switch a := straceType.(type) {
	case *expression:
		return prog.MakeResultArg(syzType, nil, a.Eval(ctx.Target))
	default:
		panic("Failed to Parse Fd because type is not Expression")
	}
}

func GetFixedFlag(ctx *Context) uint64 {
	callName := ctx.CurrentStraceCall.CallName
	if callName == "mmap" {
		return ctx.Target.ConstMap[MapFixed]
	}
	return ctx.Target.ConstMap[RemapFixed]
}
