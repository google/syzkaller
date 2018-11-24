// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package proggen

import (
	"encoding/binary"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/tools/syz-trace2syz/config"
	"github.com/google/syzkaller/tools/syz-trace2syz/parser"
	"math/rand"
)

type returnCache map[resourceDescription]prog.Arg

func newRCache() returnCache {
	return make(map[resourceDescription]prog.Arg)
}

func (r *returnCache) buildKey(syzType prog.Type) string {
	switch a := syzType.(type) {
	case *prog.ResourceType:
		return "ResourceType-" + a.Desc.Kind[0]
	default:
		log.Fatalf("Caching non resource type")
	}
	return ""
}

func (r *returnCache) cache(syzType prog.Type, traceType parser.IrType, arg prog.Arg) {
	log.Logf(2, "Caching resource type: %s, val: %s", r.buildKey(syzType), traceType.String())
	resDesc := resourceDescription{
		Type: r.buildKey(syzType),
		Val:  traceType.String(),
	}
	(*r)[resDesc] = arg
}

func (r *returnCache) get(syzType prog.Type, traceType parser.IrType) prog.Arg {
	log.Logf(2, "Fetching resource type: %s, val: %s", r.buildKey(syzType), traceType.String())
	resDesc := resourceDescription{
		Type: r.buildKey(syzType),
		Val:  traceType.String(),
	}
	if arg, ok := (*r)[resDesc]; ok {
		if arg != nil {
			log.Logf(2, "Cache hit for resource type: %s, val: %s", r.buildKey(syzType), traceType.String())
			return arg
		}
	}
	return nil
}

type resourceDescription struct {
	Type string
	Val  string
}

// Context stores metadata related to a syzkaller program

type Context struct {
	ReturnCache       returnCache
	Prog              *prog.Prog
	CurrentStraceCall *parser.Syscall
	CurrentSyzCall    *prog.Call
	CurrentStraceArg  parser.IrType
	Target            *prog.Target
	Tracker           *memoryTracker
	CallToCover       map[*prog.Call][]uint64
	CallSelector      *CallSelector
	// DependsOn field maps a call to all upstream dependencies
	// It is used to track dependencies which cannot be captured by resultArg such as VMAs mmap -> mlock -> mremap
	// Values of this map are all the calls which are the dependencies of the corresponding key
	// We encode the values in a map because the map[*prog.Call]int maps the call to its index in prog.Calls
	DependsOn map[*prog.Call]map[*prog.Call]int
}

func newContext(target *prog.Target, selector *CallSelector) (ctx *Context) {
	ctx = &Context{}
	ctx.ReturnCache = newRCache()
	ctx.CurrentStraceCall = nil
	ctx.Tracker = newTracker()
	ctx.CurrentStraceArg = nil
	ctx.Target = target
	ctx.CallSelector = selector
	ctx.CallToCover = make(map[*prog.Call][]uint64)
	ctx.DependsOn = make(map[*prog.Call]map[*prog.Call]int)
	return
}

// FillOutMemory determines how much memory to allocate for arguments in a program
// And generates an mmap c to do the allocation.This mmap is prepended to prog.Calls
func (ctx *Context) FillOutMemory() error {
	return ctx.Tracker.fillOutMemory(ctx.Prog)
}

// GenSyzProg converts a trace to one of our programs
func GenSyzProg(trace *parser.Trace, target *prog.Target, selector *CallSelector) *Context {
	syzProg := new(prog.Prog)
	syzProg.Target = target
	ctx := newContext(target, selector)
	ctx.Prog = syzProg
	var call *prog.Call
	for _, sCall := range trace.Calls {
		if sCall.Paused {
			// Probably a case where the call was killed by a signal like the following
			// 2179  wait4(2180,  <unfinished ...>
			// 2179  <... wait4 resumed> 0x7fff28981bf8, 0, NULL) = ? ERESTARTSYS
			// 2179  --- SIGUSR1 {si_signo=SIGUSR1, si_code=SI_USER, si_pid=2180, si_uid=0} ---
			continue
		}
		ctx.CurrentStraceCall = sCall

		if shouldSkip(ctx) {
			log.Logf(2, "Skipping call: %s", ctx.CurrentStraceCall.CallName)
			continue
		}
		if call = genCall(ctx); call == nil {
			continue
		}

		ctx.CallToCover[call] = sCall.Cover
		ctx.Target.AssignSizesCall(call)
		syzProg.Calls = append(syzProg.Calls, call)
	}
	return ctx
}

func genCall(ctx *Context) *prog.Call {
	log.Logf(3, "parsing call: %s", ctx.CurrentStraceCall.CallName)
	straceCall := ctx.CurrentStraceCall
	syzCall := new(prog.Call)
	syzCall.Meta = ctx.CallSelector.Select(ctx, straceCall)
	ctx.CurrentSyzCall = syzCall
	if ctx.CurrentSyzCall.Meta == nil {
		log.Logf(2, "Call: %s has no matching description. Skipping", ctx.CurrentStraceCall.CallName)
		return nil
	}
	syzCall.Ret = prog.MakeReturnArg(ctx.CurrentSyzCall.Meta.Ret)

	for i := range syzCall.Meta.Args {
		var strArg parser.IrType
		if i < len(straceCall.Args) {
			strArg = straceCall.Args[i]
		}
		res := genArgs(syzCall.Meta.Args[i], strArg, ctx)
		syzCall.Args = append(syzCall.Args, res)
	}
	genResult(syzCall.Meta.Ret, straceCall.Ret, ctx)
	ctx.Target.SanitizeCall(syzCall)
	return syzCall
}

func genResult(syzType prog.Type, straceRet int64, ctx *Context) {
	if straceRet > 0 {
		straceExpr := parser.NewIntsType([]int64{straceRet})
		switch syzType.(type) {
		case *prog.ResourceType:
			log.Logf(2, "Call: %s returned a resource type with val: %s",
				ctx.CurrentStraceCall.CallName, straceExpr.String())
			ctx.ReturnCache.cache(syzType, straceExpr, ctx.CurrentSyzCall.Ret)
		}
	}
}

func genArgs(syzType prog.Type, traceArg parser.IrType, ctx *Context) prog.Arg {
	if traceArg == nil {
		log.Logf(3, "Parsing syzType: %s, traceArg is nil. Generating default arg...", syzType.Name())
		return prog.DefaultArg(syzType)
	}
	ctx.CurrentStraceArg = traceArg
	log.Logf(3, "Parsing Arg of syz type: %s, ir type: %#v", syzType.Name(), traceArg)

	switch a := syzType.(type) {
	case *prog.IntType, *prog.ConstType, *prog.FlagsType, *prog.CsumType:
		return genConst(a, traceArg, ctx)
	case *prog.LenType:
		return prog.DefaultArg(syzType)
	case *prog.ProcType:
		return parseProc(a, traceArg, ctx)
	case *prog.ResourceType:
		return genResource(a, traceArg, ctx)
	case *prog.PtrType:
		return genPtr(a, traceArg, ctx)
	case *prog.BufferType:
		return genBuffer(a, traceArg, ctx)
	case *prog.StructType:
		return genStruct(a, traceArg, ctx)
	case *prog.ArrayType:
		return genArray(a, traceArg, ctx)
	case *prog.UnionType:
		return genUnionArg(a, traceArg, ctx)
	case *prog.VmaType:
		return genVma(a, traceArg, ctx)
	default:
		log.Fatalf("Unsupported  Type: %v", syzType)
	}
	return nil
}

func genVma(syzType *prog.VmaType, traceType parser.IrType, ctx *Context) prog.Arg {
	var npages uint64 = 1
	if syzType.RangeBegin != 0 || syzType.RangeEnd != 0 {
		npages = syzType.RangeEnd
	}
	arg := prog.MakeVmaPointerArg(syzType, 0, npages)
	ctx.Tracker.addAllocation(ctx.CurrentSyzCall, ctx.Target.PageSize, arg)
	return arg
}

func genArray(syzType *prog.ArrayType, traceType parser.IrType, ctx *Context) prog.Arg {
	var args []prog.Arg
	switch a := traceType.(type) {
	case *parser.GroupType:
		for i := 0; i < len(a.Elems); i++ {
			args = append(args, genArgs(syzType.Type, a.Elems[i], ctx))
		}
	case *parser.PointerType, parser.Expression, *parser.BufferType:
		return prog.DefaultArg(syzType)
	default:
		log.Fatalf("Error parsing Array: %s with Wrong Type: %#v", syzType.FldName, traceType)
	}
	return prog.MakeGroupArg(syzType, args)
}

func genStruct(syzType *prog.StructType, traceType parser.IrType, ctx *Context) prog.Arg {
	args := make([]prog.Arg, 0)
	switch a := traceType.(type) {
	case *parser.GroupType:
		j := 0
		reorderStructFields(syzType, a, ctx)
		for i := range syzType.Fields {
			if prog.IsPad(syzType.Fields[i]) {
				args = append(args, prog.DefaultArg(syzType.Fields[i]))
				continue
			}
			// If the last n fields of a struct are zero or NULL, strace will occasionally omit those values
			// this creates a mismatch in the number of elements in the ir type and in
			// our descriptions. We generate default values for omitted fields
			if j >= len(a.Elems) {
				args = append(args, prog.DefaultArg(syzType.Fields[i]))
			} else {
				args = append(args, genArgs(syzType.Fields[i], a.Elems[j], ctx))
			}
			j++
		}
	case parser.Expression, *parser.BufferType:
		return prog.DefaultArg(syzType)
	default:
		log.Fatalf("Unsupported Strace Type: %#v to Struct Type", a)
	}
	return prog.MakeGroupArg(syzType, args)
}

func genUnionArg(syzType *prog.UnionType, straceType parser.IrType, ctx *Context) prog.Arg {
	if straceType == nil {
		log.Logf(1, "Generating union arg. StraceType is nil")
		return prog.DefaultArg(syzType)
	}
	log.Logf(4, "Generating union arg: %s %#v", syzType.TypeName, straceType)
	// Unions are super annoying because they sometimes need to be handled case by case
	// We might need to lookinto a matching algorithm to identify the union type that most closely
	// matches our strace type

	switch syzType.TypeName {
	case "ipv4_addr":
		return genIpv4Addr(syzType, straceType, ctx)
	case "ipv6_addr":
		return genIpv6Addr(syzType, straceType, ctx)
	case "sockaddr_storage":
		return genSockaddrStorage(syzType, straceType, ctx)
	case "sockaddr_nl":
		return genSockaddrNetlink(syzType, straceType, ctx)
	case "ifr_ifru":
		return genIfrIfru(syzType, straceType, ctx)
	case "ifconf":
		return genIfconf(syzType, straceType, ctx)
	}
	return prog.MakeUnionArg(syzType, genArgs(syzType.Fields[0], straceType, ctx))
}

func genBuffer(syzType *prog.BufferType, traceType parser.IrType, ctx *Context) prog.Arg {
	if syzType.Dir() == prog.DirOut {
		if !syzType.Varlen() {
			return prog.MakeOutDataArg(syzType, syzType.Size())
		}
		switch a := traceType.(type) {
		case *parser.BufferType:
			return prog.MakeOutDataArg(syzType, uint64(len(a.Val)))
		default:
			switch syzType.Kind {
			case prog.BufferBlobRand:
				size := rand.Intn(256)
				return prog.MakeOutDataArg(syzType, uint64(size))

			case prog.BufferBlobRange:
				max := rand.Intn(int(syzType.RangeEnd) - int(syzType.RangeBegin) + 1)
				size := max + int(syzType.RangeBegin)
				return prog.MakeOutDataArg(syzType, uint64(size))
			default:
				log.Fatalf("unexpected buffer type kind: %v. call %v arg %#v", syzType.Kind, ctx.CurrentSyzCall, traceType)
			}
		}
	}
	var bufVal []byte
	switch a := traceType.(type) {
	case *parser.BufferType:
		bufVal = []byte(a.Val)
	case parser.Expression:
		val := a.Eval(ctx.Target)
		bArr := make([]byte, 8)
		binary.LittleEndian.PutUint64(bArr, val)
		bufVal = bArr
	case *parser.PointerType:
		val := a.Address
		bArr := make([]byte, 8)
		binary.LittleEndian.PutUint64(bArr, val)
		bufVal = bArr
	case *parser.GroupType:
		return prog.DefaultArg(syzType)
	default:
		log.Fatalf("Cannot parse type %#v for Buffer Type", traceType)
	}
	if !syzType.Varlen() {
		size := syzType.Size()
		for uint64(len(bufVal)) < size {
			bufVal = append(bufVal, 0)
		}
		bufVal = bufVal[:size]
	}
	return prog.MakeDataArg(syzType, bufVal)
}

func genPtr(syzType *prog.PtrType, traceType parser.IrType, ctx *Context) prog.Arg {
	switch a := traceType.(type) {
	case *parser.PointerType:
		if a.IsNull() {
			return prog.MakeSpecialPointerArg(syzType, 0)
		}
		if a.Res == nil {
			// sometimes strace will return an empty pointer
			// We just generate the default arg
			res := prog.DefaultArg(syzType.Type)
			return addr(ctx, syzType, res.Size(), res)
		}
		res := genArgs(syzType.Type, a.Res, ctx)
		return addr(ctx, syzType, res.Size(), res)

	case parser.Expression:
		// Likely have a type of the form bind(3, 0xfffffffff, [3]);
		res := prog.DefaultArg(syzType.Type)
		return addr(ctx, syzType, res.Size(), res)
	default:
		res := genArgs(syzType.Type, a, ctx)
		return addr(ctx, syzType, res.Size(), res)
	}
}

func genConst(syzType prog.Type, traceType parser.IrType, ctx *Context) prog.Arg {
	if syzType.Dir() == prog.DirOut {
		return prog.DefaultArg(syzType)
	}
	switch a := traceType.(type) {
	case parser.Expression:
		switch b := a.(type) {
		case parser.Ints:
			if len(b) >= 2 {
				// May get here through select. E.g. select(2, [6, 7], ..) since Expression can
				// be Ints. However, creating fd set is hard and we let default arg through
				return prog.DefaultArg(syzType)
			}
		}
		return prog.MakeConstArg(syzType, a.Eval(ctx.Target))
	case *parser.GroupType:
		// Sometimes strace represents a pointer to int as [0] which gets parsed
		// as Array([0], len=1). A good example is ioctl(3, FIONBIO, [1]). We may also have an union int type that
		// is a represented as a struct in strace e.g.
		// sigev_value={sival_int=-2123636944, sival_ptr=0x7ffd816bdf30}
		// For now we choose the first option
		if len(a.Elems) == 0 {
			log.Logf(2, "Parsing const type. Got array type with len 0")
			return prog.DefaultArg(syzType)
		}
		return genConst(syzType, a.Elems[0], ctx)
	case *parser.BufferType:
		// The call almost certainly an error or missing fields
		return prog.DefaultArg(syzType)
		// E.g. ltp_bind01 two arguments are empty and
	case *parser.PointerType:
		// This can be triggered by the following:
		// 2435  connect(3, {sa_family=0x2f ,..., 16)
		return prog.MakeConstArg(syzType, a.Address)
	default:
		log.Fatalf("Cannot convert Strace Type: %#v to Const Type", traceType)
	}
	return nil
}

func genResource(syzType *prog.ResourceType, traceType parser.IrType, ctx *Context) prog.Arg {
	if syzType.Dir() == prog.DirOut {
		log.Logf(2, "Resource returned by call argument: %s", traceType.String())
		res := prog.MakeResultArg(syzType, nil, syzType.Default())
		ctx.ReturnCache.cache(syzType, traceType, res)
		return res
	}
	switch a := traceType.(type) {
	case parser.Expression:
		val := a.Eval(ctx.Target)
		if arg := ctx.ReturnCache.get(syzType, traceType); arg != nil {
			res := prog.MakeResultArg(syzType, arg.(*prog.ResultArg), syzType.Default())
			return res
		}
		// May get a resource type like ifindex which is returned by ioctl$SIOCGIFINDEX
		// but strace converts the value to a call type like if_nametoindex which is hard to evaluate
		// for now we just use the value "as-is". We may try to find the type in the result cache which most closely
		// matches our resource type
		res := prog.MakeResultArg(syzType, nil, val)
		return res
	case *parser.PointerType:
		return prog.MakeResultArg(syzType, nil, 0)
	case *parser.GroupType:
		if len(a.Elems) == 1 {
			// For example: 5028  ioctl(3, SIOCSPGRP, [0])          = 0
			// last argument is a pointer to a resource. Strace will output a pointer to
			// a number x as [x]. When we parse we cannot distinguish this case from a pointer to a pointer.
			// It only matters if the value is resource AFAWCT
			res := prog.MakeResultArg(syzType, nil, syzType.Default())
			ctx.ReturnCache.cache(syzType, a.Elems[0], res)
			return res
		}
		log.Fatalf("Generating resource type from GroupType with %d elements", len(a.Elems))
	default:
		log.Fatalf("Resource Type only supports Expression")
	}
	return nil
}

func parseProc(syzType *prog.ProcType, traceType parser.IrType, ctx *Context) prog.Arg {
	if syzType.Dir() == prog.DirOut {
		return prog.DefaultArg(syzType)
	}
	switch a := traceType.(type) {
	case parser.Expression:
		val := a.Eval(ctx.Target)
		if val >= syzType.ValuesPerProc {
			return prog.MakeConstArg(syzType, syzType.ValuesPerProc-1)
		}
		return prog.MakeConstArg(syzType, val)
	case *parser.BufferType:
		// Again probably an error case
		// Something like the following will trigger this
		// bind(3, {sa_family=AF_INET, sa_data="\xac"}, 3) = -1 EINVAL(Invalid argument)
		return prog.DefaultArg(syzType)
	default:
		log.Fatalf("Unsupported Type for Proc: %#v", traceType)
	}
	return nil
}

func addr(ctx *Context, syzType prog.Type, size uint64, data prog.Arg) prog.Arg {
	arg := prog.MakePointerArg(syzType, uint64(0), data)
	ctx.Tracker.addAllocation(ctx.CurrentSyzCall, size, arg)
	return arg
}

func reorderStructFields(syzType *prog.StructType, traceType *parser.GroupType, ctx *Context) {
	// Sometimes strace reports struct fields out of order compared to our descriptions
	// Example: 5704  bind(3, {sa_family=AF_INET6,
	//				sin6_port=htons(8888),
	//				inet_pton(AF_INET6, "::", &sin6_addr),
	//				sin6_flowinfo=htonl(2206138368),
	//				sin6_scope_id=2049825634}, 128) = 0
	//	The flow_info and pton fields are switched in our description

	switch syzType.TypeName {
	case "sockaddr_in6":
		log.Logf(5, "Reordering in6. Num Elems: %d", len(traceType.Elems))
		if len(traceType.Elems) < 4 {
			return
		}
		field2 := traceType.Elems[2]
		traceType.Elems[2] = traceType.Elems[3]
		traceType.Elems[3] = field2
		// TODO: Add more cases for BPF structs
	}
}

func shouldSkip(ctx *Context) bool {
	syscall := ctx.CurrentStraceCall
	if config.ShouldSkip[syscall.CallName] {
		return true
	}
	switch syscall.CallName {
	case "write":
		// We skip all writes to stdout and stderr because they can corrupt our crash summary
		switch a := syscall.Args[0].(type) {
		case parser.Expression:
			val := a.Eval(ctx.Target)
			if val == 1 || val == 2 {
				return true
			}
		}
	}
	return false
}
