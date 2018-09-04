package trace2syz

import (
	"encoding/binary"
	"fmt"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
	"math/rand"
	"strings"
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
		panic("Caching non resource type")
	}
}

func (r *returnCache) cache(syzType prog.Type, traceType irType, arg prog.Arg) {
	log.Logf(2, "Caching resource type: %s, val: %s\n", r.buildKey(syzType), traceType.String())
	resDesc := resourceDescription{
		Type: r.buildKey(syzType),
		Val:  traceType.String(),
	}
	(*r)[resDesc] = arg
}

func (r *returnCache) get(syzType prog.Type, traceType irType) prog.Arg {
	log.Logf(2, "Fetching resource type: %s, val: %s\n", r.buildKey(syzType), traceType.String())
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

//Context stores metadata related to a syzkaller program
//Currently we are embedding the State object within the Context.
// We should probably merge the two objects
type Context struct {
	ReturnCache       returnCache
	Prog              *prog.Prog
	CurrentStraceCall *Syscall
	CurrentSyzCall    *prog.Call
	CurrentStraceArg  irType
	State             *State
	Target            *prog.Target
	CallToCover       map[*prog.Call][]uint64
	DependsOn         map[*prog.Call]map[*prog.Call]int
}

func newContext(target *prog.Target) (ctx *Context) {
	ctx = &Context{}
	ctx.ReturnCache = newRCache()
	ctx.CurrentStraceCall = nil
	ctx.State = newState(target)
	ctx.CurrentStraceArg = nil
	ctx.Target = target
	ctx.CallToCover = make(map[*prog.Call][]uint64)
	ctx.DependsOn = make(map[*prog.Call]map[*prog.Call]int)
	return
}

func (ctx *Context) FillOutMemory() error {
	if err := ctx.State.Tracker.fillOutMemory(ctx.Prog); err != nil {
		return err
	}
	totalMemory := ctx.State.Tracker.getTotalMemoryAllocations(ctx.Prog)
	log.Logf(2, "Total memory for program is: %d\n", totalMemory)
	if totalMemory == 0 {
		return fmt.Errorf("length of zero mem prog: %d", totalMemory)
	}
	mmapCall := ctx.Target.MakeMmap(0, totalMemory)
	calls := make([]*prog.Call, 0)
	calls = append(append(calls, mmapCall), ctx.Prog.Calls...)
	ctx.Prog.Calls = calls
	return nil
}

//ParseTrace converts a trace to a syzkaller program
func ParseTrace(trace *Trace, target *prog.Target) (*Context, error) {
	syzProg := new(prog.Prog)
	syzProg.Target = target
	ctx := newContext(target)
	ctx.Prog = syzProg
	for _, sCall := range trace.Calls {
		ctx.CurrentStraceCall = sCall
		if _, ok := unsupported[sCall.CallName]; ok {
			continue
		}
		if sCall.Paused {
			/*Probably a case where the call was killed by a signal like the following
			2179  wait4(2180,  <unfinished ...>
			2179  <... wait4 resumed> 0x7fff28981bf8, 0, NULL) = ? ERESTARTSYS
			2179  --- SIGUSR1 {si_signo=SIGUSR1, si_code=SI_USER, si_pid=2180, si_uid=0} ---
			*/
			continue
		}
		ctx.CurrentStraceCall = sCall

		if shouldSkip(ctx) {
			log.Logf(3, "Skipping call: %s\n", ctx.CurrentStraceCall.CallName)
			continue
		}
		if call, err := parseCall(ctx); err == nil {
			if call == nil {
				continue
			}
			ctx.CallToCover[call] = sCall.Cover
			ctx.State.analyze(call)
			ctx.Target.AssignSizesCall(call)
			syzProg.Calls = append(syzProg.Calls, call)
		} else {
			log.Fatalf("Failed to parse call: %s\n", sCall.CallName)
		}
	}
	return ctx, nil
}

func parseCall(ctx *Context) (*prog.Call, error) {
	log.Logf(2, "parsing call: %s\n", ctx.CurrentStraceCall.CallName)
	straceCall := ctx.CurrentStraceCall
	syzCallDef := ctx.Target.SyscallMap[straceCall.CallName]
	retCall := new(prog.Call)
	retCall.Meta = syzCallDef
	ctx.CurrentSyzCall = retCall

	preprocess(ctx)
	if ctx.CurrentSyzCall.Meta == nil {
		//A call like fcntl may have variants like fcntl$get_flag
		//but no generic fcntl system call in Syzkaller
		return nil, nil
	}
	retCall.Ret = prog.MakeReturnArg(ctx.CurrentSyzCall.Meta.Ret)

	if call := ParseMemoryCall(ctx); call != nil {
		return call, nil
	}
	for i := range retCall.Meta.Args {
		var strArg irType
		if i < len(straceCall.Args) {
			strArg = straceCall.Args[i]
		}
		if arg, err := parseArgs(retCall.Meta.Args[i], strArg, ctx); err != nil {
			log.Fatalf("Failed to parse arg: %s\n", err.Error())
		} else {
			retCall.Args = append(retCall.Args, arg)
		}
		//arg := syzCall.Args[i]
	}
	parseResult(retCall.Meta.Ret, straceCall.Ret, ctx)

	return retCall, nil
}

func parseResult(syzType prog.Type, straceRet int64, ctx *Context) {
	if straceRet > 0 {
		//TODO: This is a hack NEED to refacto lexer to parser return values into strace types
		straceExpr := newExpression(newIntsType([]int64{straceRet}))
		switch syzType.(type) {
		case *prog.ResourceType:
			log.Logf(2, "Call: %s returned a resource type with val: %s",
				ctx.CurrentStraceCall.CallName, straceExpr.String())
			ctx.ReturnCache.cache(syzType, straceExpr, ctx.CurrentSyzCall.Ret)
		}
	}
}

func parseArgs(syzType prog.Type, traceArg irType, ctx *Context) (prog.Arg, error) {
	if traceArg == nil {
		log.Logf(3, "Parsing syzType: %s, traceArg is nil. Generating default arg...", syzType.Name())
		return GenDefaultArg(syzType, ctx), nil
	}
	ctx.CurrentStraceArg = traceArg
	log.Logf(3, "Parsing Arg of syz type: %s, ir type: %s\n", syzType.Name(), traceArg.Name())

	switch a := syzType.(type) {
	case *prog.IntType, *prog.ConstType, *prog.FlagsType, *prog.CsumType:
		return parseConstType(a, traceArg, ctx)
	case *prog.LenType:
		return GenDefaultArg(syzType, ctx), nil
	case *prog.ProcType:
		return parseProcType(a, traceArg, ctx)
	case *prog.ResourceType:
		return parseResourceType(a, traceArg, ctx)
	case *prog.PtrType:
		return parsePtrType(a, traceArg, ctx)
	case *prog.BufferType:
		return parseBufferType(a, traceArg, ctx)
	case *prog.StructType:
		return parseStructType(a, traceArg, ctx)
	case *prog.ArrayType:
		return parseArrayType(a, traceArg, ctx)
	case *prog.UnionType:
		return parseUnionType(a, traceArg, ctx)
	case *prog.VmaType:
		return parseVmaType(a, traceArg, ctx)
	default:
		panic(fmt.Sprintf("Unsupported  Type: %v\n", syzType))
	}
}

func parseVmaType(syzType *prog.VmaType, traceType irType, ctx *Context) (prog.Arg, error) {
	npages := uint64(1)
	// TODO: strace doesn't give complete info, need to guess random page range
	if syzType.RangeBegin != 0 || syzType.RangeEnd != 0 {
		npages = uint64(int(syzType.RangeEnd)) // + r.Intn(int(a.RangeEnd-a.RangeBegin+1)))
	}
	arg := prog.MakeVmaPointerArg(syzType, 0, npages)
	ctx.State.Tracker.addAllocation(ctx.CurrentSyzCall, pageSize, arg)
	return arg, nil
}

func parseArrayType(syzType *prog.ArrayType, traceType irType, ctx *Context) (prog.Arg, error) {
	args := make([]prog.Arg, 0)
	switch a := traceType.(type) {
	case *arrayType:
		if syzType.Dir() == prog.DirOut {
			return GenDefaultArg(syzType, ctx), nil
		}
		for i := 0; i < a.Len; i++ {
			if arg, err := parseArgs(syzType.Type, a.Elems[i], ctx); err == nil {
				args = append(args, arg)
			} else {
				log.Fatalf("Error parsing array elem: %s\n", err.Error())
			}
		}
	case *field:
		return parseArrayType(syzType, a.Val, ctx)
	case *pointerType, *expression, *bufferType:
		return GenDefaultArg(syzType, ctx), nil
	default:
		log.Fatalf("Error parsing Array: %s with Wrong Type: %s\n", syzType.FldName, traceType.Name())
	}
	return prog.MakeGroupArg(syzType, args), nil
}

func parseStructType(syzType *prog.StructType, traceType irType, ctx *Context) (prog.Arg, error) {
	traceType = preprocessStruct(syzType, traceType, ctx)
	args := make([]prog.Arg, 0)
	switch a := traceType.(type) {
	case *structType:
		reorderStructFields(syzType, a, ctx)
		args = append(args, evalFields(syzType.Fields, a.Fields, ctx)...)
	case *arrayType:
		//Syzkaller's pipe definition expects a pipefd struct
		//But strace returns an array type
		args = append(args, evalFields(syzType.Fields, a.Elems, ctx)...)
	case *field:
		if arg, err := parseArgs(syzType, a.Val, ctx); err == nil {
			return arg, nil
		}
		log.Fatalf("Error parsing struct field: %#v", ctx)
	case *call:
		args = append(args, parseInnerCall(syzType, a, ctx))
	case *expression:
		/*
		 May get here through select. E.g. select(2, [6, 7], ..) since Expression can
		 be Ints. However, creating fd set is hard and we let default arg through
		*/
		return GenDefaultArg(syzType, ctx), nil
	case *bufferType:
		return serialize(syzType, []byte(a.Val), ctx)
	default:
		log.Fatalf("Unsupported Strace Type: %#v to Struct Type", a)
	}
	return prog.MakeGroupArg(syzType, args), nil
}

func evalFields(syzFields []prog.Type, straceFields []irType, ctx *Context) []prog.Arg {
	args := make([]prog.Arg, 0)
	j := 0
	for i := range syzFields {
		if prog.IsPad(syzFields[i]) {
			args = append(args, prog.DefaultArg(syzFields[i]))
		} else {
			if j >= len(straceFields) {
				args = append(args, GenDefaultArg(syzFields[i], ctx))
			} else if arg, err := parseArgs(syzFields[i], straceFields[j], ctx); err == nil {
				args = append(args, arg)
			} else {
				log.Fatalf("Error parsing struct field: %#v", ctx)
			}
			j++
		}
	}
	return args
}

func parseUnionType(syzType *prog.UnionType, straceType irType, ctx *Context) (prog.Arg, error) {
	switch strType := straceType.(type) {
	case *field:
		switch strValType := strType.Val.(type) {
		case *call:
			return parseInnerCall(syzType, strValType, ctx), nil
		default:
			return parseUnionType(syzType, strType.Val, ctx)
		}
	case *call:
		return parseInnerCall(syzType, strType, ctx), nil
	default:
		idx := identifyUnionType(ctx, syzType.TypeName)
		innerType := syzType.Fields[idx]
		if innerArg, err := parseArgs(innerType, straceType, ctx); err == nil {
			return prog.MakeUnionArg(syzType, innerArg), nil
		}
		log.Fatalf("Error parsing union type: %#v", ctx)
	}

	return nil, nil
}

func identifyUnionType(ctx *Context, typeName string) int {
	switch typeName {
	case "sockaddr_storage":
		return identifySockaddrStorageUnion(ctx)
	case "sockaddr_nl":
		return identifySockaddrNetlinkUnion(ctx)
	case "ifr_ifru":
		return identifyIfrIfruUnion(ctx)
	case "ifconf":
		return identifyIfconfUnion(ctx)
	case "bpf_instructions":
		return 0
	case "bpf_insn":
		return 1
	}
	return 0
}

func identifySockaddrStorageUnion(ctx *Context) int {
	//We currently look at the first argument of the system call
	//To determine which option of the union we select.
	call := ctx.CurrentStraceCall
	var straceArg irType
	switch call.CallName {
	//May need to handle special cases.
	case "recvfrom":
		straceArg = call.Args[4]
	default:
		if len(call.Args) >= 2 {
			straceArg = call.Args[1]
		} else {
			log.Fatalf("Unable identify union for sockaddr_storage for call: %s\n", call.CallName)
		}
	}
	switch strType := straceArg.(type) {
	case *structType:
		for i := range strType.Fields {
			fieldStr := strType.Fields[i].String()
			if strings.Contains(fieldStr, "AF_INET6") {
				return 4
			} else if strings.Contains(fieldStr, "AF_INET") {
				return 1
			} else if strings.Contains(fieldStr, "AF_UNIX") {
				return 0
			} else if strings.Contains(fieldStr, "AF_NETLINK") {
				return 5
			}
		}
	default:
		log.Fatalf("Failed to parse Sockaddr Stroage Union Type. Strace Type: %#v\n", strType)
	}
	return -1
}

func identifySockaddrNetlinkUnion(ctx *Context) int {
	switch a := ctx.CurrentStraceArg.(type) {
	case *structType:
		if len(a.Fields) > 2 {
			switch b := a.Fields[1].(type) {
			case *expression:
				pid := b.Eval(ctx.Target)
				if pid > 0 {
					//User
					return 0
				} else if pid == 0 {
					//Kernel
					return 1
				} else {
					//Unspec
					return 2
				}
			case *field:
				curArg := ctx.CurrentStraceArg
				ctx.CurrentStraceArg = b.Val
				idx := identifySockaddrNetlinkUnion(ctx)
				ctx.CurrentStraceArg = curArg
				return idx
			default:
				log.Fatalf("Parsing netlink addr struct and expect expression for first arg: %s\n", a.Name())
			}
		}
	}
	return 2
}

func identifyIfrIfruUnion(ctx *Context) int {
	switch ctx.CurrentStraceArg.(type) {
	case *expression:
		return 2
	case *field:
		return 2
	default:
		return 0
	}
}

func identifyIfconfUnion(ctx *Context) int {
	switch ctx.CurrentStraceArg.(type) {
	case *structType:
		return 1
	default:
		return 0
	}
}

func parseBufferType(syzType *prog.BufferType, traceType irType, ctx *Context) (prog.Arg, error) {
	if syzType.Dir() == prog.DirOut {
		if !syzType.Varlen() {
			return prog.MakeOutDataArg(syzType, syzType.Size()), nil
		}
		switch a := traceType.(type) {
		case *bufferType:
			return prog.MakeOutDataArg(syzType, uint64(len(a.Val))), nil
		case *field:
			return parseBufferType(syzType, a.Val, ctx)
		default:
			switch syzType.Kind {
			case prog.BufferBlobRand:
				size := rand.Intn(256)
				return prog.MakeOutDataArg(syzType, uint64(size)), nil

			case prog.BufferBlobRange:
				max := rand.Intn(int(syzType.RangeEnd) - int(syzType.RangeBegin) + 1)
				size := max + int(syzType.RangeBegin)
				return prog.MakeOutDataArg(syzType, uint64(size)), nil
			default:
				panic(fmt.Sprintf("unexpected buffer type kind: %v. call %v arg %v", syzType.Kind, ctx.CurrentSyzCall, traceType))
			}
		}
	}
	var bufVal []byte
	switch a := traceType.(type) {
	case *bufferType:
		bufVal = []byte(a.Val)
	case *expression:
		val := a.Eval(ctx.Target)
		bArr := make([]byte, 8)
		binary.LittleEndian.PutUint64(bArr, val)
		bufVal = bArr
	case *pointerType:
		val := a.Address
		bArr := make([]byte, 8)
		binary.LittleEndian.PutUint64(bArr, val)
		bufVal = bArr
	case *arrayType:
		//
	case *structType:
		return GenDefaultArg(syzType, ctx), nil
	case *field:
		return parseArgs(syzType, a.Val, ctx)
	default:
		log.Fatalf("Cannot parse type %#v for Buffer Type\n", traceType)
	}
	if !syzType.Varlen() {
		bufVal = GenBuff(bufVal, syzType.Size())
		buf := make([]byte, syzType.Size())
		valLen := len(bufVal)
		for i := range buf {
			if i < valLen {
				buf[i] = bufVal[i]
			} else {
				buf[i] = 0
			}
		}
		bufVal = buf
	}
	return prog.MakeDataArg(syzType, bufVal), nil
}

func parsePtrType(syzType *prog.PtrType, traceType irType, ctx *Context) (prog.Arg, error) {
	switch a := traceType.(type) {
	case *pointerType:
		if a.IsNull() {
			return prog.DefaultArg(syzType), nil
		}
		if a.Res == nil {
			res := GenDefaultArg(syzType.Type, ctx)
			return addr(ctx, syzType, res.Size(), res)
		}
		if res, err := parseArgs(syzType.Type, a.Res, ctx); err != nil {
			log.Fatalf("Error parsing Ptr: %s", err.Error())
		} else {
			return addr(ctx, syzType, res.Size(), res)
		}
	case *expression:
		//Likely have a type of the form bind(3, 0xfffffffff, [3]);
		res := GenDefaultArg(syzType.Type, ctx)
		return addr(ctx, syzType, res.Size(), res)
	default:
		if res, err := parseArgs(syzType.Type, a, ctx); err != nil {
			log.Fatalf("Error parsing Ptr: %s", err.Error())
		} else {
			return addr(ctx, syzType, res.Size(), res)
		}
	}
	return nil, nil
}

func parseConstType(syzType prog.Type, traceType irType, ctx *Context) (prog.Arg, error) {
	if syzType.Dir() == prog.DirOut {
		return prog.DefaultArg(syzType), nil
	}
	switch a := traceType.(type) {
	case *expression:
		if a.IntsType != nil && len(a.IntsType) >= 2 {
			/*
				 	May get here through select. E.g. select(2, [6, 7], ..) since Expression can
					 be Ints. However, creating fd set is hard and we let default arg through
			*/
			return GenDefaultArg(syzType, ctx), nil
		}
		return prog.MakeConstArg(syzType, a.Eval(ctx.Target)), nil
	case *dynamicType:
		return prog.MakeConstArg(syzType, a.BeforeCall.Eval(ctx.Target)), nil
	case *arrayType:
		/*
			Sometimes strace represents a pointer to int as [0] which gets parsed
			as Array([0], len=1). A good example is ioctl(3, FIONBIO, [1]).
		*/
		if a.Len == 0 {
			log.Fatalf("Parsing const type. Got array type with len 0: %#v", ctx)
		}
		return parseConstType(syzType, a.Elems[0], ctx)
	case *structType:
		/*
			Sometimes system calls have an int type that is actually a union. Strace will represent the union
			like a struct e.g.
			sigev_value={sival_int=-2123636944, sival_ptr=0x7ffd816bdf30}
			For now we choose the first option
		*/
		return parseConstType(syzType, a.Fields[0], ctx)
	case *field:
		//We have an argument of the form sin_port=IntType(0)
		return parseArgs(syzType, a.Val, ctx)
	case *call:
		//We have likely hit a call like inet_pton, htonl, etc
		return parseInnerCall(syzType, a, ctx), nil
	case *bufferType:
		//The call almost certainly an error or missing fields
		return GenDefaultArg(syzType, ctx), nil
		//E.g. ltp_bind01 two arguments are empty and
	case *pointerType:
		/*
			This can be triggered by the following:
			2435  connect(3, {sa_family=0x2f ,..., 16)*/
		return prog.MakeConstArg(syzType, a.Address), nil
	default:
		log.Fatalf("Cannot convert Strace Type: %s to Const Type", traceType.Name())
	}
	return nil, nil
}

func parseResourceType(syzType *prog.ResourceType, traceType irType, ctx *Context) (prog.Arg, error) {
	if syzType.Dir() == prog.DirOut {
		log.Logf(2, "Resource returned by call argument: %s\n", traceType.String())
		res := prog.MakeResultArg(syzType, nil, syzType.Default())
		ctx.ReturnCache.cache(syzType, traceType, res)
		return res, nil
	}
	switch a := traceType.(type) {
	case *expression:
		val := a.Eval(ctx.Target)
		if arg := ctx.ReturnCache.get(syzType, traceType); arg != nil {
			res := prog.MakeResultArg(syzType, arg.(*prog.ResultArg), syzType.Default())
			return res, nil
		}
		res := prog.MakeResultArg(syzType, nil, val)
		return res, nil
	case *field:
		return parseResourceType(syzType, a.Val, ctx)
	default:
		panic("Resource Type only supports Expression")
	}
}

func parseProcType(syzType *prog.ProcType, traceType irType, ctx *Context) (prog.Arg, error) {
	if syzType.Dir() == prog.DirOut {
		return GenDefaultArg(syzType, ctx), nil
	}
	switch a := traceType.(type) {
	case *expression:
		val := a.Eval(ctx.Target)
		if val >= syzType.ValuesPerProc {
			return prog.MakeConstArg(syzType, syzType.ValuesPerProc-1), nil
		}
		return prog.MakeConstArg(syzType, val), nil
	case *field:
		return parseArgs(syzType, a.Val, ctx)
	case *call:
		return parseInnerCall(syzType, a, ctx), nil
	case *bufferType:
		/* Again probably an error case
		   Something like the following will trigger this
		    bind(3, {sa_family=AF_INET, sa_data="\xac"}, 3) = -1 EINVAL(Invalid argument)
		*/
		return GenDefaultArg(syzType, ctx), nil
	default:
		log.Fatalf("Unsupported Type for Proc: %#v\n", traceType)
	}
	return nil, nil
}

func GenDefaultArg(syzType prog.Type, ctx *Context) prog.Arg {
	switch a := syzType.(type) {
	case *prog.PtrType:
		res := prog.DefaultArg(a.Type)
		ptr, _ := addr(ctx, syzType, res.Size(), res)
		return ptr
	case *prog.IntType, *prog.ConstType, *prog.FlagsType, *prog.LenType, *prog.ProcType, *prog.CsumType:
		return prog.DefaultArg(a)
	case *prog.BufferType:
		return prog.DefaultArg(a)
	case *prog.StructType:
		var inner []prog.Arg
		for _, field := range a.Fields {
			inner = append(inner, GenDefaultArg(field, ctx))
		}
		return prog.MakeGroupArg(a, inner)
	case *prog.UnionType:
		optType := a.Fields[0]
		return prog.MakeUnionArg(a, GenDefaultArg(optType, ctx))
	case *prog.ArrayType:
		return prog.DefaultArg(syzType)
	case *prog.ResourceType:
		return prog.MakeResultArg(syzType, nil, a.Default())
	case *prog.VmaType:
		return prog.DefaultArg(syzType)
	default:
		log.Fatalf("Unsupported Type: %#v", syzType)
	}
	return nil
}

func serialize(syzType prog.Type, buf []byte, ctx *Context) (prog.Arg, error) {
	switch a := syzType.(type) {
	case *prog.IntType, *prog.ConstType, *prog.FlagsType, *prog.LenType, *prog.CsumType:
		return prog.MakeConstArg(a, bufToUint(buf[:syzType.Size()])), nil
	case *prog.ProcType:
		return GenDefaultArg(syzType, ctx), nil
	case *prog.PtrType:
		if res, err := serialize(a.Type, buf, ctx); err == nil {
			return addr(ctx, a, res.Size(), res)
		}
		panic("Failed to serialize pointer type")
	case *prog.StructType:
		pos := uint64(0)
		bufLen := uint64(len(buf))
		args := make([]prog.Arg, 0)
		for _, field := range a.Fields {
			if pos+field.Size() >= bufLen {
				args = append(args, GenDefaultArg(field, ctx))
				continue
			} else {
				if res, err := serialize(field, buf[pos:pos+field.Size()], ctx); err == nil {
					args = append(args, res)
				} else {
					panic("Failed to serialize struct field")
				}
			}
			pos += field.Size()
		}
		return prog.MakeGroupArg(syzType, args), nil
	default:
		panic("Unsupported Type\n")
	}
}

func bufToUint(buf []byte) uint64 {
	switch len(buf) {
	case 1:
		return uint64(buf[0])
	case 2:
		return uint64(binary.LittleEndian.Uint16(buf))
	case 4:
		return uint64(binary.LittleEndian.Uint32(buf))
	case 8:
		return binary.LittleEndian.Uint64(buf)
	default:
		panic("Failed to convert byte to int")
	}
}

func addr(ctx *Context, syzType prog.Type, size uint64, data prog.Arg) (prog.Arg, error) {
	arg := prog.MakePointerArg(syzType, uint64(0), data)
	ctx.State.Tracker.addAllocation(ctx.CurrentSyzCall, size, arg)
	return arg, nil
}

func reorderStructFields(syzType *prog.StructType, traceType *structType, ctx *Context) {
	/*
		Sometimes strace reports struct fields out of order compared to Syzkaller.
		Example: 5704  bind(3, {sa_family=AF_INET6,
					sin6_port=htons(8888),
					inet_pton(AF_INET6, "::", &sin6_addr),
					sin6_flowinfo=htonl(2206138368),
					sin6_scope_id=2049825634}, 128) = 0
		The flow_info and pton fields are switched in Syzkaller
	*/
	switch syzType.TypeName {
	case "sockaddr_in6":
		field2 := traceType.Fields[2]
		traceType.Fields[2] = traceType.Fields[3]
		traceType.Fields[3] = field2
	case "bpf_insn_generic", "bpf_insn_exit", "bpf_insn_alu", "bpf_insn_jmp", "bpf_insn_ldst":
		fmt.Printf("bpf_insn_generic size: %d, typsize: %d\n", syzType.Size(), syzType.TypeSize)
		reg := (traceType.Fields[1].Eval(ctx.Target)) | (traceType.Fields[2].Eval(ctx.Target) << 4)
		newFields := make([]irType, len(traceType.Fields)-1)
		newFields[0] = traceType.Fields[0]
		newFields[1] = newExpression(newIntType(int64(reg)))
		newFields[2] = traceType.Fields[3]
		newFields[3] = traceType.Fields[4]
		traceType.Fields = newFields
	}
}

func genDefaultTraceType(syzType prog.Type) irType {
	switch a := syzType.(type) {
	case *prog.StructType:
		straceFields := make([]irType, len(a.Fields))
		for i := 0; i < len(straceFields); i++ {
			straceFields[i] = genDefaultTraceType(a.Fields[i])
		}
		return newStructType(straceFields)
	case *prog.ArrayType:
		straceFields := make([]irType, 1)
		straceFields[0] = genDefaultTraceType(a.Type)
		return newArrayType(straceFields)
	case *prog.ConstType, *prog.ProcType, *prog.LenType, *prog.FlagsType, *prog.IntType:
		return newExpression(newIntType(0))
	case *prog.PtrType:
		return newPointerType(0, genDefaultTraceType(a.Type))
	case *prog.UnionType:
		return genDefaultTraceType(a.Fields[0])
	default:
		log.Fatalf("Unsupported syz type for generating default strace type: %s\n", syzType.Name())
	}
	return nil
}

func shouldSkip(ctx *Context) bool {
	syscall := ctx.CurrentStraceCall
	switch syscall.CallName {
	case "write":
		switch a := syscall.Args[0].(type) {
		case *expression:
			val := a.Eval(ctx.Target)
			if val == 1 || val == 2 {
				return true
			}
		}
	}
	return false
}
