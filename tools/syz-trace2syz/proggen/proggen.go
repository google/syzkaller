// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package proggen

import (
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"math/rand"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/tools/syz-trace2syz/parser"
)

func ParseFile(filename string, target *prog.Target) ([]*prog.Prog, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error reading file: %v", err)
	}
	return ParseData(data, target)
}

func ParseData(data []byte, target *prog.Target) ([]*prog.Prog, error) {
	tree, err := parser.ParseData(data)
	if err != nil {
		return nil, err
	}
	if tree == nil {
		return nil, nil
	}
	var progs []*prog.Prog
	parseTree(tree, tree.RootPid, target, &progs)
	return progs, nil
}

// parseTree groups system calls in the trace by process id.
// The tree preserves process hierarchy i.e. parent->[]child
func parseTree(tree *parser.TraceTree, pid int64, target *prog.Target, progs *[]*prog.Prog) {
	log.Logf(2, "parsing trace pid %v", pid)
	if p := genProg(tree.TraceMap[pid], target); p != nil {
		*progs = append(*progs, p)
	}
	for _, childPid := range tree.Ptree[pid] {
		if tree.TraceMap[childPid] != nil {
			parseTree(tree, childPid, target, progs)
		}
	}
}

// Context stores metadata related to a syzkaller program
type context struct {
	builder           *prog.Builder
	target            *prog.Target
	selectors         []callSelector
	returnCache       returnCache
	currentStraceCall *parser.Syscall
	currentSyzCall    *prog.Call
}

// genProg converts a trace to one of our programs.
func genProg(trace *parser.Trace, target *prog.Target) *prog.Prog {
	retCache := newRCache()
	ctx := &context{
		builder:     prog.MakeProgGen(target),
		target:      target,
		selectors:   newSelectors(target, retCache),
		returnCache: retCache,
	}
	for _, sCall := range trace.Calls {
		if sCall.Paused {
			// Probably a case where the call was killed by a signal like the following
			// 2179  wait4(2180,  <unfinished ...>
			// 2179  <... wait4 resumed> 0x7fff28981bf8, 0, NULL) = ? ERESTARTSYS
			// 2179  --- SIGUSR1 {si_signo=SIGUSR1, si_code=SI_USER, si_pid=2180, si_uid=0} ---
			continue
		}
		if shouldSkip(sCall) {
			log.Logf(2, "skipping call: %s", sCall.CallName)
			continue
		}
		ctx.currentStraceCall = sCall
		call := ctx.genCall()
		if call == nil {
			continue
		}
		if err := ctx.builder.Append(call); err != nil {
			log.Fatalf("%v", err)
		}
	}
	p, err := ctx.builder.Finalize()
	if err != nil {
		log.Fatalf("error validating program: %v", err)
	}
	return p
}

func (ctx *context) genCall() *prog.Call {
	log.Logf(3, "parsing call: %s", ctx.currentStraceCall.CallName)
	straceCall := ctx.currentStraceCall
	ctx.currentSyzCall = new(prog.Call)
	ctx.currentSyzCall.Meta = ctx.Select(straceCall)
	syzCall := ctx.currentSyzCall
	if ctx.currentSyzCall.Meta == nil {
		log.Logf(2, "skipping call: %s which has no matching description", ctx.currentStraceCall.CallName)
		return nil
	}
	syzCall.Ret = prog.MakeReturnArg(syzCall.Meta.Ret)

	for i := range syzCall.Meta.Args {
		var strArg parser.IrType
		if i < len(straceCall.Args) {
			strArg = straceCall.Args[i]
		}
		res := ctx.genArgs(syzCall.Meta.Args[i], strArg)
		syzCall.Args = append(syzCall.Args, res)
	}
	ctx.genResult(syzCall.Meta.Ret, straceCall.Ret)
	return syzCall
}

func (ctx *context) Select(syscall *parser.Syscall) *prog.Syscall {
	for _, selector := range ctx.selectors {
		if variant := selector.Select(syscall); variant != nil {
			return variant
		}
	}
	return ctx.target.SyscallMap[syscall.CallName]
}

func (ctx *context) genResult(syzType prog.Type, straceRet int64) {
	if straceRet <= 0 {
		return
	}
	straceExpr := parser.Constant(uint64(straceRet))
	switch syzType.(type) {
	case *prog.ResourceType:
		log.Logf(2, "call: %s returned a resource type with val: %s",
			ctx.currentStraceCall.CallName, straceExpr.String())
		ctx.returnCache.cache(syzType, straceExpr, ctx.currentSyzCall.Ret)
	}
}

func (ctx *context) genArgs(syzType prog.Type, traceArg parser.IrType) prog.Arg {
	if traceArg == nil {
		log.Logf(3, "parsing syzType: %s, traceArg is nil. generating default arg...", syzType.Name())
		return syzType.DefaultArg()
	}
	log.Logf(3, "parsing arg of syz type: %s, ir type: %#v", syzType.Name(), traceArg)

	if syzType.Dir() == prog.DirOut {
		switch syzType.(type) {
		case *prog.PtrType, *prog.StructType, *prog.ResourceType, *prog.BufferType:
			// Resource Types need special care. Pointers, Structs can have resource fields e.g. pipe, socketpair
			// Buffer may need special care in out direction
		default:
			return syzType.DefaultArg()
		}
	}

	switch a := syzType.(type) {
	case *prog.IntType, *prog.ConstType, *prog.FlagsType, *prog.CsumType:
		return ctx.genConst(a, traceArg)
	case *prog.LenType:
		return syzType.DefaultArg()
	case *prog.ProcType:
		return ctx.parseProc(a, traceArg)
	case *prog.ResourceType:
		return ctx.genResource(a, traceArg)
	case *prog.PtrType:
		return ctx.genPtr(a, traceArg)
	case *prog.BufferType:
		return ctx.genBuffer(a, traceArg)
	case *prog.StructType:
		return ctx.genStruct(a, traceArg)
	case *prog.ArrayType:
		return ctx.genArray(a, traceArg)
	case *prog.UnionType:
		return ctx.genUnionArg(a, traceArg)
	case *prog.VmaType:
		return ctx.genVma(a, traceArg)
	default:
		log.Fatalf("unsupported type: %#v", syzType)
	}
	return nil
}

func (ctx *context) genVma(syzType *prog.VmaType, _ parser.IrType) prog.Arg {
	npages := uint64(1)
	if syzType.RangeBegin != 0 || syzType.RangeEnd != 0 {
		npages = syzType.RangeEnd
	}
	return prog.MakeVmaPointerArg(syzType, ctx.builder.AllocateVMA(npages), npages)
}

func (ctx *context) genArray(syzType *prog.ArrayType, traceType parser.IrType) prog.Arg {
	var args []prog.Arg
	switch a := traceType.(type) {
	case *parser.GroupType:
		for i := 0; i < len(a.Elems); i++ {
			args = append(args, ctx.genArgs(syzType.Type, a.Elems[i]))
		}
	default:
		log.Fatalf("unsupported type for array: %#v", traceType)
	}
	return prog.MakeGroupArg(syzType, args)
}

func (ctx *context) genStruct(syzType *prog.StructType, traceType parser.IrType) prog.Arg {
	var args []prog.Arg
	switch a := traceType.(type) {
	case *parser.GroupType:
		j := 0
		if ret, recursed := ctx.recurseStructs(syzType, a); recursed {
			return ret
		}
		for i := range syzType.Fields {
			if prog.IsPad(syzType.Fields[i]) {
				args = append(args, syzType.Fields[i].DefaultArg())
				continue
			}
			// If the last n fields of a struct are zero or NULL, strace will occasionally omit those values
			// this creates a mismatch in the number of elements in the ir type and in
			// our descriptions. We generate default values for omitted fields
			if j >= len(a.Elems) {
				args = append(args, syzType.Fields[i].DefaultArg())
			} else {
				args = append(args, ctx.genArgs(syzType.Fields[i], a.Elems[j]))
			}
			j++
		}
	case *parser.BufferType:
		// We could have a case like the following:
		// ioctl(3, 35111, {ifr_name="\x6c\x6f", ifr_hwaddr=00:00:00:00:00:00}) = 0
		// if_hwaddr gets parsed as a BufferType but our syscall descriptions have it as a struct type
		return syzType.DefaultArg()
	default:
		log.Fatalf("unsupported type for struct: %#v", a)
	}
	return prog.MakeGroupArg(syzType, args)
}

// recurseStructs handles cases where syzType corresponds to struct descriptions like
// sockaddr_storage_in6 {
//        addr    sockaddr_in6
// } [size[SOCKADDR_STORAGE_SIZE], align_ptr]
// which need to be recursively generated. It returns true if we needed to recurse
// along with the generated argument and false otherwise.
func (ctx *context) recurseStructs(syzType *prog.StructType, traceType *parser.GroupType) (prog.Arg, bool) {
	// only consider structs with one non-padded field
	numFields := 0
	for _, field := range syzType.Fields {
		if prog.IsPad(field) {
			continue
		}
		numFields++
	}
	if numFields != 1 {
		return nil, false
	}
	// the strace group type needs to have more one field (a mismatch)
	if len(traceType.Elems) == 1 {
		return nil, false
	}
	// first field needs to be a struct
	switch t := syzType.Fields[0].(type) {
	case *prog.StructType:
		var args []prog.Arg
		// first element and traceType should have the same number of elements
		if len(t.Fields) != len(traceType.Elems) {
			return nil, false
		}
		args = append(args, ctx.genStruct(t, traceType))
		for _, field := range syzType.Fields[1:] {
			args = append(args, field.DefaultArg())
		}
		return prog.MakeGroupArg(syzType, args), true
	}
	return nil, false
}

func (ctx *context) genUnionArg(syzType *prog.UnionType, straceType parser.IrType) prog.Arg {
	if straceType == nil {
		log.Logf(1, "generating union arg. straceType is nil")
		return syzType.DefaultArg()
	}
	log.Logf(4, "generating union arg: %s %#v", syzType.TypeName, straceType)

	// Unions are super annoying because they sometimes need to be handled case by case
	// We might need to lookinto a matching algorithm to identify the union type that most closely
	// matches our strace type.

	switch syzType.TypeName {
	case "sockaddr_storage":
		return ctx.genSockaddrStorage(syzType, straceType)
	case "sockaddr_nl":
		return ctx.genSockaddrNetlink(syzType, straceType)
	case "ifr_ifru":
		return ctx.genIfrIfru(syzType, straceType)
	}
	return prog.MakeUnionArg(syzType, ctx.genArgs(syzType.Fields[0], straceType))
}

func (ctx *context) genBuffer(syzType *prog.BufferType, traceType parser.IrType) prog.Arg {
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
				log.Fatalf("unexpected buffer type kind: %v. call %v arg %#v", syzType.Kind, ctx.currentSyzCall, traceType)
			}
		}
	}
	var bufVal []byte
	switch a := traceType.(type) {
	case *parser.BufferType:
		bufVal = []byte(a.Val)
	case parser.Constant:
		val := a.Val()
		bArr := make([]byte, 8)
		binary.LittleEndian.PutUint64(bArr, val)
		bufVal = bArr
	default:
		log.Fatalf("unsupported type for buffer: %#v", traceType)
	}
	// strace always drops the null byte for buffer types but we only need to add it back for filenames and strings
	switch syzType.Kind {
	case prog.BufferFilename, prog.BufferString:
		bufVal = append(bufVal, '\x00')
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

func (ctx *context) genPtr(syzType *prog.PtrType, traceType parser.IrType) prog.Arg {
	switch a := traceType.(type) {
	case parser.Constant:
		if a.Val() == 0 {
			return prog.MakeSpecialPointerArg(syzType, 0)
		}
		// Likely have a type of the form bind(3, 0xfffffffff, [3]);
		res := syzType.Type.DefaultArg()
		return ctx.addr(syzType, res.Size(), res)
	default:
		res := ctx.genArgs(syzType.Type, a)
		return ctx.addr(syzType, res.Size(), res)
	}
}

func (ctx *context) genConst(syzType prog.Type, traceType parser.IrType) prog.Arg {
	switch a := traceType.(type) {
	case parser.Constant:
		return prog.MakeConstArg(syzType, a.Val())
	case *parser.GroupType:
		// Sometimes strace represents a pointer to int as [0] which gets parsed
		// as Array([0], len=1). A good example is ioctl(3, FIONBIO, [1]). We may also have an union int type that
		// is a represented as a struct in strace e.g.
		// sigev_value={sival_int=-2123636944, sival_ptr=0x7ffd816bdf30}
		// For now we choose the first option
		if len(a.Elems) == 0 {
			log.Logf(2, "parsing const type, got array type with len 0")
			return syzType.DefaultArg()
		}
		return ctx.genConst(syzType, a.Elems[0])
	case *parser.BufferType:
		// strace decodes some arguments as hex strings because those values are network ordered
		// e.g. sin_port or sin_addr fields of sockaddr_in.
		// network order is big endian byte order so if the len of byte array is 1, 2, 4, or 8 then
		// it is a good chance that we are decoding one of those fields. If it isn't, then most likely
		// we have an error i.e. a sockaddr_un struct passed to a connect call with an inet file descriptor
		var val uint64
		toUint64 := binary.LittleEndian.Uint64
		toUint32 := binary.LittleEndian.Uint32
		toUint16 := binary.LittleEndian.Uint16
		if syzType.Format() == prog.FormatBigEndian {
			toUint64 = binary.BigEndian.Uint64
			toUint32 = binary.BigEndian.Uint32
			toUint16 = binary.BigEndian.Uint16
		}
		switch len(a.Val) {
		case 8:
			val = toUint64([]byte(a.Val))
		case 4:
			val = uint64(toUint32([]byte(a.Val)))
		case 2:
			val = uint64(toUint16([]byte(a.Val)))
		case 1:
			val = uint64(a.Val[0])
		default:
			return syzType.DefaultArg()
		}
		return prog.MakeConstArg(syzType, val)
	default:
		log.Fatalf("unsupported type for const: %#v", traceType)
	}
	return nil
}

func (ctx *context) genResource(syzType *prog.ResourceType, traceType parser.IrType) prog.Arg {
	if syzType.Dir() == prog.DirOut {
		log.Logf(2, "resource returned by call argument: %s", traceType.String())
		res := prog.MakeResultArg(syzType, nil, syzType.Default())
		ctx.returnCache.cache(syzType, traceType, res)
		return res
	}
	switch a := traceType.(type) {
	case parser.Constant:
		val := a.Val()
		if arg := ctx.returnCache.get(syzType, traceType); arg != nil {
			res := prog.MakeResultArg(syzType, arg.(*prog.ResultArg), syzType.Default())
			return res
		}
		res := prog.MakeResultArg(syzType, nil, val)
		return res
	case *parser.GroupType:
		if len(a.Elems) == 1 {
			// For example: 5028  ioctl(3, SIOCSPGRP, [0])          = 0
			// last argument is a pointer to a resource. Strace will output a pointer to
			// a number x as [x].
			res := prog.MakeResultArg(syzType, nil, syzType.Default())
			ctx.returnCache.cache(syzType, a.Elems[0], res)
			return res
		}
		log.Fatalf("generating resource type from GroupType with %d elements", len(a.Elems))
	default:
		log.Fatalf("unsupported type for resource: %#v", traceType)
	}
	return nil
}

func (ctx *context) parseProc(syzType *prog.ProcType, traceType parser.IrType) prog.Arg {
	switch a := traceType.(type) {
	case parser.Constant:
		val := a.Val()
		if val >= syzType.ValuesPerProc {
			return prog.MakeConstArg(syzType, syzType.ValuesPerProc-1)
		}
		return prog.MakeConstArg(syzType, val)
	case *parser.BufferType:
		// Again probably an error case
		// Something like the following will trigger this
		// bind(3, {sa_family=AF_INET, sa_data="\xac"}, 3) = -1 EINVAL(Invalid argument)
		return syzType.DefaultArg()
	default:
		log.Fatalf("unsupported type for proc: %#v", traceType)
	}
	return nil
}

func (ctx *context) addr(syzType prog.Type, size uint64, data prog.Arg) prog.Arg {
	return prog.MakePointerArg(syzType, ctx.builder.Allocate(size), data)
}

func shouldSkip(c *parser.Syscall) bool {
	switch c.CallName {
	case "write":
		// We skip all writes to stdout and stderr because they can corrupt our crash summary.
		// Also there will be nothing on stdin, so any reads will hang.
		switch a := c.Args[0].(type) {
		case parser.Constant:
			if a.Val() <= 2 {
				return true
			}
		}
	}
	return unsupportedCalls[c.CallName]
}
