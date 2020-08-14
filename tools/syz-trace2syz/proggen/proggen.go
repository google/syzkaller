// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build !codeanalysis

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
		res := ctx.genArg(syzCall.Meta.Args[i].Type, prog.DirIn, strArg)
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

func (ctx *context) genArg(syzType prog.Type, dir prog.Dir, traceArg parser.IrType) prog.Arg {
	if traceArg == nil {
		log.Logf(3, "parsing syzType: %s, traceArg is nil. generating default arg...", syzType.Name())
		return syzType.DefaultArg(dir)
	}
	log.Logf(3, "parsing arg of syz type: %s, ir type: %#v", syzType.Name(), traceArg)

	if dir == prog.DirOut {
		switch syzType.(type) {
		case *prog.PtrType, *prog.StructType, *prog.ResourceType, *prog.BufferType:
			// Resource Types need special care. Pointers, Structs can have resource fields e.g. pipe, socketpair
			// Buffer may need special care in out direction
		default:
			return syzType.DefaultArg(dir)
		}
	}

	switch a := syzType.(type) {
	case *prog.IntType, *prog.ConstType, *prog.FlagsType, *prog.CsumType:
		return ctx.genConst(a, dir, traceArg)
	case *prog.LenType:
		return syzType.DefaultArg(dir)
	case *prog.ProcType:
		return ctx.parseProc(a, dir, traceArg)
	case *prog.ResourceType:
		return ctx.genResource(a, dir, traceArg)
	case *prog.PtrType:
		return ctx.genPtr(a, dir, traceArg)
	case *prog.BufferType:
		return ctx.genBuffer(a, dir, traceArg)
	case *prog.StructType:
		return ctx.genStruct(a, dir, traceArg)
	case *prog.ArrayType:
		return ctx.genArray(a, dir, traceArg)
	case *prog.UnionType:
		return ctx.genUnionArg(a, dir, traceArg)
	case *prog.VmaType:
		return ctx.genVma(a, dir, traceArg)
	default:
		log.Fatalf("unsupported type: %#v", syzType)
	}
	return nil
}

func (ctx *context) genVma(syzType *prog.VmaType, dir prog.Dir, _ parser.IrType) prog.Arg {
	npages := uint64(1)
	if syzType.RangeBegin != 0 || syzType.RangeEnd != 0 {
		npages = syzType.RangeEnd
	}
	return prog.MakeVmaPointerArg(syzType, dir, ctx.builder.AllocateVMA(npages), npages)
}

func (ctx *context) genArray(syzType *prog.ArrayType, dir prog.Dir, traceType parser.IrType) prog.Arg {
	var args []prog.Arg
	switch a := traceType.(type) {
	case *parser.GroupType:
		for i := 0; i < len(a.Elems); i++ {
			args = append(args, ctx.genArg(syzType.Elem, dir, a.Elems[i]))
		}
	default:
		log.Fatalf("unsupported type for array: %#v", traceType)
	}
	return prog.MakeGroupArg(syzType, dir, args)
}

func (ctx *context) genStruct(syzType *prog.StructType, dir prog.Dir, traceType parser.IrType) prog.Arg {
	var args []prog.Arg
	switch a := traceType.(type) {
	case *parser.GroupType:
		j := 0
		if ret, recursed := ctx.recurseStructs(syzType, dir, a); recursed {
			return ret
		}
		for i := range syzType.Fields {
			fldDir := syzType.Fields[i].Dir(dir)
			if prog.IsPad(syzType.Fields[i].Type) {
				args = append(args, syzType.Fields[i].DefaultArg(fldDir))
				continue
			}
			// If the last n fields of a struct are zero or NULL, strace will occasionally omit those values
			// this creates a mismatch in the number of elements in the ir type and in
			// our descriptions. We generate default values for omitted fields
			if j >= len(a.Elems) {
				args = append(args, syzType.Fields[i].DefaultArg(fldDir))
			} else {
				args = append(args, ctx.genArg(syzType.Fields[i].Type, fldDir, a.Elems[j]))
			}
			j++
		}
	case *parser.BufferType:
		// We could have a case like the following:
		// ioctl(3, 35111, {ifr_name="\x6c\x6f", ifr_hwaddr=00:00:00:00:00:00}) = 0
		// if_hwaddr gets parsed as a BufferType but our syscall descriptions have it as a struct type
		return syzType.DefaultArg(dir)
	default:
		log.Fatalf("unsupported type for struct: %#v", a)
	}
	return prog.MakeGroupArg(syzType, dir, args)
}

// recurseStructs handles cases where syzType corresponds to struct descriptions like
// sockaddr_storage_in6 {
//        addr    sockaddr_in6
// } [size[SOCKADDR_STORAGE_SIZE], align_ptr]
// which need to be recursively generated. It returns true if we needed to recurse
// along with the generated argument and false otherwise.
func (ctx *context) recurseStructs(syzType *prog.StructType, dir prog.Dir, traceType *parser.GroupType) (prog.Arg, bool) {
	// only consider structs with one non-padded field
	numFields := 0
	for _, field := range syzType.Fields {
		if prog.IsPad(field.Type) {
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
	switch t := syzType.Fields[0].Type.(type) {
	case *prog.StructType:
		var args []prog.Arg
		// first element and traceType should have the same number of elements
		if len(t.Fields) != len(traceType.Elems) {
			return nil, false
		}
		args = append(args, ctx.genStruct(t, dir, traceType))
		for _, field := range syzType.Fields[1:] {
			args = append(args, field.DefaultArg(field.Dir(dir)))
		}
		return prog.MakeGroupArg(syzType, dir, args), true
	}
	return nil, false
}

func (ctx *context) genUnionArg(syzType *prog.UnionType, dir prog.Dir, straceType parser.IrType) prog.Arg {
	if straceType == nil {
		log.Logf(1, "generating union arg. straceType is nil")
		return syzType.DefaultArg(dir)
	}
	log.Logf(4, "generating union arg: %s %#v", syzType.TypeName, straceType)

	// Unions are super annoying because they sometimes need to be handled case by case
	// We might need to lookinto a matching algorithm to identify the union type that most closely
	// matches our strace type.

	switch syzType.TypeName {
	case "sockaddr_storage":
		return ctx.genSockaddrStorage(syzType, dir, straceType)
	case "sockaddr_nl":
		return ctx.genSockaddrNetlink(syzType, dir, straceType)
	case "ifr_ifru":
		return ctx.genIfrIfru(syzType, dir, straceType)
	}
	return prog.MakeUnionArg(syzType, dir, ctx.genArg(syzType.Fields[0].Type, syzType.Fields[0].Dir(dir), straceType), 0)
}

func (ctx *context) genBuffer(syzType *prog.BufferType, dir prog.Dir, traceType parser.IrType) prog.Arg {
	if dir == prog.DirOut {
		if !syzType.Varlen() {
			return prog.MakeOutDataArg(syzType, dir, syzType.Size())
		}
		switch a := traceType.(type) {
		case *parser.BufferType:
			return prog.MakeOutDataArg(syzType, dir, uint64(len(a.Val)))
		default:
			switch syzType.Kind {
			case prog.BufferBlobRand:
				size := rand.Intn(256)
				return prog.MakeOutDataArg(syzType, dir, uint64(size))

			case prog.BufferBlobRange:
				max := rand.Intn(int(syzType.RangeEnd) - int(syzType.RangeBegin) + 1)
				size := max + int(syzType.RangeBegin)
				return prog.MakeOutDataArg(syzType, dir, uint64(size))
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
	return prog.MakeDataArg(syzType, dir, bufVal)
}

func (ctx *context) genPtr(syzType *prog.PtrType, dir prog.Dir, traceType parser.IrType) prog.Arg {
	switch a := traceType.(type) {
	case parser.Constant:
		if a.Val() == 0 {
			return prog.MakeSpecialPointerArg(syzType, dir, 0)
		}
		// Likely have a type of the form bind(3, 0xfffffffff, [3]);
		res := syzType.Elem.DefaultArg(syzType.ElemDir)
		return ctx.addr(syzType, dir, res.Size(), res)
	default:
		res := ctx.genArg(syzType.Elem, syzType.ElemDir, a)
		return ctx.addr(syzType, dir, res.Size(), res)
	}
}

func (ctx *context) genConst(syzType prog.Type, dir prog.Dir, traceType parser.IrType) prog.Arg {
	switch a := traceType.(type) {
	case parser.Constant:
		return prog.MakeConstArg(syzType, dir, a.Val())
	case *parser.GroupType:
		// Sometimes strace represents a pointer to int as [0] which gets parsed
		// as Array([0], len=1). A good example is ioctl(3, FIONBIO, [1]). We may also have an union int type that
		// is a represented as a struct in strace e.g.
		// sigev_value={sival_int=-2123636944, sival_ptr=0x7ffd816bdf30}
		// For now we choose the first option
		if len(a.Elems) == 0 {
			log.Logf(2, "parsing const type, got array type with len 0")
			return syzType.DefaultArg(dir)
		}
		return ctx.genConst(syzType, dir, a.Elems[0])
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
			return syzType.DefaultArg(dir)
		}
		return prog.MakeConstArg(syzType, dir, val)
	default:
		log.Fatalf("unsupported type for const: %#v", traceType)
	}
	return nil
}

func (ctx *context) genResource(syzType *prog.ResourceType, dir prog.Dir, traceType parser.IrType) prog.Arg {
	if dir == prog.DirOut {
		log.Logf(2, "resource returned by call argument: %s", traceType.String())
		res := prog.MakeResultArg(syzType, dir, nil, syzType.Default())
		ctx.returnCache.cache(syzType, traceType, res)
		return res
	}
	switch a := traceType.(type) {
	case parser.Constant:
		val := a.Val()
		if arg := ctx.returnCache.get(syzType, traceType); arg != nil {
			res := prog.MakeResultArg(syzType, dir, arg.(*prog.ResultArg), syzType.Default())
			return res
		}
		res := prog.MakeResultArg(syzType, dir, nil, val)
		return res
	case *parser.GroupType:
		if len(a.Elems) == 1 {
			// For example: 5028  ioctl(3, SIOCSPGRP, [0])          = 0
			// last argument is a pointer to a resource. Strace will output a pointer to
			// a number x as [x].
			res := prog.MakeResultArg(syzType, dir, nil, syzType.Default())
			ctx.returnCache.cache(syzType, a.Elems[0], res)
			return res
		}
		log.Fatalf("generating resource type from GroupType with %d elements", len(a.Elems))
	default:
		log.Fatalf("unsupported type for resource: %#v", traceType)
	}
	return nil
}

func (ctx *context) parseProc(syzType *prog.ProcType, dir prog.Dir, traceType parser.IrType) prog.Arg {
	switch a := traceType.(type) {
	case parser.Constant:
		val := a.Val()
		if val >= syzType.ValuesPerProc {
			return prog.MakeConstArg(syzType, dir, syzType.ValuesPerProc-1)
		}
		return prog.MakeConstArg(syzType, dir, val)
	case *parser.BufferType:
		// Again probably an error case
		// Something like the following will trigger this
		// bind(3, {sa_family=AF_INET, sa_data="\xac"}, 3) = -1 EINVAL(Invalid argument)
		return syzType.DefaultArg(dir)
	default:
		log.Fatalf("unsupported type for proc: %#v", traceType)
	}
	return nil
}

func (ctx *context) addr(syzType prog.Type, dir prog.Dir, size uint64, data prog.Arg) prog.Arg {
	return prog.MakePointerArg(syzType, dir, ctx.builder.Allocate(size, data.Type().Alignment()), data)
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
