// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package compiler

import (
	"bytes"
	"fmt"
	"reflect"
	"sort"

	"github.com/google/syzkaller/pkg/ast"
	"github.com/google/syzkaller/pkg/serializer"
	"github.com/google/syzkaller/prog"
)

const sizeUnassigned = ^uint64(0)

func (comp *compiler) genResources() []*prog.ResourceDesc {
	var resources []*prog.ResourceDesc
	for name, n := range comp.resources {
		if !comp.used[name] {
			continue
		}
		resources = append(resources, comp.genResource(n))
	}
	sort.Slice(resources, func(i, j int) bool {
		return resources[i].Name < resources[j].Name
	})
	return resources
}

func (comp *compiler) genResource(n *ast.Resource) *prog.ResourceDesc {
	res := &prog.ResourceDesc{
		Name: n.Name.Name,
	}
	for n != nil {
		res.Values = append(genIntArray(n.Values), res.Values...)
		res.Kind = append([]string{n.Name.Name}, res.Kind...)
		n = comp.resources[n.Base.Ident]
	}
	if len(res.Values) == 0 {
		res.Values = []uint64{0}
	}
	return res
}

func (comp *compiler) collectCallArgSizes() map[string][]uint64 {
	argPos := make(map[string]ast.Pos)
	callArgSizes := make(map[string][]uint64)
	for _, decl := range comp.desc.Nodes {
		n, ok := decl.(*ast.Call)
		if !ok {
			continue
		}
		// Figure out number of arguments and their sizes for each syscall.
		// For example, we may have:
		// ioctl(fd fd, cmd int32, arg intptr)
		// ioctl$FOO(fd fd, cmd const[FOO])
		// Here we will figure out that ioctl$FOO have 3 args, even that
		// only 2 are specified and that size of cmd is 4 even that
		// normally we would assume it's 8 (intptr).
		argSizes := callArgSizes[n.CallName]
		for i, arg := range n.Args {
			if len(argSizes) <= i {
				argSizes = append(argSizes, comp.ptrSize)
			}
			desc, _, _ := comp.getArgsBase(arg.Type, arg.Name.Name, prog.DirIn, true)
			typ := comp.genField(arg, prog.DirIn, comp.ptrSize)
			// Ignore all types with base (const, flags). We don't have base in syscall args.
			// Also ignore resources and pointers because fd can be 32-bits and pointer 64-bits,
			// and then there is no way to fix this.
			// The only relevant types left is plain int types.
			if desc != typeInt {
				continue
			}
			if !comp.target.Int64SyscallArgs && typ.Size() > comp.ptrSize {
				comp.error(arg.Pos, "%v arg %v is larger than pointer size", n.Name.Name, arg.Name.Name)
				continue
			}
			argID := fmt.Sprintf("%v|%v", n.CallName, i)
			if _, ok := argPos[argID]; !ok {
				argSizes[i] = typ.Size()
				argPos[argID] = arg.Pos
				continue
			}
			if argSizes[i] != typ.Size() {
				comp.error(arg.Pos, "%v arg %v is redeclared with size %v, previously declared with size %v at %v",
					n.Name.Name, arg.Name.Name, typ.Size(), argSizes[i], argPos[argID])
				continue
			}
		}
		callArgSizes[n.CallName] = argSizes
	}
	return callArgSizes
}

func (comp *compiler) genSyscalls() []*prog.Syscall {
	callArgSizes := comp.collectCallArgSizes()
	var calls []*prog.Syscall
	for _, decl := range comp.desc.Nodes {
		if n, ok := decl.(*ast.Call); ok && n.NR != ^uint64(0) {
			calls = append(calls, comp.genSyscall(n, callArgSizes[n.CallName]))
		}
	}
	sort.Slice(calls, func(i, j int) bool {
		return calls[i].Name < calls[j].Name
	})
	return calls
}

func (comp *compiler) genSyscall(n *ast.Call, argSizes []uint64) *prog.Syscall {
	var ret prog.Type
	if n.Ret != nil {
		ret = comp.genType(n.Ret, "ret", prog.DirOut, comp.ptrSize)
	}
	var attrs prog.SyscallAttrs
	descAttrs := comp.parseAttrs(callAttrs, n, n.Attrs)
	for desc, val := range descAttrs {
		fld := reflect.ValueOf(&attrs).Elem().FieldByName(desc.Name)
		if desc.HasArg {
			fld.SetUint(val)
		} else {
			fld.SetBool(val != 0)
		}
	}
	return &prog.Syscall{
		Name:        n.Name.Name,
		CallName:    n.CallName,
		NR:          n.NR,
		MissingArgs: len(argSizes) - len(n.Args),
		Args:        comp.genFieldArray(n.Args, prog.DirIn, argSizes),
		Ret:         ret,
		Attrs:       attrs,
	}
}

type typeProxy struct {
	typ       prog.Type
	id        string
	locations []*prog.Type
}

func (comp *compiler) generateTypes(syscalls []*prog.Syscall, structs []*prog.KeyedStruct) []prog.Type {
	// Replace all Type's in the descriptions with Ref's
	// and prepare a sorted array of corresponding real types.
	proxies := make(map[string]*typeProxy)
	for _, call := range syscalls {
		for i := range call.Args {
			comp.collectTypes(proxies, &call.Args[i])
		}
		if call.Ret != nil {
			comp.collectTypes(proxies, &call.Ret)
		}
	}
	for _, str := range structs {
		for i := range str.Desc.Fields {
			comp.collectTypes(proxies, &str.Desc.Fields[i])
		}
	}
	array := make([]*typeProxy, 0, len(proxies))
	for _, proxy := range proxies {
		array = append(array, proxy)
	}
	sort.Slice(array, func(i, j int) bool {
		return array[i].id < array[j].id
	})
	types := make([]prog.Type, len(array))
	for i, proxy := range array {
		types[i] = proxy.typ
		for _, loc := range proxy.locations {
			*loc = prog.Ref(i)
		}
	}
	return types
}

func (comp *compiler) collectTypes(proxies map[string]*typeProxy, tptr *prog.Type) {
	typ := *tptr
	switch t := typ.(type) {
	case *prog.PtrType:
		comp.collectTypes(proxies, &t.Type)
	case *prog.ArrayType:
		comp.collectTypes(proxies, &t.Type)
	case *prog.ResourceType, *prog.BufferType, *prog.VmaType, *prog.LenType,
		*prog.FlagsType, *prog.ConstType, *prog.IntType, *prog.ProcType,
		*prog.CsumType, *prog.StructType, *prog.UnionType:
	default:
		panic("unknown type")
	}
	buf := new(bytes.Buffer)
	serializer.Write(buf, typ)
	id := buf.String()
	proxy := proxies[id]
	if proxy == nil {
		proxy = &typeProxy{
			typ: typ,
			id:  id,
		}
		proxies[id] = proxy
	}
	proxy.locations = append(proxy.locations, tptr)
}

func (comp *compiler) genStructDescs(syscalls []*prog.Syscall) []*prog.KeyedStruct {
	// Calculate struct/union/array sizes, add padding to structs and detach
	// StructDesc's from StructType's. StructType's can be recursive so it's
	// not possible to write them out inline as other types. To break the
	// recursion detach them, and write StructDesc's out as separate array
	// of KeyedStruct's. prog package will reattach them during init.
	ctx := &structGen{
		comp:   comp,
		padded: make(map[interface{}]bool),
		detach: make(map[**prog.StructDesc]bool),
	}
	// We have to do this in the loop until we pad nothing new
	// due to recursive structs.
	for {
		start := len(ctx.padded)
		for _, c := range syscalls {
			for _, a := range c.Args {
				ctx.walk(a)
			}
			if c.Ret != nil {
				ctx.walk(c.Ret)
			}
		}
		if start == len(ctx.padded) {
			break
		}
	}

	// Detach StructDesc's from StructType's. prog will reattach them again.
	for descp := range ctx.detach {
		*descp = nil
	}

	sort.Slice(ctx.structs, func(i, j int) bool {
		si, sj := ctx.structs[i].Key, ctx.structs[j].Key
		if si.Name != sj.Name {
			return si.Name < sj.Name
		}
		return si.Dir < sj.Dir
	})
	return ctx.structs
}

type structGen struct {
	comp    *compiler
	padded  map[interface{}]bool
	detach  map[**prog.StructDesc]bool
	structs []*prog.KeyedStruct
}

func (ctx *structGen) check(key prog.StructKey, descp **prog.StructDesc) bool {
	ctx.detach[descp] = true
	desc := *descp
	if ctx.padded[desc] {
		return false
	}
	ctx.padded[desc] = true
	for _, f := range desc.Fields {
		ctx.walk(f)
		if !f.Varlen() && f.Size() == sizeUnassigned {
			// An inner struct is not padded yet.
			// Leave this struct for next iteration.
			delete(ctx.padded, desc)
			return false
		}
	}
	if ctx.comp.used[key.Name] {
		ctx.structs = append(ctx.structs, &prog.KeyedStruct{
			Key:  key,
			Desc: desc,
		})
	}
	return true
}

func (ctx *structGen) walk(t0 prog.Type) {
	switch t := t0.(type) {
	case *prog.PtrType:
		ctx.walk(t.Type)
	case *prog.ArrayType:
		ctx.walkArray(t)
	case *prog.StructType:
		ctx.walkStruct(t)
	case *prog.UnionType:
		ctx.walkUnion(t)
	}
}

func (ctx *structGen) walkArray(t *prog.ArrayType) {
	if ctx.padded[t] {
		return
	}
	ctx.walk(t.Type)
	if !t.Type.Varlen() && t.Type.Size() == sizeUnassigned {
		// An inner struct is not padded yet.
		// Leave this array for next iteration.
		return
	}
	ctx.padded[t] = true
	t.TypeSize = 0
	if t.Kind == prog.ArrayRangeLen && t.RangeBegin == t.RangeEnd && !t.Type.Varlen() {
		t.TypeSize = t.RangeBegin * t.Type.Size()
	}
}

func (ctx *structGen) walkStruct(t *prog.StructType) {
	if !ctx.check(t.Key, &t.StructDesc) {
		return
	}
	comp := ctx.comp
	structNode := comp.structNodes[t.StructDesc]
	// Add paddings, calculate size, mark bitfields.
	varlen := false
	for _, f := range t.Fields {
		if f.Varlen() {
			varlen = true
		}
	}
	attrs := comp.parseAttrs(structAttrs, structNode, structNode.Attrs)
	t.AlignAttr = attrs[attrAlign]
	comp.layoutStruct(t, varlen, attrs[attrPacked] != 0)
	t.TypeSize = 0
	if !varlen {
		for _, f := range t.Fields {
			t.TypeSize += f.Size()
		}
		sizeAttr, hasSize := attrs[attrSize]
		if hasSize {
			if t.TypeSize > sizeAttr {
				comp.error(structNode.Attrs[0].Pos, "struct %v has size attribute %v"+
					" which is less than struct size %v",
					structNode.Name.Name, sizeAttr, t.TypeSize)
			}
			if pad := sizeAttr - t.TypeSize; pad != 0 {
				t.Fields = append(t.Fields, genPad(pad))
			}
			t.TypeSize = sizeAttr
		}
	}
}

func (ctx *structGen) walkUnion(t *prog.UnionType) {
	if !ctx.check(t.Key, &t.StructDesc) {
		return
	}
	comp := ctx.comp
	structNode := comp.structNodes[t.StructDesc]
	attrs := comp.parseAttrs(unionAttrs, structNode, structNode.Attrs)
	t.TypeSize = 0
	if attrs[attrVarlen] != 0 {
		return
	}
	sizeAttr, hasSize := attrs[attrSize]
	for i, fld := range t.Fields {
		sz := fld.Size()
		if hasSize && sz > sizeAttr {
			comp.error(structNode.Fields[i].Pos, "union %v has size attribute %v"+
				" which is less than field %v size %v",
				structNode.Name.Name, sizeAttr, fld.Name(), sz)
		}
		if t.TypeSize < sz {
			t.TypeSize = sz
		}
	}
	if hasSize {
		t.TypeSize = sizeAttr
	}
}

func (comp *compiler) genStructDesc(res *prog.StructDesc, n *ast.Struct, dir prog.Dir, varlen bool) {
	// Leave node for genStructDescs to calculate size/padding.
	comp.structNodes[res] = n
	common := genCommon(n.Name.Name, "", sizeUnassigned, dir, false)
	common.IsVarlen = varlen
	*res = prog.StructDesc{
		TypeCommon: common,
		Fields:     comp.genFieldArray(n.Fields, dir, make([]uint64, len(n.Fields))),
	}
}

func (comp *compiler) layoutStruct(t *prog.StructType, varlen, packed bool) {
	var newFields []prog.Type
	var structAlign, byteOffset, bitOffset uint64
	for i, f := range t.Fields {
		fieldAlign := uint64(1)
		if !packed {
			fieldAlign = comp.typeAlign(f)
			if structAlign < fieldAlign {
				structAlign = fieldAlign
			}
		}
		fullBitOffset := byteOffset*8 + bitOffset
		var fieldOffset uint64

		if f.IsBitfield() {
			unitAlign := f.UnitSize()
			if packed {
				unitAlign = 1
			}
			fieldOffset = rounddown(fullBitOffset/8, unitAlign)
			unitBits := f.UnitSize() * 8
			occupiedBits := fullBitOffset - fieldOffset*8
			remainBits := unitBits - occupiedBits

			if remainBits < f.BitfieldLength() {
				fieldOffset = roundup(roundup(fullBitOffset, 8)/8, unitAlign)
				fullBitOffset, bitOffset = 0, 0
			} else if fieldOffset*8 >= fullBitOffset {
				fullBitOffset, bitOffset = fieldOffset*8, 0
			}
			fieldBitOffset := (fullBitOffset - fieldOffset*8) % unitBits
			setBitfieldOffset(f, fieldBitOffset)
		} else {
			fieldOffset = roundup(roundup(fullBitOffset, 8)/8, fieldAlign)
			bitOffset = 0
		}
		if fieldOffset > byteOffset {
			pad := fieldOffset - byteOffset
			byteOffset += pad
			if i != 0 && t.Fields[i-1].IsBitfield() {
				setBitfieldTypeSize(t.Fields[i-1], pad)
				if bitOffset >= 8*pad {
					// The padding is due to bitfields, so consume the bitOffset.
					bitOffset -= 8 * pad
				} else if bitOffset >= 8 {
					// Unclear is this is a bug or not and what to do in this case.
					// But since we don't have any descriptions that trigger this,
					// let's just guard with the panic.
					panic(fmt.Sprintf("bad bitOffset: %v.%v pad=%v bitOffset=%v",
						t.Name(), f.FieldName(), pad, bitOffset))
				}
			} else {
				newFields = append(newFields, genPad(pad))
			}
		}
		if f.IsBitfield() {
			if byteOffset > fieldOffset {
				unitOffset := byteOffset - fieldOffset
				setBitfieldUnitOffset(f, unitOffset)
			}
		}
		newFields = append(newFields, f)
		if f.IsBitfield() {
			bitOffset += f.BitfieldLength()
		} else if !f.Varlen() {
			// Increase offset if the current field except when it's
			// the last field in a struct and has variable length.
			byteOffset += f.Size()
		}
	}
	if bitOffset != 0 {
		pad := roundup(bitOffset, 8) / 8
		byteOffset += pad
		i := len(t.Fields)
		if i != 0 && t.Fields[i-1].IsBitfield() {
			setBitfieldTypeSize(t.Fields[i-1], pad)
		} else {
			newFields = append(newFields, genPad(pad))
		}
	}

	if t.AlignAttr != 0 {
		structAlign = t.AlignAttr
	}
	if !varlen && structAlign != 0 && byteOffset%structAlign != 0 {
		pad := structAlign - byteOffset%structAlign
		newFields = append(newFields, genPad(pad))
	}
	t.Fields = newFields
}

func roundup(v, a uint64) uint64 {
	return rounddown(v+a-1, a)
}

func rounddown(v, a uint64) uint64 {
	if (a & (a - 1)) != 0 {
		panic(fmt.Sprintf("rounddown(%v)", a))
	}
	return v & ^(a - 1)
}

func bitfieldFields(t0 prog.Type) (*uint64, *uint64, *uint64) {
	switch t := t0.(type) {
	case *prog.IntType:
		return &t.TypeSize, &t.BitfieldOff, &t.BitfieldUnitOff
	case *prog.ConstType:
		return &t.TypeSize, &t.BitfieldOff, &t.BitfieldUnitOff
	case *prog.LenType:
		return &t.TypeSize, &t.BitfieldOff, &t.BitfieldUnitOff
	case *prog.FlagsType:
		return &t.TypeSize, &t.BitfieldOff, &t.BitfieldUnitOff
	case *prog.ProcType:
		return &t.TypeSize, &t.BitfieldOff, &t.BitfieldUnitOff
	default:
		panic(fmt.Sprintf("type %#v can't be a bitfield", t))
	}
}

func setBitfieldTypeSize(t prog.Type, v uint64) {
	p, _, _ := bitfieldFields(t)
	*p = v
}

func setBitfieldOffset(t prog.Type, v uint64) {
	_, p, _ := bitfieldFields(t)
	*p = v
}

func setBitfieldUnitOffset(t prog.Type, v uint64) {
	_, _, p := bitfieldFields(t)
	*p = v
}

func (comp *compiler) typeAlign(t0 prog.Type) uint64 {
	switch t0.Format() {
	case prog.FormatNative, prog.FormatBigEndian:
	case prog.FormatStrDec, prog.FormatStrHex, prog.FormatStrOct:
		return 1
	default:
		panic("unknown binary format")
	}
	if prog.IsPad(t0) {
		return 1
	}
	switch t := t0.(type) {
	case *prog.ConstType, *prog.IntType, *prog.LenType, *prog.FlagsType, *prog.ProcType,
		*prog.CsumType, *prog.PtrType, *prog.VmaType, *prog.ResourceType:
		align := t0.UnitSize()
		if align == 8 && comp.target.Int64Alignment != 0 {
			align = comp.target.Int64Alignment
		}
		return align
	case *prog.BufferType:
		return 1
	case *prog.ArrayType:
		return comp.typeAlign(t.Type)
	case *prog.StructType:
		n := comp.structNodes[t.StructDesc]
		attrs := comp.parseAttrs(structAttrs, n, n.Attrs)
		if align := attrs[attrAlign]; align != 0 {
			return align // overrided by user attribute
		}
		if attrs[attrPacked] != 0 {
			return 1
		}
		align := uint64(0)
		for _, f := range t.Fields {
			if a := comp.typeAlign(f); align < a {
				align = a
			}
		}
		return align
	case *prog.UnionType:
		align := uint64(0)
		for _, f := range t.Fields {
			if a := comp.typeAlign(f); align < a {
				align = a
			}
		}
		return align
	default:
		panic(fmt.Sprintf("unknown type: %#v", t))
	}
}

func genPad(size uint64) prog.Type {
	return &prog.ConstType{
		IntTypeCommon: genIntCommon(genCommon("pad", "", size, prog.DirIn, false), 0, false),
		IsPad:         true,
	}
}

func (comp *compiler) genFieldArray(fields []*ast.Field, dir prog.Dir, argSizes []uint64) []prog.Type {
	var res []prog.Type
	for i, f := range fields {
		res = append(res, comp.genField(f, dir, argSizes[i]))
	}
	return res
}

func (comp *compiler) genField(f *ast.Field, dir prog.Dir, argSize uint64) prog.Type {
	return comp.genType(f.Type, f.Name.Name, dir, argSize)
}

func (comp *compiler) genType(t *ast.Type, field string, dir prog.Dir, argSize uint64) prog.Type {
	desc, args, base := comp.getArgsBase(t, field, dir, argSize != 0)
	if desc.Gen == nil {
		panic(fmt.Sprintf("no gen for %v %#v", field, t))
	}
	if argSize != 0 {
		// Now that we know a more precise size, patch the type.
		// This is somewhat hacky. Ideally we figure out the size earlier,
		// store it somewhere and use during generation of the arg base type.
		base.TypeSize = argSize
		if desc.CheckConsts != nil {
			desc.CheckConsts(comp, t, args, base)
		}
	}
	base.IsVarlen = desc.Varlen != nil && desc.Varlen(comp, t, args)
	return desc.Gen(comp, t, args, base)
}

func genCommon(name, field string, size uint64, dir prog.Dir, opt bool) prog.TypeCommon {
	return prog.TypeCommon{
		TypeName:   name,
		TypeSize:   size,
		FldName:    field,
		ArgDir:     dir,
		IsOptional: opt,
	}
}

func genIntCommon(com prog.TypeCommon, bitLen uint64, bigEndian bool) prog.IntTypeCommon {
	bf := prog.FormatNative
	if bigEndian {
		bf = prog.FormatBigEndian
	}
	bfUnit := uint64(0)
	if bitLen != 0 {
		bfUnit = com.TypeSize
		com.TypeSize = 0
	}
	return prog.IntTypeCommon{
		TypeCommon:   com,
		ArgFormat:    bf,
		BitfieldLen:  bitLen,
		BitfieldUnit: bfUnit,
	}
}

func genIntArray(a []*ast.Int) []uint64 {
	r := make([]uint64, len(a))
	for i, v := range a {
		r[i] = v.Value
	}
	return r
}

func genStrArray(a []*ast.String) []string {
	r := make([]string, len(a))
	for i, v := range a {
		r[i] = v.Value
	}
	return r
}
