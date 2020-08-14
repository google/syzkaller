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
			desc, _, _ := comp.getArgsBase(arg.Type, true)
			typ := comp.genField(arg, comp.ptrSize)
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
		ret = comp.genType(n.Ret, comp.ptrSize)
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
		Args:        comp.genFieldArray(n.Args, argSizes),
		Ret:         ret,
		Attrs:       attrs,
	}
}

type typeProxy struct {
	typ       prog.Type
	id        string
	ref       prog.Ref
	locations []*prog.Type
}

func (comp *compiler) generateTypes(syscalls []*prog.Syscall) []prog.Type {
	// Replace all Type's in the descriptions with Ref's
	// and prepare a sorted array of corresponding real types.
	proxies := make(map[string]*typeProxy)
	prog.ForeachTypePost(syscalls, func(typ prog.Type, ctx prog.TypeCtx) {
		if _, ok := typ.(prog.Ref); ok {
			return
		}
		if !typ.Varlen() && typ.Size() == sizeUnassigned {
			panic("unassigned size")
		}
		id := typ.Name()
		switch typ.(type) {
		case *prog.StructType, *prog.UnionType:
			// There types can be uniquely identified with the name.
		default:
			buf := new(bytes.Buffer)
			serializer.Write(buf, typ)
			id = buf.String()
		}
		proxy := proxies[id]
		if proxy == nil {
			proxy = &typeProxy{
				typ: typ,
				id:  id,
				ref: prog.Ref(len(proxies)),
			}
			proxies[id] = proxy
		}
		*ctx.Ptr = proxy.ref
		proxy.locations = append(proxy.locations, ctx.Ptr)
	})
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

func (comp *compiler) layoutTypes(syscalls []*prog.Syscall) {
	// Calculate struct/union/array sizes, add padding to structs, mark bitfields.
	padded := make(map[prog.Type]bool)
	prog.ForeachTypePost(syscalls, func(typ prog.Type, _ prog.TypeCtx) {
		comp.layoutType(typ, padded)
	})
}

func (comp *compiler) layoutType(typ prog.Type, padded map[prog.Type]bool) {
	if padded[typ] {
		return
	}
	switch t := typ.(type) {
	case *prog.ArrayType:
		comp.layoutType(t.Elem, padded)
		comp.layoutArray(t)
	case *prog.StructType:
		for _, f := range t.Fields {
			comp.layoutType(f.Type, padded)
		}
		comp.layoutStruct(t)
	case *prog.UnionType:
		for _, f := range t.Fields {
			comp.layoutType(f.Type, padded)
		}
		comp.layoutUnion(t)
	default:
		return
	}
	if !typ.Varlen() && typ.Size() == sizeUnassigned {
		panic("size unassigned")
	}
	padded[typ] = true
}

func (comp *compiler) layoutArray(t *prog.ArrayType) {
	t.TypeSize = 0
	if t.Kind == prog.ArrayRangeLen && t.RangeBegin == t.RangeEnd && !t.Elem.Varlen() {
		t.TypeSize = t.RangeBegin * t.Elem.Size()
	}
}

func (comp *compiler) layoutUnion(t *prog.UnionType) {
	structNode := comp.structs[t.TypeName]
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
				structNode.Name.Name, sizeAttr, fld.Type.Name(), sz)
		}
		if t.TypeSize < sz {
			t.TypeSize = sz
		}
	}
	if hasSize {
		t.TypeSize = sizeAttr
	}
}

func (comp *compiler) layoutStruct(t *prog.StructType) {
	// Add paddings, calculate size, mark bitfields.
	structNode := comp.structs[t.TypeName]
	varlen := false
	for _, f := range t.Fields {
		if f.Varlen() {
			varlen = true
		}
	}
	attrs := comp.parseAttrs(structAttrs, structNode, structNode.Attrs)
	t.AlignAttr = attrs[attrAlign]
	comp.layoutStructFields(t, varlen, attrs[attrPacked] != 0)
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

func (comp *compiler) layoutStructFields(t *prog.StructType, varlen, packed bool) {
	var newFields []prog.Field
	var structAlign, byteOffset, bitOffset uint64
	for i, field := range t.Fields {
		f := field.Type
		fieldAlign := uint64(1)
		if !packed {
			fieldAlign = f.Alignment()
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
				setBitfieldTypeSize(t.Fields[i-1].Type, pad)
				if bitOffset >= 8*pad {
					// The padding is due to bitfields, so consume the bitOffset.
					bitOffset -= 8 * pad
				} else if bitOffset >= 8 {
					// Unclear is this is a bug or not and what to do in this case.
					// But since we don't have any descriptions that trigger this,
					// let's just guard with the panic.
					panic(fmt.Sprintf("bad bitOffset: %v.%v pad=%v bitOffset=%v",
						t.Name(), field.Name, pad, bitOffset))
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
		newFields = append(newFields, field)
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
			setBitfieldTypeSize(t.Fields[i-1].Type, pad)
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

func genPad(size uint64) prog.Field {
	return prog.Field{
		Type: &prog.ConstType{
			IntTypeCommon: genIntCommon(genCommon("pad", size, false), 0, false),
			IsPad:         true,
		},
	}
}

func (comp *compiler) genFieldArray(fields []*ast.Field, argSizes []uint64) []prog.Field {
	var res []prog.Field
	for i, f := range fields {
		res = append(res, comp.genField(f, argSizes[i]))
	}
	return res
}

func (comp *compiler) genFieldDir(f *ast.Field) (prog.Dir, bool) {
	attrs := comp.parseAttrs(fieldAttrs, f, f.Attrs)
	switch {
	case attrs[attrIn] != 0:
		return prog.DirIn, true
	case attrs[attrOut] != 0:
		return prog.DirOut, true
	case attrs[attrInOut] != 0:
		return prog.DirInOut, true
	default:
		return prog.DirIn, false
	}
}

func (comp *compiler) genField(f *ast.Field, argSize uint64) prog.Field {
	dir, hasDir := comp.genFieldDir(f)

	return prog.Field{
		Name:         f.Name.Name,
		Type:         comp.genType(f.Type, argSize),
		HasDirection: hasDir,
		Direction:    dir,
	}
}

func (comp *compiler) genType(t *ast.Type, argSize uint64) prog.Type {
	desc, args, base := comp.getArgsBase(t, argSize != 0)
	if desc.Gen == nil {
		panic(fmt.Sprintf("no gen for %v %#v", t.Ident, t))
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

func genCommon(name string, size uint64, opt bool) prog.TypeCommon {
	return prog.TypeCommon{
		TypeName:   name,
		TypeSize:   size,
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
