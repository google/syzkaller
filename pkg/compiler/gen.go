// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package compiler

import (
	"fmt"
	"sort"

	"github.com/google/syzkaller/pkg/ast"
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
	var base *ast.Type
	for n != nil {
		res.Values = append(genIntArray(n.Values), res.Values...)
		res.Kind = append([]string{n.Name.Name}, res.Kind...)
		base = n.Base
		n = comp.resources[n.Base.Ident]
	}
	if len(res.Values) == 0 {
		res.Values = []uint64{0}
	}
	res.Type = comp.genType(base, "", prog.DirIn, false)
	return res
}

func (comp *compiler) genSyscalls() []*prog.Syscall {
	var calls []*prog.Syscall
	callArgs := make(map[string]int)
	for _, decl := range comp.desc.Nodes {
		if n, ok := decl.(*ast.Call); ok {
			if callArgs[n.CallName] < len(n.Args) {
				callArgs[n.CallName] = len(n.Args)
			}
		}
	}
	for _, decl := range comp.desc.Nodes {
		if n, ok := decl.(*ast.Call); ok && n.NR != ^uint64(0) {
			calls = append(calls, comp.genSyscall(n, callArgs[n.CallName]))
		}
	}
	sort.Slice(calls, func(i, j int) bool {
		return calls[i].Name < calls[j].Name
	})
	return calls
}

func (comp *compiler) genSyscall(n *ast.Call, maxArgs int) *prog.Syscall {
	var ret prog.Type
	if n.Ret != nil {
		ret = comp.genType(n.Ret, "ret", prog.DirOut, true)
	}
	return &prog.Syscall{
		Name:        n.Name.Name,
		CallName:    n.CallName,
		NR:          n.NR,
		MissingArgs: maxArgs - len(n.Args),
		Args:        comp.genFieldArray(n.Args, prog.DirIn, true),
		Ret:         ret,
	}
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
		si, sj := ctx.structs[i], ctx.structs[j]
		if si.Key.Name != sj.Key.Name {
			return si.Key.Name < sj.Key.Name
		}
		return si.Key.Dir < sj.Key.Dir
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
	packed, sizeAttr, alignAttr := comp.parseStructAttrs(structNode)
	t.AlignAttr = alignAttr
	comp.layoutStruct(t, varlen, packed)
	t.TypeSize = 0
	if !varlen {
		for _, f := range t.Fields {
			t.TypeSize += f.Size()
		}
		if sizeAttr != sizeUnassigned {
			if t.TypeSize > sizeAttr {
				comp.error(structNode.Pos, "struct %v has size attribute %v"+
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
	varlen, sizeAttr := comp.parseUnionAttrs(structNode)
	t.TypeSize = 0
	if !varlen {
		for _, fld := range t.Fields {
			sz := fld.Size()
			if sizeAttr != sizeUnassigned && sz > sizeAttr {
				comp.error(structNode.Pos, "union %v has size attribute %v"+
					" which is less than field %v size %v",
					structNode.Name.Name, sizeAttr, fld.Name(), sz)
			}
			if t.TypeSize < sz {
				t.TypeSize = sz
			}
		}
		if sizeAttr != sizeUnassigned {
			t.TypeSize = sizeAttr
		}
	}
}

func (comp *compiler) genStructDesc(res *prog.StructDesc, n *ast.Struct, dir prog.Dir, varlen bool) {
	// Leave node for genStructDescs to calculate size/padding.
	comp.structNodes[res] = n
	common := genCommon(n.Name.Name, "", sizeUnassigned, dir, false)
	common.IsVarlen = varlen
	*res = prog.StructDesc{
		TypeCommon: common,
		Fields:     comp.genFieldArray(n.Fields, dir, false),
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
		packed, _, alignAttr := comp.parseStructAttrs(comp.structNodes[t.StructDesc])
		if alignAttr != 0 {
			return alignAttr // overrided by user attribute
		}
		if packed {
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

func (comp *compiler) genField(f *ast.Field, dir prog.Dir, isArg bool) prog.Type {
	return comp.genType(f.Type, f.Name.Name, dir, isArg)
}

func (comp *compiler) genFieldArray(fields []*ast.Field, dir prog.Dir, isArg bool) []prog.Type {
	var res []prog.Type
	for _, f := range fields {
		res = append(res, comp.genField(f, dir, isArg))
	}
	return res
}

func (comp *compiler) genType(t *ast.Type, field string, dir prog.Dir, isArg bool) prog.Type {
	desc, args, base := comp.getArgsBase(t, field, dir, isArg)
	if desc.Gen == nil {
		panic(fmt.Sprintf("no gen for %v %#v", field, t))
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
