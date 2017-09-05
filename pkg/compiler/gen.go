// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package compiler

import (
	"fmt"
	"sort"

	"github.com/google/syzkaller/pkg/ast"
	"github.com/google/syzkaller/sys"
)

const sizeUnassigned = ^uint64(0)

func (comp *compiler) genResources() []*sys.ResourceDesc {
	var resources []*sys.ResourceDesc
	for _, decl := range comp.desc.Nodes {
		if n, ok := decl.(*ast.Resource); ok {
			resources = append(resources, comp.genResource(n))
		}
	}
	sort.Slice(resources, func(i, j int) bool {
		return resources[i].Name < resources[j].Name
	})
	return resources
}

func (comp *compiler) genResource(n *ast.Resource) *sys.ResourceDesc {
	res := &sys.ResourceDesc{
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
	res.Type = comp.genType(base, "", sys.DirIn, false)
	return res
}

func (comp *compiler) genSyscalls() []*sys.Syscall {
	var calls []*sys.Syscall
	for _, decl := range comp.desc.Nodes {
		if n, ok := decl.(*ast.Call); ok {
			calls = append(calls, comp.genSyscall(n))
		}
	}
	sort.Slice(calls, func(i, j int) bool {
		return calls[i].Name < calls[j].Name
	})
	for i, c := range calls {
		c.ID = i
	}
	return calls
}

func (comp *compiler) genSyscall(n *ast.Call) *sys.Syscall {
	var ret sys.Type
	if n.Ret != nil {
		ret = comp.genType(n.Ret, "ret", sys.DirOut, true)
	}
	return &sys.Syscall{
		Name:     n.Name.Name,
		CallName: n.CallName,
		NR:       n.NR,
		Args:     comp.genFieldArray(n.Args, sys.DirIn, true),
		Ret:      ret,
	}
}

func (comp *compiler) genStructDescs(syscalls []*sys.Syscall) []*sys.KeyedStruct {
	// Calculate struct/union/array sizes, add padding to structs and detach
	// StructDesc's from StructType's. StructType's can be recursive so it's
	// not possible to write them out inline as other types. To break the
	// recursion detach them, and write StructDesc's out as separate array
	// of KeyedStruct's. sys package will reattach them during init.

	padded := make(map[interface{}]bool)
	detach := make(map[**sys.StructDesc]bool)
	var structs []*sys.KeyedStruct
	var rec func(t sys.Type)
	checkStruct := func(key sys.StructKey, descp **sys.StructDesc) bool {
		detach[descp] = true
		desc := *descp
		if padded[desc] {
			return false
		}
		padded[desc] = true
		for _, f := range desc.Fields {
			rec(f)
			if !f.Varlen() && f.Size() == sizeUnassigned {
				// An inner struct is not padded yet.
				// Leave this struct for next iteration.
				delete(padded, desc)
				return false
			}
		}
		structs = append(structs, &sys.KeyedStruct{
			Key:  key,
			Desc: desc,
		})
		return true
	}
	rec = func(t0 sys.Type) {
		switch t := t0.(type) {
		case *sys.PtrType:
			rec(t.Type)
		case *sys.ArrayType:
			if padded[t] {
				return
			}
			rec(t.Type)
			if !t.Type.Varlen() && t.Type.Size() == sizeUnassigned {
				// An inner struct is not padded yet.
				// Leave this array for next iteration.
				return
			}
			padded[t] = true
			t.TypeSize = 0
			if t.Kind == sys.ArrayRangeLen && t.RangeBegin == t.RangeEnd && !t.Type.Varlen() {
				t.TypeSize = t.RangeBegin * t.Type.Size()
			}
		case *sys.StructType:
			if !checkStruct(t.Key, &t.StructDesc) {
				return
			}
			// Add paddings, calculate size, mark bitfields.
			varlen := false
			for _, f := range t.Fields {
				if f.Varlen() {
					varlen = true
				}
			}
			comp.markBitfields(t.Fields)
			packed, alignAttr := comp.parseStructAttrs(comp.structNodes[t.StructDesc])
			t.Fields = comp.addAlignment(t.Fields, varlen, packed, alignAttr)
			t.AlignAttr = alignAttr
			t.TypeSize = 0
			if !varlen {
				for _, f := range t.Fields {
					if !f.BitfieldMiddle() {
						t.TypeSize += f.Size()
					}
				}
			}
		case *sys.UnionType:
			if !checkStruct(t.Key, &t.StructDesc) {
				return
			}
			t.TypeSize = 0
			varlen := comp.parseUnionAttrs(comp.structNodes[t.StructDesc])
			if !varlen {
				for _, fld := range t.Fields {
					if t.TypeSize < fld.Size() {
						t.TypeSize = fld.Size()
					}
				}
			}
		}
	}

	// We have to do this in the loop until we pad nothing new
	// due to recursive structs.
	for {
		start := len(padded)
		for _, c := range syscalls {
			for _, a := range c.Args {
				rec(a)
			}
			if c.Ret != nil {
				rec(c.Ret)
			}
		}
		if start == len(padded) {
			break
		}
	}

	// Detach StructDesc's from StructType's. sys will reattach them again.
	for descp := range detach {
		*descp = nil
	}

	sort.Slice(structs, func(i, j int) bool {
		si, sj := structs[i], structs[j]
		if si.Key.Name != sj.Key.Name {
			return si.Key.Name < sj.Key.Name
		}
		return si.Key.Dir < sj.Key.Dir
	})
	return structs
}

func (comp *compiler) genStructDesc(res *sys.StructDesc, n *ast.Struct, dir sys.Dir) {
	// Leave node for genStructDescs to calculate size/padding.
	comp.structNodes[res] = n
	*res = sys.StructDesc{
		TypeCommon: genCommon(n.Name.Name, "", sizeUnassigned, dir, false),
		Fields:     comp.genFieldArray(n.Fields, dir, false),
	}
}

func (comp *compiler) isStructVarlen(name string) bool {
	if varlen, ok := comp.structVarlen[name]; ok {
		return varlen
	}
	s := comp.structs[name]
	if s.IsUnion && comp.parseUnionAttrs(s) {
		comp.structVarlen[name] = true
		return true
	}
	comp.structVarlen[name] = false // to not hang on recursive types
	varlen := false
	for _, fld := range s.Fields {
		if comp.isVarlen(fld.Type) {
			varlen = true
			break
		}
	}
	comp.structVarlen[name] = varlen
	return varlen
}

func (comp *compiler) markBitfields(fields []sys.Type) {
	var bfOffset uint64
	for i, f := range fields {
		if f.BitfieldLength() == 0 {
			continue
		}
		off, middle := bfOffset, true
		bfOffset += f.BitfieldLength()
		if i == len(fields)-1 || // Last bitfield in a group, if last field of the struct...
			fields[i+1].BitfieldLength() == 0 || // or next field is not a bitfield...
			f.Size() != fields[i+1].Size() || // or next field is of different size...
			bfOffset+fields[i+1].BitfieldLength() > f.Size()*8 { // or next field does not fit into the current group.
			middle, bfOffset = false, 0
		}
		setBitfieldOffset(f, off, middle)
	}
}

func setBitfieldOffset(t0 sys.Type, offset uint64, middle bool) {
	switch t := t0.(type) {
	case *sys.IntType:
		t.BitfieldOff, t.BitfieldMdl = offset, middle
	case *sys.ConstType:
		t.BitfieldOff, t.BitfieldMdl = offset, middle
	case *sys.LenType:
		t.BitfieldOff, t.BitfieldMdl = offset, middle
	case *sys.FlagsType:
		t.BitfieldOff, t.BitfieldMdl = offset, middle
	case *sys.ProcType:
		t.BitfieldOff, t.BitfieldMdl = offset, middle
	default:
		panic(fmt.Sprintf("type %#v can't be a bitfield", t))
	}
}

func (comp *compiler) addAlignment(fields []sys.Type, varlen, packed bool, alignAttr uint64) []sys.Type {
	var newFields []sys.Type
	if packed {
		// If a struct is packed, statically sized and has explicitly set alignment,
		// add a padding at the end.
		newFields = fields
		if !varlen && alignAttr != 0 {
			size := uint64(0)
			for _, f := range fields {
				size += f.Size()
			}
			if tail := size % alignAttr; tail != 0 {
				newFields = append(newFields, genPad(alignAttr-tail))
			}
		}
		return newFields
	}
	var align, off uint64
	for i, f := range fields {
		if i > 0 && !fields[i-1].BitfieldMiddle() {
			a := comp.typeAlign(f)
			if align < a {
				align = a
			}
			// Append padding if the last field is not a bitfield or it's the last bitfield in a set.
			if off%a != 0 {
				pad := a - off%a
				off += pad
				newFields = append(newFields, genPad(pad))
			}
		}
		newFields = append(newFields, f)
		if !f.BitfieldMiddle() && (i != len(fields)-1 || !f.Varlen()) {
			// Increase offset if the current field is not a bitfield
			// or it's the last bitfield in a set, except when it's
			// the last field in a struct and has variable length.
			off += f.Size()
		}
	}
	if alignAttr != 0 {
		align = alignAttr
	}
	if align != 0 && off%align != 0 && !varlen {
		pad := align - off%align
		off += pad
		newFields = append(newFields, genPad(pad))
	}
	return newFields
}

func (comp *compiler) typeAlign(t0 sys.Type) uint64 {
	switch t0.(type) {
	case *sys.IntType, *sys.ConstType, *sys.LenType, *sys.FlagsType, *sys.ProcType,
		*sys.CsumType, *sys.PtrType, *sys.VmaType, *sys.ResourceType:
		return t0.Size()
	case *sys.BufferType:
		return 1
	}

	switch t := t0.(type) {
	case *sys.ArrayType:
		return comp.typeAlign(t.Type)
	case *sys.StructType:
		packed, alignAttr := comp.parseStructAttrs(comp.structNodes[t.StructDesc])
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
	case *sys.UnionType:
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

func genPad(size uint64) sys.Type {
	return &sys.ConstType{
		IntTypeCommon: genIntCommon(genCommon("pad", "", size, sys.DirIn, false), 0, false),
		IsPad:         true,
	}
}

func (comp *compiler) genField(f *ast.Field, dir sys.Dir, isArg bool) sys.Type {
	return comp.genType(f.Type, f.Name.Name, dir, isArg)
}

func (comp *compiler) genFieldArray(fields []*ast.Field, dir sys.Dir, isArg bool) []sys.Type {
	var res []sys.Type
	for _, f := range fields {
		res = append(res, comp.genField(f, dir, isArg))
	}
	return res
}

func (comp *compiler) genType(t *ast.Type, field string, dir sys.Dir, isArg bool) sys.Type {
	desc, args, base := comp.getArgsBase(t, field, dir, isArg)
	return desc.Gen(comp, t, args, base)
}

func genCommon(name, field string, size uint64, dir sys.Dir, opt bool) sys.TypeCommon {
	return sys.TypeCommon{
		TypeName:   name,
		TypeSize:   size,
		FldName:    field,
		ArgDir:     dir,
		IsOptional: opt,
	}
}

func genIntCommon(com sys.TypeCommon, bitLen uint64, bigEndian bool) sys.IntTypeCommon {
	return sys.IntTypeCommon{
		TypeCommon:  com,
		BigEndian:   bigEndian,
		BitfieldLen: bitLen,
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
