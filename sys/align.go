// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sys

import (
	"fmt"
)

func initAlign() {
	var rec func(t Type)
	rec = func(t Type) {
		switch t1 := t.(type) {
		case *PtrType:
			rec(t1.Type)
		case *ArrayType:
			rec(t1.Type)
		case *StructType:
			if !t1.padded {
				t1.padded = true
				for _, f := range t1.Fields {
					rec(f)
				}
				markBitfields(t1)
				addAlignment(t1)
			}
		case *UnionType:
			for _, opt := range t1.Options {
				rec(opt)
			}
		}
	}

	for _, s := range Structs {
		rec(s)
	}
}

func setBitfieldOffset(t Type, offset uintptr, last bool) {
	switch t1 := t.(type) {
	case *IntType:
		t1.BitfieldOff = offset
		t1.BitfieldLst = last
	case *ConstType:
		t1.BitfieldOff = offset
		t1.BitfieldLst = last
	case *LenType:
		t1.BitfieldOff = offset
		t1.BitfieldLst = last
	case *FlagsType:
		t1.BitfieldOff = offset
		t1.BitfieldLst = last
	case *ProcType:
		t1.BitfieldOff = offset
		t1.BitfieldLst = last
	default:
		panic(fmt.Sprintf("type %+v can't be a bitfield", t1))
	}
}

func markBitfields(t *StructType) {
	var bfOffset uintptr
	for i, f := range t.Fields {
		if f.BitfieldLength() == 0 {
			continue
		}
		off, last := bfOffset, false
		bfOffset += f.BitfieldLength()
		if i == len(t.Fields)-1 || // Last bitfield in a group, if last field of the struct...
			t.Fields[i+1].BitfieldLength() == 0 || // or next field is not a bitfield...
			f.Size() != t.Fields[i+1].Size() || // or next field is of different size...
			bfOffset+t.Fields[i+1].BitfieldLength() > f.Size()*8 { // or next field does not fit into the current group.
			last, bfOffset = true, 0
		}
		setBitfieldOffset(f, off, last)
	}
}

func addAlignment(t *StructType) {
	if t.packed {
		return
	}
	var fields []Type
	var off, align uintptr
	varLen := false
	for i, f := range t.Fields {
		a := f.Align()
		if align < a {
			align = a
		}
		if i > 0 && (t.Fields[i-1].BitfieldLength() == 0 || t.Fields[i-1].BitfieldLast()) {
			// Append padding if the last field is not a bitfield or it's the last bitfield in a set.
			if off%a != 0 {
				pad := a - off%a
				off += pad
				fields = append(fields, makePad(pad))
			}
		}
		fields = append(fields, f)
		if at, ok := f.(*ArrayType); ok && (at.Kind == ArrayRandLen || (at.Kind == ArrayRangeLen && at.RangeBegin != at.RangeEnd)) {
			varLen = true
		}
		if at, ok := f.(*BufferType); ok && (at.Kind == BufferBlobRand || (at.Kind == BufferBlobRange && at.RangeBegin != at.RangeEnd)) {
			varLen = true
		}
		if varLen && i != len(t.Fields)-1 {
			panic("embed array in middle of a struct")
		}
		if (f.BitfieldLength() == 0 || f.BitfieldLast()) && !varLen {
			// Increase offset if the current field is not a bitfield or it's the last bitfield in a set.
			off += f.Size()
		}
	}
	if align != 0 && off%align != 0 && !varLen {
		pad := align - off%align
		off += pad
		fields = append(fields, makePad(pad))
	}
	t.Fields = fields
}

func makePad(sz uintptr) Type {
	return &ConstType{
		IntTypeCommon: IntTypeCommon{
			TypeCommon: TypeCommon{TypeName: "pad", IsOptional: false},
			TypeSize:   sz,
		},
		Val:   0,
		IsPad: true,
	}
}
