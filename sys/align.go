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
				t1.Varlen() // dummy call to initialize t1.varlen
				addAlignment(t1)
			}
		case *UnionType:
			for _, opt := range t1.Options {
				rec(opt)
			}
		}
	}

	for _, c := range Calls {
		for _, a := range c.Args {
			rec(a)
		}
		if c.Ret != nil {
			rec(c.Ret)
		}
	}
}

func addAlignment(t *StructType) {
	if t.IsPacked {
		// If a struct is packed, statically sized and has explicitly set alignment, add a padding.
		if !t.Varlen() && t.AlignAttr != 0 && t.Size()%t.AlignAttr != 0 {
			pad := t.AlignAttr - t.Size()%t.AlignAttr
			t.Fields = append(t.Fields, makePad(pad))
		}
		return
	}
	var fields []Type
	var off uint64
	align := t.AlignAttr
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
		if f.Varlen() && i != len(t.Fields)-1 {
			panic(fmt.Sprintf("variable length field %+v in the middle of a struct %+v", f, t))
		}
		fields = append(fields, f)
		if (f.BitfieldLength() == 0 || f.BitfieldLast()) && (i != len(t.Fields)-1 || !f.Varlen()) {
			// Increase offset if the current field is not a bitfield or it's the last bitfield in a set,
			// except when it's the last field in a struct and has variable length.
			off += f.Size()
		}
	}
	if align != 0 && off%align != 0 && !t.Varlen() {
		pad := align - off%align
		off += pad
		fields = append(fields, makePad(pad))
	}
	t.Fields = fields
}

func makePad(sz uint64) Type {
	return &ConstType{
		IntTypeCommon: IntTypeCommon{
			TypeCommon: TypeCommon{TypeName: "pad", IsOptional: false},
			TypeSize:   sz,
		},
		Val:   0,
		IsPad: true,
	}
}
