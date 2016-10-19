// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sys

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
		if off%a != 0 {
			pad := a - off%a
			off += pad
			fields = append(fields, makePad(pad))
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
		if !varLen {
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
		TypeCommon: TypeCommon{TypeName: "pad", IsOptional: false},
		TypeSize:   sz,
		Val:        0,
		IsPad:      true,
	}
}
