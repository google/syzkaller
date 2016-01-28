// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sys

import (
	"fmt"
)

func initAlign() {
	var rec func(t Type) Type
	rec = func(t Type) Type {
		switch t1 := t.(type) {
		case PtrType:
			t1.Type = rec(t1.Type)
			t = t1
		case ArrayType:
			t1.Type = rec(t1.Type)
			t = t1
		case StructType:
			for i, f := range t1.Fields {
				t1.Fields[i] = rec(f)
			}
			t = addAlignment(t1)
		case UnionType:
			opts := make(map[string]bool)
			for i, opt := range t1.Options {
				if opts[opt.Name()] {
					panic(fmt.Sprintf("duplicate option %v in union %v", opt.Name(), t.Name()))
				}
				opts[opt.Name()] = true
				t1.Options[i] = rec(opt)
			}
		}
		return t
	}
	for _, c := range Calls {
		for i, t := range c.Args {
			c.Args[i] = rec(t)
		}
		if c.Ret != nil {
			c.Ret = rec(c.Ret)
		}
	}
}

func addAlignment(t StructType) Type {
	if t.packed {
		t.padded = true
		return t
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
		off += f.Size()
		fields = append(fields, f)
		if at, ok := f.(ArrayType); ok && at.Len == 0 {
			varLen = true
		}
		if varLen && i != len(t.Fields)-1 {
			panic("embed array in middle of a struct")
		}
	}
	if align != 0 && off%align != 0 && !varLen {
		pad := align - off%align
		off += pad
		fields = append(fields, makePad(pad))
	}
	t.Fields = fields
	t.padded = true
	return t
}

func makePad(sz uintptr) Type {
	return ConstType{
		TypeCommon: TypeCommon{TypeName: "pad", IsOptional: false},
		TypeSize:   sz,
		Val:        0,
		IsPad:      true,
	}
}
