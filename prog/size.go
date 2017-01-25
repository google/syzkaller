// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"

	"github.com/google/syzkaller/sys"
)

func generateSize(arg *Arg, lenType *sys.LenType) *Arg {
	if arg == nil {
		// Arg is an optional pointer, set size to 0.
		return constArg(lenType, 0)
	}

	switch arg.Type.(type) {
	case *sys.VmaType:
		return pageSizeArg(lenType, arg.AddrPagesNum, 0)
	case *sys.ArrayType:
		if lenType.ByteSize != 0 {
			return constArg(lenType, arg.Size()/lenType.ByteSize)
		} else {
			return constArg(lenType, uintptr(len(arg.Inner)))
		}
	default:
		if lenType.ByteSize != 0 {
			return constArg(lenType, arg.Size()/lenType.ByteSize)
		} else {
			return constArg(lenType, arg.Size())
		}
	}
}

func assignSizes(args []*Arg, parentsMap map[*Arg]*Arg) {
	// Create a map of args and calculate size of the whole struct.
	argsMap := make(map[string]*Arg)
	for _, arg := range args {
		if sys.IsPad(arg.Type) {
			continue
		}
		argsMap[arg.Type.FieldName()] = arg
	}

	// Fill in size arguments.
	for _, arg := range args {
		if arg = arg.InnerArg(); arg == nil {
			continue // Pointer to optional len field, no need to fill in value.
		}
		if typ, ok := arg.Type.(*sys.LenType); ok {
			buf, ok := argsMap[typ.Buf]
			if ok {
				*arg = *generateSize(buf.InnerArg(), typ)
				continue
			}

			if typ.Buf == "parent" {
				arg.Val = parentsMap[arg].Size()
				if typ.ByteSize != 0 {
					arg.Val /= typ.ByteSize
				}
				continue
			}

			sizeAssigned := false
			for parent := parentsMap[arg]; parent != nil; parent = parentsMap[parent] {
				if typ.Buf == parent.Type.Name() {
					arg.Val = parent.Size()
					if typ.ByteSize != 0 {
						arg.Val /= typ.ByteSize
					}
					sizeAssigned = true
					break
				}
			}
			if sizeAssigned {
				continue
			}

			panic(fmt.Sprintf("len field '%v' references non existent field '%v', argsMap: %+v",
				typ.FieldName(), typ.Buf, argsMap))
		}
	}
}

func assignSizesArray(args []*Arg) {
	parentsMap := make(map[*Arg]*Arg)
	foreachArgArray(&args, nil, func(arg, base *Arg, _ *[]*Arg) {
		if _, ok := arg.Type.(*sys.StructType); ok {
			for _, field := range arg.Inner {
				parentsMap[field.InnerArg()] = arg
			}
		}
	})
	assignSizes(args, parentsMap)
	foreachArgArray(&args, nil, func(arg, base *Arg, _ *[]*Arg) {
		if _, ok := arg.Type.(*sys.StructType); ok {
			assignSizes(arg.Inner, parentsMap)
		}
	})
}

func assignSizesCall(c *Call) {
	assignSizesArray(c.Args)
}
