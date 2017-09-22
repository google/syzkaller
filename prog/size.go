// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
)

func (target *Target) generateSize(arg Arg, lenType *LenType) Arg {
	if arg == nil {
		// Arg is an optional pointer, set size to 0.
		return MakeConstArg(lenType, 0)
	}

	switch arg.Type().(type) {
	case *VmaType:
		a := arg.(*PointerArg)
		return MakeConstArg(lenType, a.PagesNum*target.PageSize)
	case *ArrayType:
		a := arg.(*GroupArg)
		if lenType.ByteSize != 0 {
			return MakeConstArg(lenType, a.Size()/lenType.ByteSize)
		} else {
			return MakeConstArg(lenType, uint64(len(a.Inner)))
		}
	default:
		if lenType.ByteSize != 0 {
			return MakeConstArg(lenType, arg.Size()/lenType.ByteSize)
		} else {
			return MakeConstArg(lenType, arg.Size())
		}
	}
}

func (target *Target) assignSizes(args []Arg, parentsMap map[Arg]Arg) {
	// Create a map from field names to args.
	argsMap := make(map[string]Arg)
	for _, arg := range args {
		if IsPad(arg.Type()) {
			continue
		}
		argsMap[arg.Type().FieldName()] = arg
	}

	// Fill in size arguments.
	for _, arg := range args {
		if arg = InnerArg(arg); arg == nil {
			continue // Pointer to optional len field, no need to fill in value.
		}
		if typ, ok := arg.Type().(*LenType); ok {
			a := arg.(*ConstArg)

			buf, ok := argsMap[typ.Buf]
			if ok {
				*a = *target.generateSize(InnerArg(buf), typ).(*ConstArg)
				continue
			}

			if typ.Buf == "parent" {
				a.Val = parentsMap[arg].Size()
				if typ.ByteSize != 0 {
					a.Val /= typ.ByteSize
				}
				continue
			}

			sizeAssigned := false
			for parent := parentsMap[arg]; parent != nil; parent = parentsMap[parent] {
				if typ.Buf == parent.Type().Name() {
					a.Val = parent.Size()
					if typ.ByteSize != 0 {
						a.Val /= typ.ByteSize
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

func (target *Target) assignSizesArray(args []Arg) {
	parentsMap := make(map[Arg]Arg)
	foreachArgArray(&args, nil, func(arg, base Arg, _ *[]Arg) {
		if _, ok := arg.Type().(*StructType); ok {
			for _, field := range arg.(*GroupArg).Inner {
				parentsMap[InnerArg(field)] = arg
			}
		}
	})
	target.assignSizes(args, parentsMap)
	foreachArgArray(&args, nil, func(arg, base Arg, _ *[]Arg) {
		if _, ok := arg.Type().(*StructType); ok {
			target.assignSizes(arg.(*GroupArg).Inner, parentsMap)
		}
	})
}

func (target *Target) assignSizesCall(c *Call) {
	target.assignSizesArray(c.Args)
}
