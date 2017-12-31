// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
)

func (target *Target) generateSize(arg Arg, lenType *LenType) uint64 {
	if arg == nil {
		// Arg is an optional pointer, set size to 0.
		return 0
	}

	byteSize := lenType.ByteSize
	if byteSize == 0 {
		byteSize = 1
	}
	switch arg.Type().(type) {
	case *VmaType:
		a := arg.(*PointerArg)
		return a.PagesNum * target.PageSize / byteSize
	case *ArrayType:
		a := arg.(*GroupArg)
		if lenType.ByteSize != 0 {
			return a.Size() / byteSize
		} else {
			return uint64(len(a.Inner))
		}
	default:
		return arg.Size() / byteSize
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
				a.Val = target.generateSize(InnerArg(buf), typ)
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

func (r *randGen) mutateSize(arg *ConstArg, parent []Arg) bool {
	typ := arg.Type().(*LenType)
	elemSize := typ.ByteSize
	if elemSize == 0 {
		elemSize = 1
		for _, field := range parent {
			if typ.Buf != field.Type().FieldName() {
				continue
			}
			if inner := InnerArg(field); inner != nil {
				switch targetType := inner.Type().(type) {
				case *VmaType:
					return false
				case *ArrayType:
					elemSize = targetType.Type.Size()
				}
			}
			break
		}
	}
	if r.oneOf(100) {
		arg.Val = r.rand64()
		return true
	}
	if r.bin() {
		// Small adjustment to trigger missed size checks.
		if arg.Val != 0 && r.bin() {
			arg.Val = r.randRangeInt(0, arg.Val-1)
		} else {
			arg.Val = r.randRangeInt(arg.Val+1, arg.Val+1000)
		}
		return true
	}
	// Try to provoke int overflows.
	max := ^uint64(0)
	if r.oneOf(3) {
		max = 1<<32 - 1
		if r.oneOf(2) {
			max = 1<<16 - 1
			if r.oneOf(2) {
				max = 1<<8 - 1
			}
		}
	}
	n := max / elemSize
	delta := uint64(1000 - r.biasedRand(1000, 10))
	if elemSize == 1 || r.oneOf(10) {
		n -= delta
	} else {
		n += delta
	}
	arg.Val = n
	return true
}
