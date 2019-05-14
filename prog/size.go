// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
	"strings"
)

func (target *Target) assignSizes(args []Arg, parentsMap map[Arg]Arg, autos map[Arg]bool) {
	for _, arg := range args {
		if arg = InnerArg(arg); arg == nil {
			continue // Pointer to optional len field, no need to fill in value.
		}
		typ, ok := arg.Type().(*LenType)
		if !ok {
			continue
		}
		if autos != nil {
			if !autos[arg] {
				continue
			}
			delete(autos, arg)
		}
		a := arg.(*ConstArg)
		target.assignSize(a, a, typ.Path, args, parentsMap)
	}
}

func (target *Target) assignSize(dst *ConstArg, pos Arg, path []string, args []Arg, parentsMap map[Arg]Arg) {
	elem := path[0]
	path = path[1:]
	for _, buf := range args {
		if elem != buf.Type().FieldName() {
			continue
		}
		buf = InnerArg(buf)
		if len(path) == 0 {
			dst.Val = target.computeSize(buf, dst.Type().(*LenType))
		} else {
			target.assignSize(dst, buf, path, buf.(*GroupArg).Inner, parentsMap)
		}
		return
	}
	if elem == "parent" {
		buf := parentsMap[pos]
		if len(path) == 0 {
			dst.Val = target.computeSize(buf, dst.Type().(*LenType))
		} else {
			if path[0] == "parent" {
				buf = parentsMap[buf]
			}
			target.assignSize(dst, buf, path, buf.(*GroupArg).Inner, parentsMap)
		}
		return
	}
	for buf := parentsMap[pos]; buf != nil; buf = parentsMap[buf] {
		parentName := buf.Type().Name()
		if pos := strings.IndexByte(parentName, '['); pos != -1 {
			// For template parents, strip arguments.
			parentName = parentName[:pos]
		}
		if elem != parentName {
			continue
		}
		if len(path) == 0 {
			dst.Val = target.computeSize(buf, dst.Type().(*LenType))
		} else {
			target.assignSize(dst, buf, path, buf.(*GroupArg).Inner, parentsMap)
		}
		return
	}
	var argNames []string
	for _, arg := range args {
		argNames = append(argNames, arg.Type().FieldName())
	}
	panic(fmt.Sprintf("len field %q references non existent field %q, pos=%q/%q, argsMap: %+v",
		dst.Type().FieldName(), elem, pos.Type().Name(), pos.Type().FieldName(), argNames))
}

func (target *Target) computeSize(arg Arg, lenType *LenType) uint64 {
	if arg == nil {
		// Arg is an optional pointer, set size to 0.
		return 0
	}
	bitSize := lenType.BitSize
	if bitSize == 0 {
		bitSize = 8
	}
	switch arg.Type().(type) {
	case *VmaType:
		a := arg.(*PointerArg)
		return a.VmaSize * 8 / bitSize
	case *ArrayType:
		a := arg.(*GroupArg)
		if lenType.BitSize != 0 {
			return a.Size() * 8 / bitSize
		}
		return uint64(len(a.Inner))
	default:
		return arg.Size() * 8 / bitSize
	}
}

func (target *Target) assignSizesArray(args []Arg, autos map[Arg]bool) {
	parentsMap := make(map[Arg]Arg)
	for _, arg := range args {
		ForeachSubArg(arg, func(arg Arg, _ *ArgCtx) {
			if _, ok := arg.Type().(*StructType); ok {
				for _, field := range arg.(*GroupArg).Inner {
					parentsMap[InnerArg(field)] = arg
				}
			}
		})
	}
	target.assignSizes(args, parentsMap, autos)
	for _, arg := range args {
		ForeachSubArg(arg, func(arg Arg, _ *ArgCtx) {
			if _, ok := arg.Type().(*StructType); ok {
				target.assignSizes(arg.(*GroupArg).Inner, parentsMap, autos)
			}
		})
	}
}

func (target *Target) assignSizesCall(c *Call) {
	target.assignSizesArray(c.Args, nil)
}

func (r *randGen) mutateSize(arg *ConstArg, parent []Arg) bool {
	typ := arg.Type().(*LenType)
	elemSize := typ.BitSize / 8
	if elemSize == 0 {
		elemSize = 1
		// TODO(dvyukov): implement path support for size mutation.
		if len(typ.Path) == 1 {
			for _, field := range parent {
				if typ.Path[0] != field.Type().FieldName() {
					continue
				}
				if inner := InnerArg(field); inner != nil {
					switch targetType := inner.Type().(type) {
					case *VmaType:
						return false
					case *ArrayType:
						if targetType.Type.Varlen() {
							return false
						}
						elemSize = targetType.Type.Size()
					}
				}
				break
			}
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
