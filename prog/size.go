// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
)

const (
	// Special reference to the outer struct used in len targets.
	ParentRef = "parent"
	// Special reference directly to syscall arguments used in len targets.
	SyscallRef = "syscall"
)

func (target *Target) assignSizes(args []Arg, fields []Field, parentsMap map[Arg]Arg,
	syscallArgs []Arg, syscallFields []Field, autos map[Arg]bool) {
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
		if typ.Path[0] == SyscallRef {
			target.assignSize(a, nil, typ.Path[1:], syscallArgs, syscallFields, parentsMap)
		} else {
			target.assignSize(a, a, typ.Path, args, fields, parentsMap)
		}
	}
}

func (target *Target) assignSizeStruct(dst *ConstArg, buf Arg, path []string, parentsMap map[Arg]Arg) {
	arg := buf.(*GroupArg)
	typ := arg.Type().(*StructType)
	target.assignSize(dst, buf, path, arg.Inner, typ.Fields, parentsMap)
}

func (target *Target) assignSize(dst *ConstArg, pos Arg, path []string, args []Arg,
	fields []Field, parentsMap map[Arg]Arg) {
	elem := path[0]
	path = path[1:]
	var offset uint64
	for i, buf := range args {
		if elem != fields[i].Name {
			offset += buf.Size()
			continue
		}
		if typ := buf.Type(); typ == target.any.ptrPtr || typ == target.any.ptr64 {
			// If path points into squashed argument, we don't have the target argument.
			// In such case we simply leave size argument as is. It can't happen during generation,
			// only during mutation and mutation can set size to random values, so it should be fine.
			return
		}
		buf = InnerArg(buf)
		if buf == nil {
			dst.Val = 0 // target is an optional pointer
			return
		}
		if len(path) != 0 {
			target.assignSizeStruct(dst, buf, path, parentsMap)
			return
		}
		dst.Val = target.computeSize(buf, offset, dst.Type().(*LenType))
		return
	}
	if elem == ParentRef {
		buf := parentsMap[pos]
		if len(path) != 0 {
			target.assignSizeStruct(dst, buf, path, parentsMap)
			return
		}
		dst.Val = target.computeSize(buf, noOffset, dst.Type().(*LenType))
		return
	}
	for buf := parentsMap[pos]; buf != nil; buf = parentsMap[buf] {
		if elem != buf.Type().TemplateName() {
			continue
		}
		if len(path) != 0 {
			target.assignSizeStruct(dst, buf, path, parentsMap)
			return
		}
		dst.Val = target.computeSize(buf, noOffset, dst.Type().(*LenType))
		return
	}
	var fieldNames []string
	for _, field := range fields {
		fieldNames = append(fieldNames, field.Name)
	}
	panic(fmt.Sprintf("len field %q references non existent field %q, pos=%q, argsMap: %v, path: %v",
		dst.Type().Name(), elem, pos.Type().Name(), fieldNames, path))
}

const noOffset = ^uint64(0)

func (target *Target) computeSize(arg Arg, offset uint64, lenType *LenType) uint64 {
	if lenType.Offset {
		if offset == noOffset {
			panic("offset of a non-field")
		}
		return offset * 8 / lenType.BitSize
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

func (target *Target) assignSizesArray(args []Arg, fields []Field, autos map[Arg]bool) {
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
	target.assignSizes(args, fields, parentsMap, args, fields, autos)
	for _, arg := range args {
		ForeachSubArg(arg, func(arg Arg, _ *ArgCtx) {
			if typ, ok := arg.Type().(*StructType); ok {
				target.assignSizes(arg.(*GroupArg).Inner, typ.Fields, parentsMap, args, fields, autos)
			}
		})
	}
}

func (target *Target) assignSizesCall(c *Call) {
	target.assignSizesArray(c.Args, c.Meta.Args, nil)
}

func (r *randGen) mutateSize(arg *ConstArg, parent []Arg, fields []Field) bool {
	typ := arg.Type().(*LenType)
	elemSize := typ.BitSize / 8
	if elemSize == 0 {
		elemSize = 1
		// TODO(dvyukov): implement path support for size mutation.
		if len(typ.Path) == 1 {
			for i, field := range parent {
				if typ.Path[0] != fields[i].Name {
					continue
				}
				if inner := InnerArg(field); inner != nil {
					switch targetType := inner.Type().(type) {
					case *VmaType:
						return false
					case *ArrayType:
						if targetType.Elem.Varlen() {
							return false
						}
						elemSize = targetType.Elem.Size()
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
			arg.Val = r.randRangeInt(0, arg.Val-1, arg.Type().TypeBitSize(), 0)
		} else {
			arg.Val = r.randRangeInt(arg.Val+1, arg.Val+100, arg.Type().TypeBitSize(), 0)
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
