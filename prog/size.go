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

func (target *Target) assignSizes(args []Arg, fields []Field, parents parentStack,
	syscallArgs []Arg, syscallFields []Field, autos map[Arg]bool, overlayField int) {
	for _, arg := range args {
		target.assignArgSize(arg, args, fields, parents, syscallArgs,
			syscallFields, autos, overlayField)
	}
}

func (target *Target) assignArgSize(arg Arg, args []Arg, fields []Field, parents parentStack,
	syscallArgs []Arg, syscallFields []Field, autos map[Arg]bool, overlayField int) {
	if arg = InnerArg(arg); arg == nil {
		return // Pointer to optional len field, no need to fill in value.
	}
	typ, ok := arg.Type().(*LenType)
	if !ok {
		return
	}
	if autos != nil {
		if !autos[arg] {
			return
		}
		delete(autos, arg)
	}
	a := arg.(*ConstArg)
	if typ.Path[0] == SyscallRef {
		target.assignSize(a, nil, typ.Path[1:], syscallArgs, syscallFields, parents, 0)
	} else {
		target.assignSize(a, a, typ.Path, args, fields, parents, overlayField)
	}
}

func (target *Target) assignSize(dst *ConstArg, pos Arg, path []string, args []Arg,
	fields []Field, parents parentStack, overlayField int) {
	found := target.findArg(pos, path, args, fields, parents, overlayField)
	if found != nil && !found.isAnyPtr {
		dst.Val = target.computeSize(found.arg, found.offset, dst.Type().(*LenType))
	}
}

type foundArg struct {
	arg      Arg
	offset   uint64
	isAnyPtr bool
}

func (target *Target) findFieldStruct(buf Arg, path []string, parents parentStack) *foundArg {
	switch arg := buf.(type) {
	case *GroupArg:
		typ := arg.Type().(*StructType)
		return target.findArg(buf, path, arg.Inner, typ.Fields, parents, typ.OverlayField)
	case *UnionArg:
		return target.findArg(buf, path, nil, nil, parents, 0)
	default:
		panic(fmt.Sprintf("unexpected arg type %#v", arg))
	}
}

func (target *Target) findArg(pos Arg, path []string, args []Arg, fields []Field,
	parents parentStack, overlayField int) *foundArg {
	elem := path[0]
	path = path[1:]
	var offset uint64
	for i, buf := range args {
		if i == overlayField {
			offset = 0
		}
		if buf == nil {
			continue
		}
		if elem != fields[i].Name {
			offset += buf.Size()
			continue
		}
		if typ := buf.Type(); typ == target.any.ptrPtr || typ == target.any.ptr64 {
			// If path points into squashed argument, we don't have the target argument.
			// In such case we simply leave size argument as is. It can't happen during generation,
			// only during mutation and mutation can set size to random values, so it should be fine.
			return &foundArg{buf, offset, true}
		}
		buf = InnerArg(buf)
		if buf == nil {
			return &foundArg{nil, offset, false}
		}
		if len(path) != 0 {
			return target.findFieldStruct(buf, path, parents)
		}
		return &foundArg{buf, offset, false}
	}
	if elem == ParentRef {
		parents, buf := popStack(parents)
		if len(path) != 0 {
			return target.findFieldStruct(buf, path, parents)
		}
		return &foundArg{buf, noOffset, false}
	}
	for parents, buf := popStack(parents); buf != nil; parents, buf = popStack(parents) {
		if elem != buf.Type().TemplateName() {
			continue
		}
		if len(path) != 0 {
			return target.findFieldStruct(buf, path, parents)
		}
		return &foundArg{buf, noOffset, false}
	}
	var fieldNames []string
	for _, field := range fields {
		fieldNames = append(fieldNames, field.Name)
	}
	posName := "nil"
	if pos != nil {
		posName = pos.Type().Name()
	}
	panic(fmt.Sprintf("path references non existent field %q, pos=%q, argsMap: %v, path: %v",
		elem, posName, fieldNames, path))
}

const noOffset = ^uint64(0)

func (target *Target) computeSize(arg Arg, offset uint64, lenType *LenType) uint64 {
	if lenType.Offset {
		if offset == noOffset {
			panic("offset of a non-field")
		}
		return offset * 8 / lenType.BitSize
	}
	if arg == nil {
		// For e.g. optional pointers.
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

func (target *Target) assignSizesArray(args []Arg, fields []Field, autos map[Arg]bool) {
	target.assignSizes(args, fields, nil, args, fields, autos, 0)
	for _, arg := range args {
		foreachSubArgWithStack(arg, func(arg Arg, ctx *ArgCtx) {
			if typ, ok := arg.Type().(*StructType); ok {
				target.assignSizes(arg.(*GroupArg).Inner, typ.Fields, ctx.parentStack, args, fields, autos, typ.OverlayField)
			}
			if v, ok := arg.(*UnionArg); ok {
				target.assignArgSize(v.Option, nil, nil, ctx.parentStack, args, fields, autos, 0)
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
					case *BufferType:
						// Don't mutate size of compressed images.
						// If we do, then our code will fail/crash on decompression.
						if targetType.Kind == BufferCompressed {
							return false
						}
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
