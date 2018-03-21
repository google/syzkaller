package prog

import (
	"fmt"
)

type anyTypes struct {
	union  *UnionType
	array  *ArrayType
	blob   *BufferType
	ptrPtr *PtrType
	ptr64  *PtrType
	res16  *ResourceType
	res32  *ResourceType
	res64  *ResourceType
}

// This generates type descriptions for:
//
// resource ANYRES16[int16]: 0xffffffffffffffff, 0
// resource ANYRES32[int32]: 0xffffffffffffffff, 0
// resource ANYRES64[int64]: 0xffffffffffffffff, 0
// ANY [
// 	bin	array[int8]
// 	ptr	ptr[in, array[ANY], opt]
// 	ptr64	ptr64[in, array[ANY], opt]
// 	res16	ANYRES16
// 	res32	ANYRES32
// 	res64	ANYRES64
// ] [varlen]
func initAnyTypes(target *Target) {
	target.any.union = &UnionType{
		FldName: "ANYUNION",
	}
	target.any.array = &ArrayType{
		TypeCommon: TypeCommon{
			TypeName: "ANYARRAY",
			FldName:  "ANYARRAY",
			IsVarlen: true,
		},
		Type: target.any.union,
	}
	target.any.ptrPtr = &PtrType{
		TypeCommon: TypeCommon{
			TypeName:   "ptr",
			FldName:    "ANYPTR",
			TypeSize:   target.PtrSize,
			IsOptional: true,
		},
		Type: target.any.array,
	}
	target.any.ptr64 = &PtrType{
		TypeCommon: TypeCommon{
			TypeName:   "ptr64",
			FldName:    "ANYPTR64",
			TypeSize:   8,
			IsOptional: true,
		},
		Type: target.any.array,
	}
	target.any.blob = &BufferType{
		TypeCommon: TypeCommon{
			TypeName: "ANYBLOB",
			FldName:  "ANYBLOB",
			IsVarlen: true,
		},
	}
	createResource := func(name, base string, size uint64) *ResourceType {
		return &ResourceType{
			TypeCommon: TypeCommon{
				TypeName:   name,
				FldName:    name,
				ArgDir:     DirIn,
				TypeSize:   size,
				IsOptional: true,
			},
			Desc: &ResourceDesc{
				Name:   name,
				Kind:   []string{name},
				Values: []uint64{^uint64(0), 0},
				Type: &IntType{
					IntTypeCommon: IntTypeCommon{
						TypeCommon: TypeCommon{
							TypeName: base,
							TypeSize: size,
						},
					},
				},
			},
		}
	}
	target.any.res16 = createResource("ANYRES16", "int16", 2)
	target.any.res32 = createResource("ANYRES32", "int32", 4)
	target.any.res64 = createResource("ANYRES64", "int64", 8)
	target.any.union.StructDesc = &StructDesc{
		TypeCommon: TypeCommon{
			TypeName: "ANYUNION",
			FldName:  "ANYUNION",
			IsVarlen: true,
			ArgDir:   DirIn,
		},
		Fields: []Type{
			target.any.blob,
			target.any.ptrPtr,
			target.any.ptr64,
			target.any.res16,
			target.any.res32,
			target.any.res64,
		},
	}
}

func (target *Target) makeAnyPtrType(size uint64, field string) *PtrType {
	// We need to make a copy because type holds field name,
	// and field names are used as len target.
	var typ PtrType
	if size == target.PtrSize {
		typ = *target.any.ptrPtr
	} else if size == 8 {
		typ = *target.any.ptr64
	} else {
		panic(fmt.Sprintf("bad pointer size %v", size))
	}
	typ.TypeSize = size
	if field != "" {
		typ.FldName = field
	}
	return &typ
}

func (target *Target) isAnyPtr(typ Type) bool {
	ptr, ok := typ.(*PtrType)
	return ok && ptr.Type == target.any.array
}

func (p *Prog) complexPtrs() (res []*PointerArg) {
	for _, c := range p.Calls {
		ForeachArg(c, func(arg Arg, ctx *ArgCtx) {
			if ptrArg, ok := arg.(*PointerArg); ok && p.Target.isComplexPtr(ptrArg) {
				res = append(res, ptrArg)
				ctx.Stop = true
			}
		})
	}
	return
}

func (target *Target) isComplexPtr(arg *PointerArg) bool {
	if arg.Res == nil || arg.Type().Dir() != DirIn {
		return false
	}
	if target.isAnyPtr(arg.Type()) {
		return true
	}
	res := false
	ForeachSubArg(arg.Res, func(a1 Arg, ctx *ArgCtx) {
		switch typ := a1.Type().(type) {
		case *StructType:
			if typ.Varlen() {
				res = true
				ctx.Stop = true
			}
		case *UnionType:
			if typ.Varlen() && len(typ.Fields) > 5 {
				res = true
				ctx.Stop = true
			}
		case *PtrType:
			if a1 != arg {
				ctx.Stop = true
			}
		}
	})
	return res
}

func (target *Target) CallContainsAny(c *Call) (res bool) {
	ForeachArg(c, func(arg Arg, ctx *ArgCtx) {
		if target.isAnyPtr(arg.Type()) {
			res = true
			ctx.Stop = true
		}
	})
	return
}

func (target *Target) ArgContainsAny(arg0 Arg) (res bool) {
	ForeachSubArg(arg0, func(arg Arg, ctx *ArgCtx) {
		if target.isAnyPtr(arg.Type()) {
			res = true
			ctx.Stop = true
		}
	})
	return
}

func (target *Target) squashPtr(arg *PointerArg, preserveField bool) {
	if arg.Res == nil || arg.VmaSize != 0 {
		panic("bad ptr arg")
	}
	res0 := arg.Res
	size0 := res0.Size()
	var elems []Arg
	target.squashPtrImpl(arg.Res, &elems)
	field := ""
	if preserveField {
		field = arg.Type().FieldName()
	}
	arg.typ = target.makeAnyPtrType(arg.Type().Size(), field)
	arg.Res = MakeGroupArg(arg.typ.(*PtrType).Type, elems)
	if size := arg.Res.Size(); size != size0 {
		panic(fmt.Sprintf("squash changed size %v->%v for %v", size0, size, res0.Type()))
	}
}

func (target *Target) squashPtrImpl(a Arg, elems *[]Arg) {
	if a.Type().BitfieldLength() != 0 {
		panic("bitfield in squash")
	}
	var pad uint64
	switch arg := a.(type) {
	case *ConstArg:
		if IsPad(arg.Type()) {
			pad = arg.Size()
		} else {
			v := target.squashConst(arg)
			elem := target.ensureDataElem(elems)
			for i := uint64(0); i < arg.Size(); i++ {
				elem.data = append(elem.Data(), byte(v))
				v >>= 8
			}
		}
	case *ResultArg:
		switch arg.Size() {
		case 2:
			arg.typ = target.any.res16
		case 4:
			arg.typ = target.any.res32
		case 8:
			arg.typ = target.any.res64
		default:
			panic("bad size")
		}
		*elems = append(*elems, MakeUnionArg(target.any.union, arg))
	case *PointerArg:
		if arg.Res != nil {
			target.squashPtr(arg, false)
			*elems = append(*elems, MakeUnionArg(target.any.union, arg))
		} else {
			elem := target.ensureDataElem(elems)
			addr := target.PhysicalAddr(arg)
			for i := uint64(0); i < arg.Size(); i++ {
				elem.data = append(elem.Data(), byte(addr))
				addr >>= 8
			}
		}
	case *UnionArg:
		if !arg.Type().Varlen() {
			pad = arg.Size() - arg.Option.Size()
		}
		target.squashPtrImpl(arg.Option, elems)
	case *DataArg:
		if arg.Type().Dir() == DirOut {
			pad = arg.Size()
		} else {
			elem := target.ensureDataElem(elems)
			elem.data = append(elem.Data(), arg.Data()...)
		}
	case *GroupArg:
		if typ, ok := arg.Type().(*StructType); ok && typ.Varlen() && typ.AlignAttr != 0 {
			var fieldsSize uint64
			for _, fld := range arg.Inner {
				if !fld.Type().BitfieldMiddle() {
					fieldsSize += fld.Size()
				}
			}
			if fieldsSize%typ.AlignAttr != 0 {
				pad = typ.AlignAttr - fieldsSize%typ.AlignAttr
			}
		}
		var bitfield uint64
		for _, fld := range arg.Inner {
			// Squash bitfields separately.
			if bfLen := fld.Type().BitfieldLength(); bfLen != 0 {
				bfOff := fld.Type().BitfieldOffset()
				// Note: we can have a ResultArg here as well,
				// but it is unsupported at the moment.
				v := target.squashConst(fld.(*ConstArg))
				bitfield |= (v & ((1 << bfLen) - 1)) << bfOff
				if !fld.Type().BitfieldMiddle() {
					elem := target.ensureDataElem(elems)
					for i := uint64(0); i < fld.Size(); i++ {
						elem.data = append(elem.Data(), byte(bitfield))
						bitfield >>= 8
					}
					bitfield = 0
				}
				continue
			}
			target.squashPtrImpl(fld, elems)
		}
	default:
		panic("bad arg kind")
	}
	if pad != 0 {
		elem := target.ensureDataElem(elems)
		elem.data = append(elem.Data(), make([]byte, pad)...)
	}
}

func (target *Target) squashConst(arg *ConstArg) uint64 {
	// Note: we need a constant value, but it depends on pid for proc.
	v := arg.ValueForProc(0)
	if _, ok := arg.Type().(*CsumType); ok {
		// We can't compute value for the checksum here,
		// but at least leave something recognizable by hints code.
		v = 0xabcdef1234567890
	}
	return v
}

func (target *Target) ensureDataElem(elems *[]Arg) *DataArg {
	if len(*elems) == 0 {
		res := MakeDataArg(target.any.blob, nil)
		*elems = append(*elems, MakeUnionArg(target.any.union, res))
		return res
	}
	res, ok := (*elems)[len(*elems)-1].(*UnionArg).Option.(*DataArg)
	if !ok {
		res = MakeDataArg(target.any.blob, nil)
		*elems = append(*elems, MakeUnionArg(target.any.union, res))
	}
	return res
}
