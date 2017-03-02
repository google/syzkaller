// Copyright 2015/2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sys

import (
	"fmt"
)

const ptrSize = 8

type Call struct {
	ID       int
	NR       int // kernel syscall number
	Name     string
	CallName string
	Args     []Type
	Ret      Type
}

type Dir int

const (
	DirIn Dir = iota
	DirOut
	DirInOut
)

type Type interface {
	Name() string
	FieldName() string
	Dir() Dir
	Optional() bool
	Default() uintptr
	Varlen() bool
	Size() uintptr
	Align() uintptr
	BitfieldOffset() uintptr
	BitfieldLength() uintptr
	BitfieldLast() bool
}

func IsPad(t Type) bool {
	if ct, ok := t.(*ConstType); ok && ct.IsPad {
		return true
	}
	return false
}

type TypeCommon struct {
	TypeName   string
	FldName    string // for struct fields and named args
	ArgDir     Dir
	IsOptional bool
}

func (t *TypeCommon) Name() string {
	return t.TypeName
}

func (t *TypeCommon) FieldName() string {
	return t.FldName
}

func (t *TypeCommon) Optional() bool {
	return t.IsOptional
}

func (t *TypeCommon) Default() uintptr {
	return 0
}

func (t *TypeCommon) Varlen() bool {
	return false
}

func (t *TypeCommon) BitfieldOffset() uintptr {
	return 0
}

func (t *TypeCommon) BitfieldLength() uintptr {
	return 0
}

func (t *TypeCommon) BitfieldLast() bool {
	return false
}

func (t TypeCommon) Dir() Dir {
	return t.ArgDir
}

const (
	InvalidFD = ^uintptr(0)
)

type ResourceDesc struct {
	Name   string
	Type   Type
	Kind   []string
	Values []uintptr
}

type ResourceType struct {
	TypeCommon
	Desc *ResourceDesc
}

func (t *ResourceType) Default() uintptr {
	return t.Desc.Values[0]
}

func (t *ResourceType) SpecialValues() []uintptr {
	return t.Desc.Values
}

func (t *ResourceType) Size() uintptr {
	return t.Desc.Type.Size()
}

func (t *ResourceType) Align() uintptr {
	return t.Desc.Type.Align()
}

type IntTypeCommon struct {
	TypeCommon
	TypeSize    uintptr
	BigEndian   bool
	BitfieldOff uintptr
	BitfieldLen uintptr
	BitfieldLst bool
}

func (t *IntTypeCommon) Size() uintptr {
	return t.TypeSize
}

func (t *IntTypeCommon) Align() uintptr {
	return t.Size()
}

func (t *IntTypeCommon) BitfieldOffset() uintptr {
	return t.BitfieldOff
}

func (t *IntTypeCommon) BitfieldLength() uintptr {
	return t.BitfieldLen
}

func (t *IntTypeCommon) BitfieldLast() bool {
	return t.BitfieldLst
}

type ConstType struct {
	IntTypeCommon
	Val   uintptr
	IsPad bool
}

type IntKind int

const (
	IntPlain IntKind = iota
	IntSignalno
	IntFileoff // offset within a file
	IntRange
)

type IntType struct {
	IntTypeCommon
	Kind       IntKind
	RangeBegin int64
	RangeEnd   int64
}

type FlagsType struct {
	IntTypeCommon
	Vals []uintptr
}

type LenType struct {
	IntTypeCommon
	ByteSize uintptr // want size in multiple of bytes instead of array size
	Buf      string
}

type ProcType struct {
	IntTypeCommon
	ValuesStart   int64
	ValuesPerProc uint64
}

type CsumKind int

const (
	CsumInet CsumKind = iota
	CsumPseudo
)

type CsumType struct {
	IntTypeCommon
	Kind     CsumKind
	Buf      string
	Protocol uint64 // for CsumPseudo
}

type VmaType struct {
	TypeCommon
	RangeBegin int64 // in pages
	RangeEnd   int64
}

func (t *VmaType) Size() uintptr {
	return ptrSize
}

func (t *VmaType) Align() uintptr {
	return t.Size()
}

type BufferKind int

const (
	BufferBlobRand BufferKind = iota
	BufferBlobRange
	BufferString
	BufferFilename
	BufferText
)

type TextKind int

const (
	Text_x86_real TextKind = iota
	Text_x86_16
	Text_x86_32
	Text_x86_64
	Text_arm64
)

type BufferType struct {
	TypeCommon
	Kind       BufferKind
	RangeBegin uintptr  // for BufferBlobRange kind
	RangeEnd   uintptr  // for BufferBlobRange kind
	Text       TextKind // for BufferText
	SubKind    string
	Values     []string // possible values for BufferString kind
	Length     uintptr  // max string length for BufferString kind
}

func (t *BufferType) Varlen() bool {
	switch t.Kind {
	case BufferBlobRand:
		return true
	case BufferBlobRange:
		return t.RangeBegin != t.RangeEnd
	case BufferString:
		return t.Length == 0
	case BufferFilename:
		return true
	case BufferText:
		return true
	default:
		panic("bad buffer kind")
	}
}

func (t *BufferType) Size() uintptr {
	if t.Varlen() {
		panic(fmt.Sprintf("buffer size is not statically known: %v", t.Name()))
	}
	switch t.Kind {
	case BufferString:
		return t.Length
	case BufferBlobRange:
		return t.RangeBegin
	default:
		panic("bad buffer kind")
	}
}

func (t *BufferType) Align() uintptr {
	return 1
}

type ArrayKind int

const (
	ArrayRandLen ArrayKind = iota
	ArrayRangeLen
)

type ArrayType struct {
	TypeCommon
	Type       Type
	Kind       ArrayKind
	RangeBegin uintptr
	RangeEnd   uintptr
}

func (t *ArrayType) Varlen() bool {
	switch t.Kind {
	case ArrayRandLen:
		return true
	case ArrayRangeLen:
		return t.RangeBegin != t.RangeEnd
	default:
		panic("bad array kind")
	}
}

func (t *ArrayType) Size() uintptr {
	if t.Varlen() {
		panic(fmt.Sprintf("array size is not statically known: %v", t.Name()))
	}
	switch t.Kind {
	case ArrayRangeLen:
		return t.RangeBegin * t.Type.Size()
	default:
		panic("bad array type")
	}
}

func (t *ArrayType) Align() uintptr {
	return t.Type.Align()
}

type PtrType struct {
	TypeCommon
	Type Type
}

func (t *PtrType) Size() uintptr {
	return ptrSize
}

func (t *PtrType) Align() uintptr {
	return t.Size()
}

type StructType struct {
	TypeCommon
	Fields         []Type
	padded         bool
	packed         bool
	align          uintptr
	varlen         bool
	varlenAssigned bool
}

func (t *StructType) Varlen() bool {
	if t.varlenAssigned {
		return t.varlen
	}
	for _, f := range t.Fields {
		if f.Varlen() {
			t.varlen = true
			t.varlenAssigned = true
			return t.varlen
		}
	}
	t.varlen = false
	t.varlenAssigned = true
	return t.varlen
}

func (t *StructType) Size() uintptr {
	if t.Varlen() {
		panic(fmt.Sprintf("struct size is not statically known: %v", t.Name()))
	}
	if !t.padded {
		panic("struct is not padded yet")
	}
	var size uintptr
	for _, f := range t.Fields {
		if f.BitfieldLength() == 0 || f.BitfieldLast() {
			size += f.Size()
		}
	}
	return size
}

func (t *StructType) Align() uintptr {
	if t.align != 0 {
		return t.align // overrided by user attribute
	}
	if t.packed {
		return 1
	}
	var align uintptr
	for _, f := range t.Fields {
		if a1 := f.Align(); align < a1 {
			align = a1
		}
	}
	return align
}

type UnionType struct {
	TypeCommon
	Options []Type
	varlen  bool // provided by user
}

func (t *UnionType) Varlen() bool {
	return t.varlen
}

func (t *UnionType) Size() uintptr {
	if t.Varlen() {
		panic(fmt.Sprintf("union size is not statically known: %v", t.Name()))
	}
	size := t.Options[0].Size()
	for _, opt := range t.Options {
		if size < opt.Size() {
			size = opt.Size()
		}
	}
	return size
}

func (t *UnionType) Align() uintptr {
	var align uintptr
	for _, opt := range t.Options {
		if a1 := opt.Align(); align < a1 {
			align = a1
		}
	}
	return align
}

var ctors = make(map[string][]*Call)

// ResourceConstructors returns a list of calls that can create a resource of the given kind.
func ResourceConstructors(name string) []*Call {
	return ctors[name]
}

func initResources() {
	for name, res := range Resources {
		ctors[name] = resourceCtors(res.Kind, false)
	}
}

func resourceCtors(kind []string, precise bool) []*Call {
	// Find calls that produce the necessary resources.
	var metas []*Call
	for _, meta := range Calls {
		// Recurse into arguments to see if there is an out/inout arg of necessary type.
		ok := false
		ForeachType(meta, func(typ Type) {
			if ok {
				return
			}
			switch typ1 := typ.(type) {
			case *ResourceType:
				if typ1.Dir() != DirIn && isCompatibleResource(kind, typ1.Desc.Kind, precise) {
					ok = true
				}
			}
		})
		if ok {
			metas = append(metas, meta)
		}
	}
	return metas
}

// IsCompatibleResource returns true if resource of kind src can be passed as an argument of kind dst.
func IsCompatibleResource(dst, src string) bool {
	dstRes := Resources[dst]
	if dstRes == nil {
		panic(fmt.Sprintf("unknown resource '%v'", dst))
	}
	srcRes := Resources[src]
	if srcRes == nil {
		panic(fmt.Sprintf("unknown resource '%v'", src))
	}
	return isCompatibleResource(dstRes.Kind, srcRes.Kind, false)
}

// isCompatibleResource returns true if resource of kind src can be passed as an argument of kind dst.
// If precise is true, then it does not allow passing a less specialized resource (e.g. fd)
// as a more specialized resource (e.g. socket). Otherwise it does.
func isCompatibleResource(dst, src []string, precise bool) bool {
	if len(dst) > len(src) {
		// dst is more specialized, e.g dst=socket, src=fd.
		if precise {
			return false
		}
		dst = dst[:len(src)]
	}
	if len(src) > len(dst) {
		// src is more specialized, e.g dst=fd, src=socket.
		src = src[:len(dst)]
	}
	for i, k := range dst {
		if k != src[i] {
			return false
		}
	}
	return true
}

func (c *Call) InputResources() []*ResourceType {
	var resources []*ResourceType
	ForeachType(c, func(typ Type) {
		switch typ1 := typ.(type) {
		case *ResourceType:
			if typ1.Dir() != DirOut && !typ1.IsOptional {
				resources = append(resources, typ1)
			}
		}
	})
	return resources
}

func TransitivelyEnabledCalls(enabled map[*Call]bool) map[*Call]bool {
	supported := make(map[*Call]bool)
	for c := range enabled {
		supported[c] = true
	}
	for {
		n := len(supported)
		haveGettime := supported[CallMap["clock_gettime"]]
		for c := range supported {
			canCreate := true
			for _, res := range c.InputResources() {
				noctors := true
				for _, ctor := range resourceCtors(res.Desc.Kind, true) {
					if supported[ctor] {
						noctors = false
						break
					}
				}
				if noctors {
					canCreate = false
					break
				}
			}
			// We need to support structs as resources,
			// but for now we just special-case timespec/timeval.
			if canCreate && !haveGettime {
				ForeachType(c, func(typ Type) {
					if a, ok := typ.(*StructType); ok && a.Dir() != DirOut && (a.Name() == "timespec" || a.Name() == "timeval") {
						canCreate = false
					}
				})
			}
			if !canCreate {
				delete(supported, c)
			}
		}
		if n == len(supported) {
			break
		}
	}
	return supported
}

func ForeachType(meta *Call, f func(Type)) {
	seen := make(map[Type]bool)
	var rec func(t Type)
	rec = func(t Type) {
		f(t)
		switch a := t.(type) {
		case *PtrType:
			rec(a.Type)
		case *ArrayType:
			rec(a.Type)
		case *StructType:
			if seen[a] {
				return // prune recursion via pointers to structs/unions
			}
			seen[a] = true
			for _, f := range a.Fields {
				rec(f)
			}
		case *UnionType:
			if seen[a] {
				return // prune recursion via pointers to structs/unions
			}
			seen[a] = true
			for _, opt := range a.Options {
				rec(opt)
			}
		case *ResourceType, *BufferType, *VmaType, *LenType,
			*FlagsType, *ConstType, *IntType, *ProcType, *CsumType:
		default:
			panic("unknown type")
		}
	}
	for _, t := range meta.Args {
		rec(t)
	}
	if meta.Ret != nil {
		rec(meta.Ret)
	}
}

var (
	Calls   []*Call
	CallMap = make(map[string]*Call)
)

func init() {
	initCalls()
	initStructFields()
	initResources()
	initAlign()

	for i, c := range Calls {
		c.ID = i
		if CallMap[c.Name] != nil {
			println(c.Name)
			panic("duplicate syscall")
		}
		CallMap[c.Name] = c
	}
}
