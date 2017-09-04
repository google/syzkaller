// Copyright 2015/2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sys

import (
	"fmt"
)

type Call struct {
	ID       int
	NR       uint64 // kernel syscall number
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
	Default() uint64
	Varlen() bool
	Size() uint64
	BitfieldOffset() uint64
	BitfieldLength() uint64
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
	TypeSize   uint64 // static size of the type, or 0 for variable size types
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

func (t *TypeCommon) Default() uint64 {
	return 0
}

func (t *TypeCommon) Size() uint64 {
	if t.Varlen() {
		panic(fmt.Sprintf("static type size is not known: %#v", t))
	}
	return t.TypeSize
}

func (t *TypeCommon) Varlen() bool {
	return t.TypeSize == 0
}

func (t *TypeCommon) BitfieldOffset() uint64 {
	return 0
}

func (t *TypeCommon) BitfieldLength() uint64 {
	return 0
}

func (t *TypeCommon) BitfieldLast() bool {
	return false
}

func (t TypeCommon) Dir() Dir {
	return t.ArgDir
}

const (
	InvalidFD = ^uint64(0)
)

type ResourceDesc struct {
	Name   string
	Type   Type
	Kind   []string
	Values []uint64
}

type ResourceType struct {
	TypeCommon
	Desc *ResourceDesc
}

func (t *ResourceType) Default() uint64 {
	return t.Desc.Values[0]
}

func (t *ResourceType) SpecialValues() []uint64 {
	return t.Desc.Values
}

type IntTypeCommon struct {
	TypeCommon
	BitfieldOff uint64
	BitfieldLen uint64
	BigEndian   bool
	BitfieldLst bool
}

func (t *IntTypeCommon) Size() uint64 {
	// TODO(dvyukov): check that this is not a middle bitfield
	// if t.BitfieldLen != 0 && !t.BitfieldLst {
	//	panic(fmt.Sprintf("bitfields don't have size: %#v", t))
	// }
	return t.TypeCommon.Size()
}

func (t *IntTypeCommon) BitfieldOffset() uint64 {
	return t.BitfieldOff
}

func (t *IntTypeCommon) BitfieldLength() uint64 {
	return t.BitfieldLen
}

func (t *IntTypeCommon) BitfieldLast() bool {
	return t.BitfieldLst
}

type ConstType struct {
	IntTypeCommon
	Val   uint64
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
	RangeBegin uint64
	RangeEnd   uint64
}

type FlagsType struct {
	IntTypeCommon
	Vals []uint64
}

type LenType struct {
	IntTypeCommon
	ByteSize uint64 // want size in multiple of bytes instead of array size
	Buf      string
}

type ProcType struct {
	IntTypeCommon
	ValuesStart   uint64
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
	RangeBegin uint64 // in pages
	RangeEnd   uint64
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
	RangeBegin uint64   // for BufferBlobRange kind
	RangeEnd   uint64   // for BufferBlobRange kind
	Text       TextKind // for BufferText
	SubKind    string
	Values     []string // possible values for BufferString kind
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
	RangeBegin uint64
	RangeEnd   uint64
}

type PtrType struct {
	TypeCommon
	Type Type
}

type StructType struct {
	Key     StructKey
	FldName string
	*StructDesc
}

func (t *StructType) FieldName() string {
	return t.FldName
}

type UnionType struct {
	Key     StructKey
	FldName string
	*StructDesc
}

func (t *UnionType) FieldName() string {
	return t.FldName
}

var (
	CallMap   = make(map[string]*Call)
	Resources map[string]*ResourceDesc
	ctors     = make(map[string][]*Call)
)

type StructDesc struct {
	TypeCommon
	Fields    []Type
	AlignAttr uint64
}

func (t *StructDesc) FieldName() string {
	panic("must not be called")
}

type StructKey struct {
	Name string
	Dir  Dir
}

type KeyedStruct struct {
	Key  StructKey
	Desc *StructDesc
}

func initStructFields() {
	keyedStructs := make(map[StructKey]*StructDesc)
	for _, desc := range structDescs {
		keyedStructs[desc.Key] = desc.Desc
	}

	for _, c := range Calls {
		ForeachType(c, func(t Type) {
			switch s := t.(type) {
			case *StructType:
				s.StructDesc = keyedStructs[s.Key]
				if s.StructDesc == nil {
					panic("no struct desc")
				}
			case *UnionType:
				s.StructDesc = keyedStructs[s.Key]
				if s.StructDesc == nil {
					panic("no union desc")
				}
			}
		})
	}
}

// ResourceConstructors returns a list of calls that can create a resource of the given kind.
func ResourceConstructors(name string) []*Call {
	return ctors[name]
}

func initResources() {
	Resources = make(map[string]*ResourceDesc)
	for _, res := range resourceArray {
		Resources[res.Name] = res
	}
	for _, c := range Calls {
		ForeachType(c, func(t Type) {
			if r, ok := t.(*ResourceType); ok {
				r.Desc = Resources[r.TypeName]
			}
		})
	}
	for _, res := range resourceArray {
		ctors[res.Name] = resourceCtors(res.Kind, false)
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
	inputResources := make(map[*Call][]*ResourceType)
	ctors := make(map[string][]*Call)
	for c := range supported {
		inputs := c.InputResources()
		inputResources[c] = inputs
		for _, res := range inputs {
			if _, ok := ctors[res.Desc.Name]; ok {
				continue
			}
			ctors[res.Desc.Name] = resourceCtors(res.Desc.Kind, true)
		}
	}
	for {
		n := len(supported)
		haveGettime := supported[CallMap["clock_gettime"]]
		for c := range supported {
			canCreate := true
			for _, res := range inputResources[c] {
				noctors := true
				for _, ctor := range ctors[res.Desc.Name] {
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
	seen := make(map[*StructDesc]bool)
	var rec func(t Type)
	rec = func(t Type) {
		f(t)
		switch a := t.(type) {
		case *PtrType:
			rec(a.Type)
		case *ArrayType:
			rec(a.Type)
		case *StructType:
			if seen[a.StructDesc] {
				return // prune recursion via pointers to structs/unions
			}
			seen[a.StructDesc] = true
			for _, f := range a.Fields {
				rec(f)
			}
		case *UnionType:
			if seen[a.StructDesc] {
				return // prune recursion via pointers to structs/unions
			}
			seen[a.StructDesc] = true
			for _, opt := range a.Fields {
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

func init() {
	initStructFields()
	initResources()
	structDescs = nil

	for i, c := range Calls {
		c.ID = i
		if CallMap[c.Name] != nil {
			println(c.Name)
			panic("duplicate syscall")
		}
		CallMap[c.Name] = c
	}
}
