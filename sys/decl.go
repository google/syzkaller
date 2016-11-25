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
	CallID   int
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
	Dir() Dir
	Optional() bool
	Default() uintptr
	Size() uintptr
	Align() uintptr
}

func IsPad(t Type) bool {
	if ct, ok := t.(*ConstType); ok && ct.IsPad {
		return true
	}
	return false
}

type TypeCommon struct {
	TypeName   string
	ArgDir     Dir
	IsOptional bool
}

func (t *TypeCommon) Name() string {
	return t.TypeName
}

func (t *TypeCommon) Optional() bool {
	return t.IsOptional
}

func (t *TypeCommon) Default() uintptr {
	return 0
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

type BufferKind int

const (
	BufferBlobRand BufferKind = iota
	BufferBlobRange
	BufferString
	BufferFilename
	BufferSockaddr
)

type BufferType struct {
	TypeCommon
	Kind       BufferKind
	RangeBegin uintptr // for BufferBlobRange kind
	RangeEnd   uintptr // for BufferBlobRange kind
	SubKind    string
	Values     []string // possible values for BufferString kind
}

func (t *BufferType) Size() uintptr {
	switch t.Kind {
	case BufferString:
		size := 0
		for _, s := range t.Values {
			if size != 0 && size != len(s) {
				size = 0
				break
			}
			size = len(s)
		}
		if size != 0 {
			return uintptr(size)
		}
	case BufferBlobRange:
		if t.RangeBegin == t.RangeEnd {
			return t.RangeBegin
		}
	}
	panic(fmt.Sprintf("buffer size is not statically known: %v", t.Name()))
}

func (t *BufferType) Align() uintptr {
	return 1
}

type VmaType struct {
	TypeCommon
}

func (t *VmaType) Size() uintptr {
	return ptrSize
}

func (t *VmaType) Align() uintptr {
	return t.Size()
}

type LenType struct {
	TypeCommon
	TypeSize  uintptr
	BigEndian bool
	ByteSize  bool // want size in bytes instead of array size
	Buf       string
}

func (t *LenType) Size() uintptr {
	return t.TypeSize
}

func (t *LenType) Align() uintptr {
	return t.Size()
}

type FlagsType struct {
	TypeCommon
	TypeSize  uintptr
	BigEndian bool
	Vals      []uintptr
}

func (t *FlagsType) Size() uintptr {
	return t.TypeSize
}

func (t *FlagsType) Align() uintptr {
	return t.Size()
}

type ConstType struct {
	TypeCommon
	TypeSize  uintptr
	BigEndian bool
	Val       uintptr
	IsPad     bool
}

func (t *ConstType) Size() uintptr {
	return t.TypeSize
}

func (t *ConstType) Align() uintptr {
	return t.Size()
}

type IntKind int

const (
	IntPlain IntKind = iota
	IntSignalno
	IntInaddr
	IntFileoff // offset within a file
	IntRange
)

type IntType struct {
	TypeCommon
	TypeSize   uintptr
	BigEndian  bool
	Kind       IntKind
	RangeBegin int64
	RangeEnd   int64
}

func (t *IntType) Size() uintptr {
	return t.TypeSize
}

func (t *IntType) Align() uintptr {
	return t.Size()
}

type ProcType struct {
	TypeCommon
	TypeSize      uintptr
	BigEndian     bool
	ValuesStart   int64
	ValuesPerProc uint64
}

func (t *ProcType) Size() uintptr {
	return t.TypeSize
}

func (t *ProcType) Align() uintptr {
	return t.Size()
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

func (t *ArrayType) Size() uintptr {
	if t.RangeBegin == t.RangeEnd {
		return t.RangeBegin * t.Type.Size()
	}
	return 0 // for trailing embed arrays
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
	Fields []Type
	padded bool
	packed bool
	align  uintptr
}

func (t *StructType) Size() uintptr {
	if !t.padded {
		panic("struct is not padded yet")
	}
	var size uintptr
	for _, f := range t.Fields {
		size += f.Size()
	}
	return size
}

func (t *StructType) Align() uintptr {
	if t.align != 0 {
		return t.align // overrided by user attribute
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
	varlen  bool
}

func (t *UnionType) Size() uintptr {
	if t.varlen {
		panic("union size is not statically known")
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
		for c := range enabled {
			if !supported[c] {
				continue
			}
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
			*FlagsType, *ConstType, *IntType, *ProcType:
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
	Calls     []*Call
	CallCount int
	CallMap   = make(map[string]*Call)
	CallID    = make(map[string]int)
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
		id, ok := CallID[c.CallName]
		if !ok {
			id = len(CallID)
			CallID[c.CallName] = id
		}
		c.CallID = id
		CallMap[c.Name] = c
	}
	CallCount = len(CallID)
}
