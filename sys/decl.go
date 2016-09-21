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

type Type interface {
	Name() string
	Optional() bool
	Default() uintptr
	Size() uintptr
	Align() uintptr
}

func IsPad(t Type) bool {
	if ct, ok := t.(ConstType); ok && ct.IsPad {
		return true
	}
	return false
}

type TypeCommon struct {
	TypeName   string
	IsOptional bool
}

func (t TypeCommon) Name() string {
	return t.TypeName
}

func (t TypeCommon) Optional() bool {
	return t.IsOptional
}

func (t TypeCommon) Default() uintptr {
	return 0
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

func (t ResourceType) Default() uintptr {
	return t.Desc.Values[0]
}

func (t ResourceType) SpecialValues() []uintptr {
	return t.Desc.Values
}

func (t ResourceType) Size() uintptr {
	return t.Desc.Type.Size()
}

func (t ResourceType) Align() uintptr {
	return t.Desc.Type.Align()
}

type FileoffType struct {
	TypeCommon
	TypeSize uintptr
	File     string
}

func (t FileoffType) Size() uintptr {
	return t.TypeSize
}

func (t FileoffType) Align() uintptr {
	return t.Size()
}

type BufferKind int

const (
	BufferBlobRand BufferKind = iota
	BufferBlobRange
	BufferString
	BufferSockaddr
	BufferFilesystem
	BufferAlgType
	BufferAlgName
)

type BufferType struct {
	TypeCommon
	Kind       BufferKind
	RangeBegin uintptr // for BufferBlobRange kind
	RangeEnd   uintptr // for BufferBlobRange kind
}

func (t BufferType) Size() uintptr {
	switch t.Kind {
	case BufferAlgType:
		return 14
	case BufferAlgName:
		return 64
	case BufferBlobRange:
		if t.RangeBegin == t.RangeEnd {
			return t.RangeBegin
		}
		fallthrough
	default:
		panic(fmt.Sprintf("buffer size is not statically known: %v", t.Name()))
	}
}

func (t BufferType) Align() uintptr {
	return 1
}

type VmaType struct {
	TypeCommon
}

func (t VmaType) Size() uintptr {
	return ptrSize
}

func (t VmaType) Align() uintptr {
	return t.Size()
}

type LenType struct {
	TypeCommon
	TypeSize uintptr
	ByteSize bool // want size in bytes instead of array size
	Buf      string
}

func (t LenType) Size() uintptr {
	return t.TypeSize
}

func (t LenType) Align() uintptr {
	return t.Size()
}

type FlagsType struct {
	TypeCommon
	TypeSize uintptr
	Vals     []uintptr
}

func (t FlagsType) Size() uintptr {
	return t.TypeSize
}

func (t FlagsType) Align() uintptr {
	return t.Size()
}

type ConstType struct {
	TypeCommon
	TypeSize uintptr
	Val      uintptr
	IsPad    bool
}

func (t ConstType) Size() uintptr {
	return t.TypeSize
}

func (t ConstType) Align() uintptr {
	return t.Size()
}

type StrConstType struct {
	TypeCommon
	TypeSize uintptr
	Val      string
}

func (t StrConstType) Size() uintptr {
	return ptrSize
}

func (t StrConstType) Align() uintptr {
	return t.Size()
}

type IntKind int

const (
	IntPlain IntKind = iota
	IntSignalno
	IntInaddr
	IntInport
	IntRange
)

type IntType struct {
	TypeCommon
	TypeSize   uintptr
	Kind       IntKind
	RangeBegin int64
	RangeEnd   int64
}

func (t IntType) Size() uintptr {
	return t.TypeSize
}

func (t IntType) Align() uintptr {
	return t.Size()
}

type FilenameType struct {
	TypeCommon
}

func (t FilenameType) Size() uintptr {
	panic("filename size is not statically known")
}

func (t FilenameType) Align() uintptr {
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

func (t ArrayType) Size() uintptr {
	if t.RangeBegin == t.RangeEnd {
		return t.RangeBegin * t.Type.Size()
	}
	return 0 // for trailing embed arrays
}

func (t ArrayType) Align() uintptr {
	return t.Type.Align()
}

type PtrType struct {
	TypeCommon
	Type Type
	Dir  Dir
}

func (t PtrType) Size() uintptr {
	return ptrSize
}

func (t PtrType) Align() uintptr {
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

type Dir int

const (
	DirIn Dir = iota
	DirOut
	DirInOut
)

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
	// Recurse into arguments to see if there is an out/inout arg of necessary type.
	seen := make(map[Type]bool)
	var checkArg func(typ Type, dir Dir) bool
	checkArg = func(typ Type, dir Dir) bool {
		if resarg, ok := typ.(ResourceType); ok && dir != DirIn && isCompatibleResource(kind, resarg.Desc.Kind, precise) {
			return true
		}
		switch typ1 := typ.(type) {
		case ArrayType:
			if checkArg(typ1.Type, dir) {
				return true
			}
		case *StructType:
			if seen[typ1] {
				return false // prune recursion via pointers to structs/unions
			}
			seen[typ1] = true
			for _, fld := range typ1.Fields {
				if checkArg(fld, dir) {
					return true
				}
			}
		case *UnionType:
			if seen[typ1] {
				return false // prune recursion via pointers to structs/unions
			}
			seen[typ1] = true
			for _, opt := range typ1.Options {
				if checkArg(opt, dir) {
					return true
				}
			}
		case PtrType:
			if checkArg(typ1.Type, typ1.Dir) {
				return true
			}
		}
		return false
	}
	for _, meta := range Calls {
		ok := false
		for _, arg := range meta.Args {
			if checkArg(arg, DirIn) {
				ok = true
				break
			}
		}
		if !ok && meta.Ret != nil && checkArg(meta.Ret, DirOut) {
			ok = true
		}
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

func (c *Call) InputResources() []ResourceType {
	var resources []ResourceType
	seen := make(map[Type]bool)
	var checkArg func(typ Type, dir Dir)
	checkArg = func(typ Type, dir Dir) {
		switch typ1 := typ.(type) {
		case ResourceType:
			if dir != DirOut && !typ1.IsOptional {
				resources = append(resources, typ1)
			}
		case ArrayType:
			checkArg(typ1.Type, dir)
		case PtrType:
			checkArg(typ1.Type, typ1.Dir)
		case *StructType:
			if seen[typ1] {
				return // prune recursion via pointers to structs/unions
			}
			seen[typ1] = true
			for _, fld := range typ1.Fields {
				checkArg(fld, dir)
			}
		case *UnionType:
			if seen[typ1] {
				return // prune recursion via pointers to structs/unions
			}
			seen[typ1] = true
			for _, opt := range typ1.Options {
				checkArg(opt, dir)
			}
		}
	}
	for _, arg := range c.Args {
		checkArg(arg, DirIn)
	}
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
