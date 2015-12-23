// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:generate go install github.com/google/syzkaller/sysgen
//go:generate sysgen sys.txt

package sys

const ptrSize = 8

type Call struct {
	ID       int
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

type (
	ResourceKind    int
	ResourceSubkind int
)

const (
	ResFD ResourceKind = iota
	ResIOCtx
	ResIPC
	ResKey
	ResInotifyDesc
	ResPid
	ResUid
	ResGid
	ResTimerid
	ResIocbPtr
)

const (
	ResAny ResourceSubkind = iota
	FdFile
	FdSock
	FdPipe
	FdSignal
	FdEvent
	FdTimer
	FdEpoll
	FdDir
	FdMq
	FdInotify
	FdFanotify
	FdTty
	FdDRI
	FdFuse
	FdKdbus
	FdBpfMap
	FdBpfProg
	FdPerf
	FdUserFault
	FdAlg
	FdAlgConn
	FdNfcRaw
	FdNfcLlcp
	FdBtHci
	FdBtSco
	FdBtL2cap
	FdBtRfcomm
	FdBtHidp
	FdBtCmtp
	FdBtBnep

	IPCMsq
	IPCSem
	IPCShm
)

const (
	InvalidFD = ^uintptr(0)
	BogusFD   = uintptr(100000 - 1)
)

type ResourceType struct {
	TypeCommon
	Kind    ResourceKind
	Subkind ResourceSubkind
}

func (t ResourceType) Default() uintptr {
	switch t.Kind {
	case ResFD:
		return InvalidFD
	case ResIOCtx:
		return 0
	case ResIPC:
		return 0
	case ResKey:
		return 0
	case ResInotifyDesc:
		return 0
	case ResPid:
		return 0
	case ResUid:
		return 0
	case ResGid:
		return 0
	case ResTimerid:
		return 0
	default:
		panic("unknown resource type")
	}
}

func (t ResourceType) SpecialValues() []uintptr {
	switch t.Kind {
	case ResFD:
		return []uintptr{InvalidFD, BogusFD, ^uintptr(0) - 99 /*AT_FDCWD*/}
	case ResIOCtx:
		return []uintptr{0}
	case ResIPC:
		return []uintptr{0, ^uintptr(0)}
	case ResKey:
		// KEY_SPEC_THREAD_KEYRING values
		return []uintptr{0, ^uintptr(0), ^uintptr(0) - 1, ^uintptr(0) - 2, ^uintptr(0) - 3,
			^uintptr(0) - 4, ^uintptr(0) - 5, ^uintptr(0) - 6, ^uintptr(0) - 7}
	case ResInotifyDesc:
		return []uintptr{0}
	case ResPid:
		return []uintptr{0, ^uintptr(0)}
	case ResUid:
		return []uintptr{0, ^uintptr(0)}
	case ResGid:
		return []uintptr{0, ^uintptr(0)}
	case ResTimerid:
		return []uintptr{0}
	default:
		panic("unknown resource kind")
	}
}

func (t ResourceType) Size() uintptr {
	switch t.Kind {
	case ResFD:
		return 4
	case ResIOCtx:
		return 8
	case ResIPC:
		return 4
	case ResKey:
		return 4
	case ResInotifyDesc:
		return 4
	case ResPid:
		return 4
	case ResUid:
		return 4
	case ResGid:
		return 4
	case ResTimerid:
		return 4
	default:
		panic("unknown resource kind")
	}
}

func (t ResourceType) Align() uintptr {
	return t.Size()
}

func (t ResourceType) SubKinds() []ResourceSubkind {
	switch t.Kind {
	case ResFD:
		return []ResourceSubkind{FdFile, FdSock, FdPipe, FdSignal, FdEvent,
			FdTimer, FdEpoll, FdDir, FdMq, FdInotify, FdFanotify, FdTty,
			FdDRI, FdFuse, FdKdbus, FdBpfMap, FdBpfProg, FdPerf, FdUserFault,
			FdAlg, FdAlgConn, FdNfcRaw, FdNfcLlcp, FdBtHci, FdBtSco, FdBtL2cap,
			FdBtRfcomm, FdBtHidp, FdBtCmtp, FdBtBnep}
	case ResIPC:
		return []ResourceSubkind{IPCMsq, IPCSem, IPCShm}
	case ResIOCtx, ResKey, ResInotifyDesc, ResPid, ResUid, ResGid, ResTimerid:
		return []ResourceSubkind{ResAny}
	default:
		panic("unknown resource kind")
	}
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
	BufferBlob BufferKind = iota
	BufferString
	BufferSockaddr
	BufferFilesystem
	BufferAlgType
	BufferAlgName
)

type BufferType struct {
	TypeCommon
	Kind BufferKind
}

func (t BufferType) Size() uintptr {
	switch t.Kind {
	case BufferAlgType:
		return 14
	case BufferAlgName:
		return 64
	default:
		panic("buffer size is not statically known")
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
)

type IntType struct {
	TypeCommon
	TypeSize uintptr
	Kind     IntKind
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

type ArrayType struct {
	TypeCommon
	Type Type
	Len  uintptr // 0 if variable-length, unused for now
}

func (t ArrayType) Size() uintptr {
	if t.Len == 0 {
		return 0 // for trailing embed arrays
	}
	return t.Len * t.Type.Size()
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
}

func (t StructType) Size() uintptr {
	if !t.padded {
		panic("struct is not padded yet")
	}
	var size uintptr
	for _, f := range t.Fields {
		size += f.Size()
	}
	return size
}

func (t StructType) Align() uintptr {
	var align uintptr
	for _, f := range t.Fields {
		if a1 := f.Align(); align < a1 {
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

var (
	CallCount int
	CallMap   = make(map[string]*Call)
	CallID    = make(map[string]int)
)

func init() {
	initCalls()
	var rec func(t Type) Type
	rec = func(t Type) Type {
		switch t1 := t.(type) {
		case PtrType:
			rec(t1.Type)
		case ArrayType:
			rec(t1.Type)
		case StructType:
			for i, f := range t1.Fields {
				t1.Fields[i] = rec(f)
			}
			t = addAlignment(t1)
		}
		return t
	}
	for _, c := range Calls {
		for i, t := range c.Args {
			c.Args[i] = rec(t)
		}
		if c.Ret != nil {
			c.Ret = rec(c.Ret)
		}
	}

	for _, c := range Calls {
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

func addAlignment(t StructType) Type {
	var fields []Type
	var off, align uintptr
	varLen := false
	for i, f := range t.Fields {
		a := f.Align()
		if align < a {
			align = a
		}
		if off%a != 0 {
			pad := a - off%a
			off += pad
			fields = append(fields, makePad(pad))
		}
		off += f.Size()
		fields = append(fields, f)
		if at, ok := f.(ArrayType); ok && at.Len == 0 {
			varLen = true
		}
		if varLen && i != len(t.Fields)-1 {
			panic("embed array in middle of a struct")
		}
	}
	if align != 0 && off%align != 0 && !varLen {
		pad := align - off%align
		off += pad
		fields = append(fields, makePad(pad))
	}
	t.Fields = fields
	t.padded = true
	return t
}

func makePad(sz uintptr) Type {
	return ConstType{
		TypeCommon: TypeCommon{TypeName: "pad", IsOptional: false},
		TypeSize:   sz,
		Val:        0,
	}
}
