// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:generate go install github.com/google/syzkaller/sysgen
//go:generate sysgen sys.txt

package sys

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
		return []uintptr{InvalidFD, BogusFD}
	case ResIOCtx:
		return []uintptr{0}
	case ResIPC:
		return []uintptr{0, ^uintptr(0)}
	case ResKey:
		// KEY_SPEC_THREAD_KEYRING values
		return []uintptr{0, ^uintptr(0), ^uintptr(0) - 1, ^uintptr(0) - 2, ^uintptr(0) - 3, ^uintptr(0) - 4, ^uintptr(0) - 5, ^uintptr(0) - 6, ^uintptr(0) - 7}
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

func (t ResourceType) SubKinds() []ResourceSubkind {
	switch t.Kind {
	case ResFD:
		return []ResourceSubkind{FdFile, FdSock, FdPipe, FdSignal, FdEvent, FdTimer, FdEpoll, FdDir, FdMq, FdInotify, FdFanotify, FdTty, FdDRI}
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

type BufferKind int

const (
	BufferBlob BufferKind = iota
	BufferString
	BufferSockaddr
	BufferFilesystem
)

type BufferType struct {
	TypeCommon
	Kind BufferKind
}

type VmaType struct {
	TypeCommon
}

type LenType struct {
	TypeCommon
	TypeSize uintptr
	Buf      string
}

type FlagsType struct {
	TypeCommon
	TypeSize uintptr
	Vals     []uintptr
}

type ConstType struct {
	TypeCommon
	TypeSize uintptr
	Val      uintptr
}

type StrConstType struct {
	TypeCommon
	TypeSize uintptr
	Val      string
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

type FilenameType struct {
	TypeCommon
}

type ArrayType struct {
	TypeCommon
	Type Type
}

type PtrType struct {
	TypeCommon
	Type Type
	Dir  Dir
}

type StructType struct {
	TypeCommon
	Fields []Type
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
