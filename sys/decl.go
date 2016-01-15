// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sys

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
	ResDrmCtx
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
	FdUnix
	FdSctp
	FdKvm
	FdKvmVm
	FdKvmCpu
	FdSndSeq
	FdSndTimer
	FdSndControl
	FdInputEvent

	IPCMsq
	IPCSem
	IPCShm
)

func ResourceKinds() []ResourceKind {
	return []ResourceKind{
		ResFD,
		ResIOCtx,
		ResIPC,
		ResKey,
		ResInotifyDesc,
		ResPid,
		ResUid,
		ResGid,
		ResTimerid,
		ResIocbPtr,
	}
}

func ResourceSubkinds(kind ResourceKind) []ResourceSubkind {
	switch kind {
	case ResFD:
		return []ResourceSubkind{ResAny, FdFile, FdSock, FdPipe, FdSignal, FdEvent,
			FdTimer, FdEpoll, FdDir, FdMq, FdInotify, FdFanotify, FdTty,
			FdDRI, FdFuse, FdKdbus, FdBpfMap, FdBpfProg, FdPerf, FdUserFault,
			FdAlg, FdAlgConn, FdNfcRaw, FdNfcLlcp, FdBtHci, FdBtSco, FdBtL2cap,
			FdBtRfcomm, FdBtHidp, FdBtCmtp, FdBtBnep, FdUnix, FdSctp, FdKvm, FdKvmVm,
			FdKvmCpu, FdSndSeq, FdSndTimer, FdSndControl, FdInputEvent}
	case ResIPC:
		return []ResourceSubkind{IPCMsq, IPCSem, IPCShm}
	case ResIOCtx, ResKey, ResInotifyDesc, ResPid, ResUid, ResGid, ResTimerid, ResIocbPtr, ResDrmCtx:
		return []ResourceSubkind{ResAny}
	default:
		panic("unknown resource kind")
	}
}

func SocketSubkinds() []ResourceSubkind {
	return []ResourceSubkind{FdAlg, FdAlgConn, FdNfcRaw, FdNfcLlcp, FdBtHci, FdBtSco,
		FdBtL2cap, FdBtRfcomm, FdBtHidp, FdBtCmtp, FdBtBnep, FdUnix, FdSctp}
}

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
	case ResDrmCtx:
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
	case ResDrmCtx:
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
	case ResDrmCtx:
		return 4
	default:
		panic("unknown resource kind")
	}
}

func (t ResourceType) Align() uintptr {
	return t.Size()
}

func (t ResourceType) SubKinds() []ResourceSubkind {
	return ResourceSubkinds(t.Kind)
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
	packed bool
	align  uintptr
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

func (t UnionType) Size() uintptr {
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

func (t UnionType) Align() uintptr {
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

var ctors = make(map[ResourceKind]map[ResourceSubkind][]*Call)

// ResourceConstructors returns a list of calls that can create a resource of the given kind/subkind.
func ResourceConstructors(kind ResourceKind, sk ResourceSubkind) []*Call {
	return ctors[kind][sk]
}

func initResources() {
	for _, kind := range ResourceKinds() {
		ctors[kind] = make(map[ResourceSubkind][]*Call)
		for _, sk := range ResourceSubkinds(kind) {
			ctors[kind][sk] = ResourceCtors(kind, sk, false)
		}
	}
}

func ResourceCtors(kind ResourceKind, sk ResourceSubkind, precise bool) []*Call {
	// Find calls that produce the necessary resources.
	var metas []*Call
	// Recurse into arguments to see if there is an out/inout arg of necessary type.
	var checkArg func(typ Type, dir Dir) bool
	checkArg = func(typ Type, dir Dir) bool {
		if resarg, ok := typ.(ResourceType); ok && dir != DirIn && resarg.Kind == kind &&
			(sk == resarg.Subkind || sk == ResAny || (resarg.Subkind == ResAny && !precise)) {
			return true
		}
		switch typ1 := typ.(type) {
		case ArrayType:
			if checkArg(typ1.Type, dir) {
				return true
			}
		case StructType:
			for _, fld := range typ1.Fields {
				if checkArg(fld, dir) {
					return true
				}
			}
		case UnionType:
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

func (c *Call) InputResources() []ResourceType {
	var resources []ResourceType
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
		case StructType:
			for _, fld := range typ1.Fields {
				checkArg(fld, dir)
			}
		case UnionType:
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
				for _, ctor := range ResourceCtors(res.Kind, res.Subkind, true) {
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
	CallCount int
	CallMap   = make(map[string]*Call)
	CallID    = make(map[string]int)
)

func init() {
	initCalls()
	initResources()
	initAlign()

	for _, c := range Calls {
		c.NR = numbers[c.ID]
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
