package prog

import (
	"fmt"
	"math/rand"
	"unsafe"
	"github.com/google/syzkaller/pkg/log"
)

/*
#cgo CXXFLAGS: -I/usr/lib/ -Wno-narrowing
#cgo LDFLAGS: -l:libjsoncpp.a -L/usr/lib/ -lstdc++
#include <stdint.h>
#include <stdlib.h>
#include "genbpfimport.hpp"
*/
import "C"

type bpf_xattr struct {
	part1		[8]byte
	//insns		int64
	insns		*[]byte
	//license		int64
	license		*[]byte
	loglevel	int32
	logsize		int32
	//log			int64
	log			*[]byte
	part2		[40]byte
	//func_info			int64
	func_info			*[]byte
	func_info_cnt		int32
	line_info_rec_size	int32
	//line_info			int64
	line_info			*[]byte
	line_info_cnt		int32
	part3				[20]byte
}

func (target *Target) BPFGenerate(rs rand.Source, ncalls int, ct *ChoiceTable) *Prog {

	p := &Prog{
        Target: target,
    }
    r := newRand(target, rs)
    s := newState(target, ct, nil)
	calls := make([]*Call, 0)

	MAXSIZE := int(C.bpfAttrSize()) * 3
	cbpfProgAttr := C.malloc(C.sizeof_char * (C.ulong)(MAXSIZE))
	defer C.free(unsafe.Pointer(cbpfProgAttr))
	cbpfMapAttr := C.malloc(C.sizeof_char * (C.ulong)(MAXSIZE))
	defer C.free(unsafe.Pointer(cbpfMapAttr))
	mapCnt := C.GenBPFProg((*C.char)(cbpfProgAttr), (*C.char)(cbpfMapAttr), C.int(MAXSIZE))
	progArgLists := structC2GO((*bpf_xattr)(cbpfProgAttr))
	mapArgLists := cMapAttr2Go(C.GoBytes(cbpfMapAttr, (C.int)(MAXSIZE)), int(mapCnt))

	// Generate map creation calls
	log.Logf(0, "Generating map call")
	for i := 0; i < int(mapCnt); i++ {
		mapCall := 120
		meta := r.target.Syscalls[mapCall]
		calls1 := r.generateParticularBPFCall(s, meta, mapArgLists[i])
		calls = append(calls, calls1...)
	}

	// Generate prog load call
	log.Logf(0, "Generating load call")
    loadCall := 134
    meta := r.target.Syscalls[loadCall]
    calls2 := r.generateParticularBPFCall(s, meta, progArgLists)
    calls = append(calls, calls2...)

	for _, c := range calls {
        s.analyze(c)
        p.Calls = append(p.Calls, c)
    }
	for len(p.Calls) > ncalls {
        p.RemoveCall(ncalls - 1)
    }
    p.sanitizeFix()
    p.debugValidate()
    return p
}

func cPtr2Array(ptr *[]byte, size C.int) *[]byte {
    if ptr != nil {
        array := C.GoBytes(unsafe.Pointer(ptr), size)
		return &array
    } else {
        array := make([]byte, 0)
		return &array
    }
}

// func structC2GO(cbpfProgAttr *bpf_xattr) (*bpf_xattr, []*[]byte) {
func structC2GO(cbpfProgAttr *bpf_xattr) ([][][]byte) {

    gbpfProgAttr := (*bpf_xattr)((unsafe.Pointer(cbpfProgAttr)))

    gbpfProgAttr.insns = cPtr2Array(gbpfProgAttr.insns, C.insnSize)
    gbpfProgAttr.license = cPtr2Array(gbpfProgAttr.license, C.licenseSize)
    gbpfProgAttr.func_info = cPtr2Array(gbpfProgAttr.func_info, C.funcInfoSize)
    gbpfProgAttr.line_info = cPtr2Array(gbpfProgAttr.line_info, C.lineInfoSize)

	xattrLists := make([][]byte, 13)

	part1 := make([]byte, 8)
	copy(part1[:], gbpfProgAttr.part1[:])
	xattrLists[0] = part1

	xattrLists[1] = *gbpfProgAttr.insns
	xattrLists[2] = *gbpfProgAttr.license

	part2 := make([]byte, 40)
    copy(part2[:], gbpfProgAttr.part2[:])
    xattrLists[6] = part2

	xattrLists[7] = *gbpfProgAttr.func_info
	xattrLists[10] = *gbpfProgAttr.line_info

	part3 := make([]byte, 20)
    copy(part3[:], gbpfProgAttr.part3[:])
    xattrLists[12] = part3

	empty := [][]byte{make([]byte, 0)}
	lists := [][][]byte{empty, xattrLists, empty}

    // return gbpfProgAttr, lists
	return lists
}

func cMapAttr2Go(gbpfMapAttrs []byte, cnt int) (maps [][][][]byte) {
	for i := 0; i < cnt; i++ {
		s := i * int(C.bpfAttrSize())
		e := (i+1) * int(C.bpfAttrSize())
		structArray := [][]byte{gbpfMapAttrs[s:e]}
		empty := [][]byte{make([]byte, 0)}
		tmp := [][][]byte{empty, structArray, empty}
		maps = append(maps, tmp)
	}
	return maps
}

func (r *randGen) generateParticularBPFCall(s *state, meta *Syscall, argData [][][]byte) (calls []*Call) {
    if meta.Attrs.Disabled {
        panic(fmt.Sprintf("generating disabled call %v", meta.Name))
    }
    if meta.Attrs.NoGenerate {
        panic(fmt.Sprintf("generating no_generate call: %v", meta.Name))
    }
    c := MakeCall(meta, nil)
    c.Args, calls = r.generateBPFArgs(s, meta.Args, DirIn, argData)
    r.target.assignSizesCall(c)
    return append(calls, c)
}

func (r *randGen) generateBPFArgs(s *state, fields []Field, dir Dir, argData [][][]byte) ([]Arg, []*Call) {
    
	var calls []*Call
    args := make([]Arg, len(fields))

    for i, field := range fields {
		arg, calls1 := r.generateBPFArg(s, field.Type, field.Dir(dir), argData, i, -1)
		args[i] = arg
        calls = append(calls, calls1...)
    }
    return args, calls
}

func (r *randGen) generateBPFArg(s *state, typ Type, dir Dir, argData [][][]byte, i int, j int) (arg Arg, calls []*Call) {

	if typ1, ok := typ.(*PtrType); ok {
		log.Logf(0, "argData ptr: %v, %v", typ1, argData)
		arg, calls = typ1.generatePtrType(r, s, dir, argData, i, j)
	} else if typ1, ok := typ.(*BufferType); ok {
		log.Logf(0, "argData buffer: %v, %v", typ1, argData)
		arg, calls = typ1.generateBufferType(r, s, dir, argData, i, j)
	} else {
		log.Logf(0, "argData other: %v", typ)
		arg, calls = typ.generate(r, s, dir)
		if arg == nil {
			panic(fmt.Sprintf("generated arg is nil for field '%v'", typ.Name()))
		}
	}

	return arg, calls
}

func (a *PtrType) generatePtrType(r *randGen, s *state, dir Dir, argData [][][]byte, i int, j int) (arg Arg, calls []*Call) {
	
	var inner Arg
	if _, ok := a.Elem.(*BufferType); ok {
		inner, calls = a.Elem.(*BufferType).generateBufferType(r, s, a.ElemDir, argData, i, j)

	} else if typ, ok := a.Elem.(*StructType); ok {
		args := make([]Arg, len(typ.Fields))
		for idx, field := range typ.Fields {
			arg, calls1 := r.generateBPFArg(s, field.Type, a.ElemDir, argData, i, idx)
			args[idx] = arg
	        calls = append(calls, calls1...)
		}
		inner = MakeGroupArg(a.Elem, dir, args)

	} else {
		inner, calls = r.generateArg(s, a.Elem, a.ElemDir)
	}

	arg = r.allocAddr(s, a, dir, inner.Size(), inner)
	return arg, calls
}

func (a *BufferType) generateBufferType(r *randGen, s *state, dir Dir, argData [][][]byte, i int, j int) (arg Arg, calls []*Call) {
    switch a.Kind {
    case BufferBlobRand, BufferBlobRange:
        sz := r.randBufLen()
        if a.Kind == BufferBlobRange {
            sz = r.randRange(a.RangeBegin, a.RangeEnd)
        }
        if dir == DirOut {
            return MakeOutDataArg(a, dir, sz), nil
        }
        return MakeDataArg(a, dir, argData[i][j]), nil
    default:
        panic("unknown buffer kind")
    }
}
