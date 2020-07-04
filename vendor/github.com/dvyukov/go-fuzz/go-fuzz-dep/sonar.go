// Copyright 2015 go-fuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build gofuzz

package gofuzzdep

import (
	"sync/atomic"
	"unsafe"

	. "github.com/dvyukov/go-fuzz/go-fuzz-defs"
)

var (
	sonarRegion []byte
	sonarPos    uint32
)

const failure = ^uint8(0)

type iface struct {
	typ unsafe.Pointer
	val unsafe.Pointer
}

// Sonar is called by instrumentation code to notify go-fuzz about comparisons.
// Low 8 bits of id are flags, the rest is unique id of a comparison.
func Sonar(v1, v2 interface{}, id uint32) {
	var buf [SonarHdrLen + 2*SonarMaxLen]byte
	n1, f1 := serialize(v1, v2, buf[SonarHdrLen:])
	if n1 == failure {
		return
	}
	n2, f2 := serialize(v2, v1, buf[SonarHdrLen+n1:])
	if n2 == failure {
		return
	}
	// Ideal const operands are converted to signed int,
	// but it does not mean that the comparison is signed
	// unless the other operand is signed.
	if id&SonarConst1 != 0 {
		f1 &^= SonarSigned
	}
	if id&SonarConst2 != 0 {
		f2 &^= SonarSigned
	}
	id |= uint32(f1 | f2)
	serialize32(buf[:], id)
	buf[4] = n1
	buf[5] = n2
	n := uint32(SonarHdrLen + n1 + n2)
	pos := atomic.LoadUint32(&sonarPos)
	for {
		if pos+n > uint32(len(sonarRegion)) {
			return
		}
		if atomic.CompareAndSwapUint32(&sonarPos, pos, pos+n) {
			break
		}
		pos = atomic.LoadUint32(&sonarPos)
	}
	copy(sonarRegion[pos:pos+n], buf[:])
}

func serialize(v, v2 interface{}, buf []byte) (n, flags uint8) {
	switch vv := v.(type) {
	case int8:
		buf[0] = byte(vv)
		return 1, SonarSigned
	case uint8:
		buf[0] = byte(vv)
		return 1, 0
	case int16:
		return serialize16(buf, uint16(vv)), SonarSigned
	case uint16:
		return serialize16(buf, vv), 0
	case int32:
		return serialize32(buf, uint32(vv)), SonarSigned
	case uint32:
		return serialize32(buf, vv), 0
	case int64:
		return serialize64(buf, uint64(vv)), SonarSigned
	case uint64:
		return serialize64(buf, vv), 0
	case int:
		if unsafe.Sizeof(vv) == 4 {
			return serialize32(buf, uint32(vv)), SonarSigned
		} else {
			return serialize64(buf, uint64(vv)), SonarSigned
		}
	case uint:
		if unsafe.Sizeof(vv) == 4 {
			return serialize32(buf, uint32(vv)), 0
		} else {
			return serialize64(buf, uint64(vv)), 0
		}
	case string:
		if len(vv) > SonarMaxLen {
			return failure, 0
		}
		return uint8(copy(buf, vv)), SonarString
	case [1]byte:
		return uint8(copy(buf, vv[:])), SonarString
	case [2]byte:
		return uint8(copy(buf, vv[:])), SonarString
	case [3]byte:
		return uint8(copy(buf, vv[:])), SonarString
	case [4]byte:
		return uint8(copy(buf, vv[:])), SonarString
	case [5]byte:
		return uint8(copy(buf, vv[:])), SonarString
	case [6]byte:
		return uint8(copy(buf, vv[:])), SonarString
	case [7]byte:
		return uint8(copy(buf, vv[:])), SonarString
	case [8]byte:
		return uint8(copy(buf, vv[:])), SonarString
	case [9]byte:
		return uint8(copy(buf, vv[:])), SonarString
	case [10]byte:
		return uint8(copy(buf, vv[:])), SonarString
	case [11]byte:
		return uint8(copy(buf, vv[:])), SonarString
	case [12]byte:
		return uint8(copy(buf, vv[:])), SonarString
	case [13]byte:
		return uint8(copy(buf, vv[:])), SonarString
	case [14]byte:
		return uint8(copy(buf, vv[:])), SonarString
	case [15]byte:
		return uint8(copy(buf, vv[:])), SonarString
	case [16]byte:
		return uint8(copy(buf, vv[:])), SonarString
	case [17]byte:
		return uint8(copy(buf, vv[:])), SonarString
	case [18]byte:
		return uint8(copy(buf, vv[:])), SonarString
	case [19]byte:
		return uint8(copy(buf, vv[:])), SonarString
	case [20]byte:
		return uint8(copy(buf, vv[:])), SonarString
	default:
		// Special case: string literal is compared with a variable of
		// user type with string underlying type:
		//	type Name string
		//	var name Name
		//	if name == "foo" { ... }
		if _, ok := v2.(string); ok {
			s := *(*string)((*iface)(unsafe.Pointer(&v)).val)
			if len(s) <= SonarMaxLen {
				return uint8(copy(buf[:], s)), SonarString
			}
		}
		return failure, 0
	}
}

// The serialization routines here match those of encoding/binary.LittleEndian.
// They are copied here because importing encoding/binary creates import cycles.

func serialize16(buf []byte, v uint16) uint8 {
	_ = buf[1]
	buf[0] = byte(v >> 0)
	buf[1] = byte(v >> 8)
	return 2
}

func serialize32(buf []byte, v uint32) uint8 {
	_ = buf[3]
	buf[0] = byte(v >> 0)
	buf[1] = byte(v >> 8)
	buf[2] = byte(v >> 16)
	buf[3] = byte(v >> 24)
	return 4
}

func serialize64(buf []byte, v uint64) uint8 {
	_ = buf[7]
	buf[0] = byte(v >> 0)
	buf[1] = byte(v >> 8)
	buf[2] = byte(v >> 16)
	buf[3] = byte(v >> 24)
	buf[4] = byte(v >> 32)
	buf[5] = byte(v >> 40)
	buf[6] = byte(v >> 48)
	buf[7] = byte(v >> 56)
	return 8
}

func deserialize64(buf []byte) uint64 {
	_ = buf[7]
	return uint64(buf[0])<<0 |
		uint64(buf[1])<<8 |
		uint64(buf[2])<<16 |
		uint64(buf[3])<<24 |
		uint64(buf[4])<<32 |
		uint64(buf[5])<<40 |
		uint64(buf[6])<<48 |
		uint64(buf[7])<<56
}
