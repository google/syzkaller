// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
	"unsafe"

	"github.com/google/syzkaller/sys"
)

type IPChecksum struct {
	acc uint32
}

func (csum *IPChecksum) Update(data []byte) {
	length := len(data) - 1
	for i := 0; i < length; i += 2 {
		csum.acc += uint32(data[i]) << 8
		csum.acc += uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		csum.acc += uint32(data[length]) << 8
	}
	for csum.acc > 0xffff {
		csum.acc = (csum.acc >> 16) + (csum.acc & 0xffff)
	}
}

func (csum *IPChecksum) Digest() uint16 {
	return ^uint16(csum.acc)
}

func ipChecksum(data []byte) uint16 {
	var csum IPChecksum
	csum.Update(data)
	return csum.Digest()
}

func bitmaskLen(bfLen uint64) uint64 {
	return (1 << bfLen) - 1
}

func bitmaskLenOff(bfOff, bfLen uint64) uint64 {
	return bitmaskLen(bfLen) << bfOff
}

func storeByBitmask8(addr *uint8, value uint8, bfOff uint64, bfLen uint64) {
	if bfOff == 0 && bfLen == 0 {
		*addr = value
	} else {
		newValue := *addr
		newValue &= ^uint8(bitmaskLenOff(bfOff, bfLen))
		newValue |= (value & uint8(bitmaskLen(bfLen))) << bfOff
		*addr = newValue
	}
}

func storeByBitmask16(addr *uint16, value uint16, bfOff uint64, bfLen uint64) {
	if bfOff == 0 && bfLen == 0 {
		*addr = value
	} else {
		newValue := *addr
		newValue &= ^uint16(bitmaskLenOff(bfOff, bfLen))
		newValue |= (value & uint16(bitmaskLen(bfLen))) << bfOff
		*addr = newValue
	}
}

func storeByBitmask32(addr *uint32, value uint32, bfOff uint64, bfLen uint64) {
	if bfOff == 0 && bfLen == 0 {
		*addr = value
	} else {
		newValue := *addr
		newValue &= ^uint32(bitmaskLenOff(bfOff, bfLen))
		newValue |= (value & uint32(bitmaskLen(bfLen))) << bfOff
		*addr = newValue
	}
}

func storeByBitmask64(addr *uint64, value uint64, bfOff uint64, bfLen uint64) {
	if bfOff == 0 && bfLen == 0 {
		*addr = value
	} else {
		newValue := *addr
		newValue &= ^uint64(bitmaskLenOff(bfOff, bfLen))
		newValue |= (value & uint64(bitmaskLen(bfLen))) << bfOff
		*addr = newValue
	}
}

func encodeStruct(arg *Arg, pid int) []byte {
	bytes := make([]byte, arg.Size())
	foreachSubargOffset(arg, func(arg *Arg, offset uintptr) {
		switch arg.Kind {
		case ArgConst:
			addr := unsafe.Pointer(&bytes[offset])
			val := arg.Value(pid)
			bfOff := uint64(arg.Type.BitfieldOffset())
			bfLen := uint64(arg.Type.BitfieldLength())
			switch arg.Size() {
			case 1:
				storeByBitmask8((*uint8)(addr), uint8(val), bfOff, bfLen)
			case 2:
				storeByBitmask16((*uint16)(addr), uint16(val), bfOff, bfLen)
			case 4:
				storeByBitmask32((*uint32)(addr), uint32(val), bfOff, bfLen)
			case 8:
				storeByBitmask64((*uint64)(addr), uint64(val), bfOff, bfLen)
			default:
				panic(fmt.Sprintf("bad arg size %v, arg: %+v\n", arg.Size(), arg))
			}
		case ArgData:
			copy(bytes[offset:], arg.Data)
		default:
			panic(fmt.Sprintf("bad arg kind %v, arg: %+v, type: %+v", arg.Kind, arg, arg.Type))
		}
	})
	return bytes
}

func calcChecksumIPv4(arg *Arg, pid int) (*Arg, *Arg) {
	var csumField *Arg
	for _, field := range arg.Inner {
		if _, ok := field.Type.(*sys.CsumType); ok {
			csumField = field
			break
		}
	}
	if csumField == nil {
		panic(fmt.Sprintf("failed to find csum field in %v", arg.Type.Name()))
	}
	if csumField.Value(pid) != 0 {
		panic(fmt.Sprintf("checksum field has nonzero value %v, arg: %+v", csumField.Value(pid), csumField))
	}
	bytes := encodeStruct(arg, pid)
	csum := ipChecksum(bytes)
	newCsumField := *csumField
	newCsumField.Val = uintptr(csum)
	return csumField, &newCsumField
}

func calcChecksumsCall(c *Call, pid int) map[*Arg]*Arg {
	var m map[*Arg]*Arg
	foreachArgArray(&c.Args, nil, func(arg, base *Arg, _ *[]*Arg) {
		// syz_csum_ipv4 struct is used in tests
		if arg.Type.Name() == "ipv4_header" || arg.Type.Name() == "syz_csum_ipv4" {
			if m == nil {
				m = make(map[*Arg]*Arg)
			}
			k, v := calcChecksumIPv4(arg, pid)
			m[k] = v
		}
	})
	return m
}
