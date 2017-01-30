// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"encoding/binary"
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

func encodeArg(arg *Arg, pid int) []byte {
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

func getFieldByName(arg *Arg, name string) *Arg {
	for _, field := range arg.Inner {
		if field.Type.FieldName() == name {
			return field
		}
	}
	panic(fmt.Sprintf("failed to find %v field in %v", name, arg.Type.Name()))
}

func calcChecksumIPv4(arg *Arg, pid int) (*Arg, *Arg) {
	csumField := getFieldByName(arg, "csum")
	if typ, ok := csumField.Type.(*sys.CsumType); !ok {
		panic(fmt.Sprintf("checksum field has bad type %v, arg: %+v", csumField.Type, csumField))
	} else if typ.Kind != sys.CsumIPv4 {
		panic(fmt.Sprintf("checksum field has bad kind %v, arg: %+v", typ.Kind, csumField))
	}
	if csumField.Value(pid) != 0 {
		panic(fmt.Sprintf("checksum field has nonzero value %v, arg: %+v", csumField.Value(pid), csumField))
	}
	bytes := encodeArg(arg, pid)
	csum := ipChecksum(bytes)
	newCsumField := *csumField
	newCsumField.Val = uintptr(csum)
	return csumField, &newCsumField
}

func extractHeaderParamsIPv4(arg *Arg) (*Arg, *Arg, *Arg) {
	srcAddr := getFieldByName(arg, "src_ip")
	if srcAddr.Size() != 4 {
		panic(fmt.Sprintf("src_ip field in %v must be 4 bytes", arg.Type.Name()))
	}
	dstAddr := getFieldByName(arg, "dst_ip")
	if dstAddr.Size() != 4 {
		panic(fmt.Sprintf("dst_ip field in %v must be 4 bytes", arg.Type.Name()))
	}
	protocol := getFieldByName(arg, "protocol")
	if protocol.Size() != 1 {
		panic(fmt.Sprintf("protocol field in %v must be 1 byte", arg.Type.Name()))
	}
	return srcAddr, dstAddr, protocol
}

func calcChecksumTCP(tcpPacket, srcAddr, dstAddr, protocol *Arg, pid int) (*Arg, *Arg) {
	tcpHeaderField := getFieldByName(tcpPacket, "header")
	csumField := getFieldByName(tcpHeaderField, "csum")
	if typ, ok := csumField.Type.(*sys.CsumType); !ok {
		panic(fmt.Sprintf("checksum field has bad type %v, arg: %+v", csumField.Type, csumField))
	} else if typ.Kind != sys.CsumTCP {
		panic(fmt.Sprintf("checksum field has bad kind %v, arg: %+v", typ.Kind, csumField))
	}

	var csum IPChecksum
	csum.Update(encodeArg(srcAddr, pid))
	csum.Update(encodeArg(dstAddr, pid))
	csum.Update([]byte{0, byte(protocol.Value(pid))})
	length := []byte{0, 0}
	binary.BigEndian.PutUint16(length, uint16(tcpPacket.Size()))
	csum.Update(length)
	csum.Update(encodeArg(tcpPacket, pid))

	newCsumField := *csumField
	newCsumField.Val = uintptr(csum.Digest())
	return csumField, &newCsumField
}

func calcChecksumsCall(c *Call, pid int) map[*Arg]*Arg {
	var csumMap map[*Arg]*Arg
	ipv4HeaderParsed := false
	var ipv4SrcAddr *Arg
	var ipv4DstAddr *Arg
	var ipv4Protocol *Arg
	foreachArgArray(&c.Args, nil, func(arg, base *Arg, _ *[]*Arg) {
		// syz_csum_ipv4_header struct is used in tests
		if arg.Type.Name() == "ipv4_header" || arg.Type.Name() == "syz_csum_ipv4_header" {
			if csumMap == nil {
				csumMap = make(map[*Arg]*Arg)
			}
			csumField, newCsumField := calcChecksumIPv4(arg, pid)
			csumMap[csumField] = newCsumField
			ipv4SrcAddr, ipv4DstAddr, ipv4Protocol = extractHeaderParamsIPv4(arg)
			ipv4HeaderParsed = true
		}
		// syz_csum_tcp_packet struct is used in tests
		if arg.Type.Name() == "tcp_packet" || arg.Type.Name() == "syz_csum_tcp_packet" {
			if !ipv4HeaderParsed {
				panic("tcp_packet is being parsed before ipv4_header")
			}
			csumField, newCsumField := calcChecksumTCP(arg, ipv4SrcAddr, ipv4DstAddr, ipv4Protocol, pid)
			csumMap[csumField] = newCsumField
		}
	})
	return csumMap
}
