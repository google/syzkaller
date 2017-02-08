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

func calcChecksumInet(packet, csumField *Arg, pid int) *Arg {
	bytes := encodeArg(packet, pid)
	csum := ipChecksum(bytes)
	newCsumField := *csumField
	newCsumField.Val = uintptr(csum)
	return &newCsumField
}

func extractHeaderParamsIPv4(arg *Arg) (*Arg, *Arg) {
	srcAddr := getFieldByName(arg, "src_ip")
	if srcAddr.Size() != 4 {
		panic(fmt.Sprintf("src_ip field in %v must be 4 bytes", arg.Type.Name()))
	}
	dstAddr := getFieldByName(arg, "dst_ip")
	if dstAddr.Size() != 4 {
		panic(fmt.Sprintf("dst_ip field in %v must be 4 bytes", arg.Type.Name()))
	}
	return srcAddr, dstAddr
}

func extractHeaderParamsIPv6(arg *Arg) (*Arg, *Arg) {
	srcAddr := getFieldByName(arg, "src_ip")
	if srcAddr.Size() != 16 {
		panic(fmt.Sprintf("src_ip field in %v must be 4 bytes", arg.Type.Name()))
	}
	dstAddr := getFieldByName(arg, "dst_ip")
	if dstAddr.Size() != 16 {
		panic(fmt.Sprintf("dst_ip field in %v must be 4 bytes", arg.Type.Name()))
	}
	return srcAddr, dstAddr
}

func composePseudoHeaderIPv4(tcpPacket, srcAddr, dstAddr *Arg, protocol uint8, pid int) []byte {
	header := []byte{}
	header = append(header, encodeArg(srcAddr, pid)...)
	header = append(header, encodeArg(dstAddr, pid)...)
	header = append(header, []byte{0, protocol}...)
	length := []byte{0, 0}
	binary.BigEndian.PutUint16(length, uint16(tcpPacket.Size()))
	header = append(header, length...)
	return header
}

func composePseudoHeaderIPv6(tcpPacket, srcAddr, dstAddr *Arg, protocol uint8, pid int) []byte {
	header := []byte{}
	header = append(header, encodeArg(srcAddr, pid)...)
	header = append(header, encodeArg(dstAddr, pid)...)
	length := []byte{0, 0, 0, 0}
	binary.BigEndian.PutUint32(length, uint32(tcpPacket.Size()))
	header = append(header, length...)
	header = append(header, []byte{0, 0, 0, protocol}...)
	return header
}

func calcChecksumPseudo(packet, csumField *Arg, pseudoHeader []byte, pid int) *Arg {
	var csum IPChecksum
	csum.Update(pseudoHeader)
	csum.Update(encodeArg(packet, pid))
	newCsumField := *csumField
	newCsumField.Val = uintptr(csum.Digest())
	return &newCsumField
}

func findCsummedArg(arg *Arg, typ *sys.CsumType, parentsMap map[*Arg]*Arg) *Arg {
	if typ.Buf == "parent" {
		if csummedArg, ok := parentsMap[arg]; ok {
			return csummedArg
		}
		panic(fmt.Sprintf("parent for %v is not in parents map", typ.Name()))
	} else {
		for parent := parentsMap[arg]; parent != nil; parent = parentsMap[parent] {
			if typ.Buf == parent.Type.Name() {
				return parent
			}
		}
	}
	panic(fmt.Sprintf("csum field '%v' references non existent field '%v'", typ.FieldName(), typ.Buf))
}

func calcChecksumsCall(c *Call, pid int) map[*Arg]*Arg {
	var inetCsumFields []*Arg
	var pseudoCsumFields []*Arg

	// Find all csum fields.
	foreachArgArray(&c.Args, nil, func(arg, base *Arg, _ *[]*Arg) {
		if typ, ok := arg.Type.(*sys.CsumType); ok {
			switch typ.Kind {
			case sys.CsumInet:
				inetCsumFields = append(inetCsumFields, arg)
			case sys.CsumPseudo:
				pseudoCsumFields = append(pseudoCsumFields, arg)
			default:
				panic(fmt.Sprintf("unknown csum kind %v\n", typ.Kind))
			}
		}
	})

	// Return if no csum fields found.
	if len(inetCsumFields) == 0 && len(pseudoCsumFields) == 0 {
		return nil
	}

	// Build map of each field to its parent struct.
	parentsMap := make(map[*Arg]*Arg)
	foreachArgArray(&c.Args, nil, func(arg, base *Arg, _ *[]*Arg) {
		if _, ok := arg.Type.(*sys.StructType); ok {
			for _, field := range arg.Inner {
				parentsMap[field.InnerArg()] = arg
			}
		}
	})

	csumMap := make(map[*Arg]*Arg)

	// Calculate inet checksums.
	for _, arg := range inetCsumFields {
		typ, _ := arg.Type.(*sys.CsumType)
		csummedArg := findCsummedArg(arg, typ, parentsMap)
		newCsumField := calcChecksumInet(csummedArg, arg, pid)
		csumMap[arg] = newCsumField
	}

	// No need to continue if there are no pseudo csum fields.
	if len(pseudoCsumFields) == 0 {
		return csumMap
	}

	// Extract ipv4 or ipv6 source and destination addresses.
	ipv4HeaderParsed := false
	ipv6HeaderParsed := false
	var ipSrcAddr *Arg
	var ipDstAddr *Arg
	foreachArgArray(&c.Args, nil, func(arg, base *Arg, _ *[]*Arg) {
		// syz_csum_* structs are used in tests
		switch arg.Type.Name() {
		case "ipv4_header", "syz_csum_ipv4_header":
			ipSrcAddr, ipDstAddr = extractHeaderParamsIPv4(arg)
			ipv4HeaderParsed = true
		case "ipv6_packet", "syz_csum_ipv6_header":
			ipSrcAddr, ipDstAddr = extractHeaderParamsIPv6(arg)
			ipv6HeaderParsed = true
		}
	})
	if !ipv4HeaderParsed && !ipv6HeaderParsed {
		panic("no ipv4 nor ipv6 header found")
	}

	// Calculate pseudo checksums.
	for _, arg := range pseudoCsumFields {
		typ, _ := arg.Type.(*sys.CsumType)
		csummedArg := findCsummedArg(arg, typ, parentsMap)
		protocol := uint8(typ.Protocol)
		var pseudoHeader []byte
		if ipv4HeaderParsed {
			pseudoHeader = composePseudoHeaderIPv4(csummedArg, ipSrcAddr, ipDstAddr, protocol, pid)
		} else {
			pseudoHeader = composePseudoHeaderIPv6(csummedArg, ipSrcAddr, ipDstAddr, protocol, pid)
		}
		newCsumField := calcChecksumPseudo(csummedArg, arg, pseudoHeader, pid)
		csumMap[arg] = newCsumField
	}

	return csumMap
}
