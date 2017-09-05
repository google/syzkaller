// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
)

type CsumChunkKind int

const (
	CsumChunkArg CsumChunkKind = iota
	CsumChunkConst
)

type CsumInfo struct {
	Kind   CsumKind
	Chunks []CsumChunk
}

type CsumChunk struct {
	Kind  CsumChunkKind
	Arg   Arg    // for CsumChunkArg
	Value uint64 // for CsumChunkConst
	Size  uint64 // for CsumChunkConst
}

func getFieldByName(arg Arg, name string) Arg {
	for _, field := range arg.(*GroupArg).Inner {
		if field.Type().FieldName() == name {
			return field
		}
	}
	panic(fmt.Sprintf("failed to find %v field in %v", name, arg.Type().Name()))
}

func extractHeaderParamsIPv4(arg Arg) (Arg, Arg) {
	srcAddr := getFieldByName(arg, "src_ip")
	if srcAddr.Size() != 4 {
		panic(fmt.Sprintf("src_ip field in %v must be 4 bytes", arg.Type().Name()))
	}
	dstAddr := getFieldByName(arg, "dst_ip")
	if dstAddr.Size() != 4 {
		panic(fmt.Sprintf("dst_ip field in %v must be 4 bytes", arg.Type().Name()))
	}
	return srcAddr, dstAddr
}

func extractHeaderParamsIPv6(arg Arg) (Arg, Arg) {
	srcAddr := getFieldByName(arg, "src_ip")
	if srcAddr.Size() != 16 {
		panic(fmt.Sprintf("src_ip field in %v must be 4 bytes", arg.Type().Name()))
	}
	dstAddr := getFieldByName(arg, "dst_ip")
	if dstAddr.Size() != 16 {
		panic(fmt.Sprintf("dst_ip field in %v must be 4 bytes", arg.Type().Name()))
	}
	return srcAddr, dstAddr
}

func composePseudoCsumIPv4(tcpPacket, srcAddr, dstAddr Arg, protocol uint8, pid int) CsumInfo {
	info := CsumInfo{Kind: CsumInet}
	info.Chunks = append(info.Chunks, CsumChunk{CsumChunkArg, srcAddr, 0, 0})
	info.Chunks = append(info.Chunks, CsumChunk{CsumChunkArg, dstAddr, 0, 0})
	info.Chunks = append(info.Chunks, CsumChunk{CsumChunkConst, nil, uint64(swap16(uint16(protocol))), 2})
	info.Chunks = append(info.Chunks, CsumChunk{CsumChunkConst, nil, uint64(swap16(uint16(tcpPacket.Size()))), 2})
	info.Chunks = append(info.Chunks, CsumChunk{CsumChunkArg, tcpPacket, 0, 0})
	return info
}

func composePseudoCsumIPv6(tcpPacket, srcAddr, dstAddr Arg, protocol uint8, pid int) CsumInfo {
	info := CsumInfo{Kind: CsumInet}
	info.Chunks = append(info.Chunks, CsumChunk{CsumChunkArg, srcAddr, 0, 0})
	info.Chunks = append(info.Chunks, CsumChunk{CsumChunkArg, dstAddr, 0, 0})
	info.Chunks = append(info.Chunks, CsumChunk{CsumChunkConst, nil, uint64(swap32(uint32(tcpPacket.Size()))), 4})
	info.Chunks = append(info.Chunks, CsumChunk{CsumChunkConst, nil, uint64(swap32(uint32(protocol))), 4})
	info.Chunks = append(info.Chunks, CsumChunk{CsumChunkArg, tcpPacket, 0, 0})
	return info
}

func findCsummedArg(arg Arg, typ *CsumType, parentsMap map[Arg]Arg) Arg {
	if typ.Buf == "parent" {
		if csummedArg, ok := parentsMap[arg]; ok {
			return csummedArg
		}
		panic(fmt.Sprintf("parent for %v is not in parents map", typ.Name()))
	} else {
		for parent := parentsMap[arg]; parent != nil; parent = parentsMap[parent] {
			if typ.Buf == parent.Type().Name() {
				return parent
			}
		}
	}
	panic(fmt.Sprintf("csum field '%v' references non existent field '%v'", typ.FieldName(), typ.Buf))
}

func calcChecksumsCall(c *Call, pid int) map[Arg]CsumInfo {
	var inetCsumFields []Arg
	var pseudoCsumFields []Arg

	// Find all csum fields.
	foreachArgArray(&c.Args, nil, func(arg, base Arg, _ *[]Arg) {
		if typ, ok := arg.Type().(*CsumType); ok {
			switch typ.Kind {
			case CsumInet:
				inetCsumFields = append(inetCsumFields, arg)
			case CsumPseudo:
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
	parentsMap := make(map[Arg]Arg)
	foreachArgArray(&c.Args, nil, func(arg, base Arg, _ *[]Arg) {
		if _, ok := arg.Type().(*StructType); ok {
			for _, field := range arg.(*GroupArg).Inner {
				parentsMap[InnerArg(field)] = arg
			}
		}
	})

	csumMap := make(map[Arg]CsumInfo)

	// Calculate generic inet checksums.
	for _, arg := range inetCsumFields {
		typ, _ := arg.Type().(*CsumType)
		csummedArg := findCsummedArg(arg, typ, parentsMap)
		chunk := CsumChunk{CsumChunkArg, csummedArg, 0, 0}
		info := CsumInfo{Kind: CsumInet, Chunks: make([]CsumChunk, 0)}
		info.Chunks = append(info.Chunks, chunk)
		csumMap[arg] = info
	}

	// No need to continue if there are no pseudo csum fields.
	if len(pseudoCsumFields) == 0 {
		return csumMap
	}

	// Extract ipv4 or ipv6 source and destination addresses.
	ipv4HeaderParsed := false
	ipv6HeaderParsed := false
	var ipSrcAddr Arg
	var ipDstAddr Arg
	foreachArgArray(&c.Args, nil, func(arg, base Arg, _ *[]Arg) {
		// syz_csum_* structs are used in tests
		switch arg.Type().Name() {
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
		typ, _ := arg.Type().(*CsumType)
		csummedArg := findCsummedArg(arg, typ, parentsMap)
		protocol := uint8(typ.Protocol)
		var info CsumInfo
		if ipv4HeaderParsed {
			info = composePseudoCsumIPv4(csummedArg, ipSrcAddr, ipDstAddr, protocol, pid)
		} else {
			info = composePseudoCsumIPv6(csummedArg, ipSrcAddr, ipDstAddr, protocol, pid)
		}
		csumMap[arg] = info
	}

	return csumMap
}
