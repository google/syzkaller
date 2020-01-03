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

func calcChecksumsCall(c *Call) (map[Arg]CsumInfo, map[Arg]struct{}) {
	var inetCsumFields, pseudoCsumFields []Arg

	// Find all csum fields.
	ForeachArg(c, func(arg Arg, _ *ArgCtx) {
		if typ, ok := arg.Type().(*CsumType); ok {
			switch typ.Kind {
			case CsumInet:
				inetCsumFields = append(inetCsumFields, arg)
			case CsumPseudo:
				pseudoCsumFields = append(pseudoCsumFields, arg)
			default:
				panic(fmt.Sprintf("unknown csum kind %v", typ.Kind))
			}
		}
	})

	if len(inetCsumFields) == 0 && len(pseudoCsumFields) == 0 {
		return nil, nil
	}

	// Build map of each field to its parent struct.
	parentsMap := make(map[Arg]Arg)
	ForeachArg(c, func(arg Arg, _ *ArgCtx) {
		if _, ok := arg.Type().(*StructType); ok {
			for _, field := range arg.(*GroupArg).Inner {
				parentsMap[InnerArg(field)] = arg
			}
		}
	})

	csumMap := make(map[Arg]CsumInfo)
	csumUses := make(map[Arg]struct{})

	// Calculate generic inet checksums.
	for _, arg := range inetCsumFields {
		typ, _ := arg.Type().(*CsumType)
		csummedArg := findCsummedArg(arg, typ, parentsMap)
		csumUses[csummedArg] = struct{}{}
		chunk := CsumChunk{CsumChunkArg, csummedArg, 0, 0}
		csumMap[arg] = CsumInfo{Kind: CsumInet, Chunks: []CsumChunk{chunk}}
	}

	// No need to continue if there are no pseudo csum fields.
	if len(pseudoCsumFields) == 0 {
		return csumMap, csumUses
	}

	// Extract ipv4 or ipv6 source and destination addresses.
	var ipSrcAddr, ipDstAddr Arg
	ForeachArg(c, func(arg Arg, _ *ArgCtx) {
		groupArg, ok := arg.(*GroupArg)
		if !ok {
			return
		}
		// syz_csum_* structs are used in tests
		switch groupArg.Type().TemplateName() {
		case "ipv4_header", "syz_csum_ipv4_header":
			ipSrcAddr, ipDstAddr = extractHeaderParams(groupArg, 4)
		case "ipv6_packet_t", "syz_csum_ipv6_header":
			ipSrcAddr, ipDstAddr = extractHeaderParams(groupArg, 16)
		}
	})
	if ipSrcAddr == nil || ipDstAddr == nil {
		panic("no ipv4 nor ipv6 header found")
	}

	// Calculate pseudo checksums.
	for _, arg := range pseudoCsumFields {
		typ, _ := arg.Type().(*CsumType)
		csummedArg := findCsummedArg(arg, typ, parentsMap)
		protocol := uint8(typ.Protocol)
		var info CsumInfo
		if ipSrcAddr.Size() == 4 {
			info = composePseudoCsumIPv4(csummedArg, ipSrcAddr, ipDstAddr, protocol)
		} else {
			info = composePseudoCsumIPv6(csummedArg, ipSrcAddr, ipDstAddr, protocol)
		}
		csumMap[arg] = info
		csumUses[csummedArg] = struct{}{}
		csumUses[ipSrcAddr] = struct{}{}
		csumUses[ipDstAddr] = struct{}{}
	}

	return csumMap, csumUses
}

func findCsummedArg(arg Arg, typ *CsumType, parentsMap map[Arg]Arg) Arg {
	if typ.Buf == ParentRef {
		if csummedArg, ok := parentsMap[arg]; ok {
			return csummedArg
		}
		panic(fmt.Sprintf("%v for %v is not in parents map", ParentRef, typ.Name()))
	} else {
		for parent := parentsMap[arg]; parent != nil; parent = parentsMap[parent] {
			// TODO(dvyukov): support template argument names as in size calculation.
			if typ.Buf == parent.Type().Name() {
				return parent
			}
		}
	}
	panic(fmt.Sprintf("csum field '%v' references non existent field '%v'", typ.FieldName(), typ.Buf))
}

func composePseudoCsumIPv4(tcpPacket, srcAddr, dstAddr Arg, protocol uint8) CsumInfo {
	info := CsumInfo{Kind: CsumInet}
	info.Chunks = append(info.Chunks, CsumChunk{CsumChunkArg, srcAddr, 0, 0})
	info.Chunks = append(info.Chunks, CsumChunk{CsumChunkArg, dstAddr, 0, 0})
	info.Chunks = append(info.Chunks, CsumChunk{CsumChunkConst, nil, uint64(swap16(uint16(protocol))), 2})
	info.Chunks = append(info.Chunks, CsumChunk{CsumChunkConst, nil, uint64(swap16(uint16(tcpPacket.Size()))), 2})
	info.Chunks = append(info.Chunks, CsumChunk{CsumChunkArg, tcpPacket, 0, 0})
	return info
}

func composePseudoCsumIPv6(tcpPacket, srcAddr, dstAddr Arg, protocol uint8) CsumInfo {
	info := CsumInfo{Kind: CsumInet}
	info.Chunks = append(info.Chunks, CsumChunk{CsumChunkArg, srcAddr, 0, 0})
	info.Chunks = append(info.Chunks, CsumChunk{CsumChunkArg, dstAddr, 0, 0})
	info.Chunks = append(info.Chunks, CsumChunk{CsumChunkConst, nil, uint64(swap32(uint32(tcpPacket.Size()))), 4})
	info.Chunks = append(info.Chunks, CsumChunk{CsumChunkConst, nil, uint64(swap32(uint32(protocol))), 4})
	info.Chunks = append(info.Chunks, CsumChunk{CsumChunkArg, tcpPacket, 0, 0})
	return info
}

func extractHeaderParams(arg *GroupArg, size uint64) (Arg, Arg) {
	srcAddr := getFieldByName(arg, "src_ip")
	dstAddr := getFieldByName(arg, "dst_ip")
	if srcAddr.Size() != size || dstAddr.Size() != size {
		panic(fmt.Sprintf("src/dst_ip fields in %v must be %v bytes", arg.Type().Name(), size))
	}
	return srcAddr, dstAddr
}

func getFieldByName(arg *GroupArg, name string) Arg {
	for _, field := range arg.Inner {
		if field.Type().FieldName() == name {
			return field
		}
	}
	panic(fmt.Sprintf("failed to find %v field in %v", name, arg.Type().Name()))
}
