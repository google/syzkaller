// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Minimal KD protocol decoder.
// KD protocol is used by windows to talk to debuggers. Here are some links:
// https://github.com/radare/radare2/issues/1246#issuecomment-135565901
// http://articles.sysprogs.org/kdvmware/kdcom/
// https://doxygen.reactos.org/df/de3/windbgkd_8h_source.html
package kd

import (
	"bytes"
	"fmt"
	"unsafe"
)

var (
	dataHeader = []byte{0x30, 0x30, 0x30, 0x30}
)

const (
	typStateChange64 = 7
)

type packet struct {
	header uint32
	typ    uint16
	size   uint16
	id     uint32
	csum   uint32
}

func Decode(data []byte) (start, size int, decoded []byte) {
	if len(data) < len(dataHeader) {
		return
	}
	start = bytes.Index(data, dataHeader)
	if start == -1 {
		start = len(data) - len(dataHeader) - 1
		return
	}
	packetSize := int(unsafe.Sizeof(packet{}))
	if len(data)-start < packetSize {
		return // incomplete header
	}
	// Note: assuming little-endian machine.
	pkt := (*packet)(unsafe.Pointer(&data[start]))
	if len(data)-start < packetSize+int(pkt.size) {
		return // incomplete data
	}
	size = packetSize + int(pkt.size) // skip whole packet
	if pkt.typ == typStateChange64 {
		if int(pkt.size) < int(unsafe.Sizeof(stateChange64{})) {
			return
		}
		payload := (*stateChange64)(unsafe.Pointer(&data[start+packetSize]))
		chance := "second"
		if payload.exception.firstChance != 0 {
			chance = "first"
		}
		decoded = []byte(fmt.Sprintf("\n\nBUG: %v chance exception 0x%x\n\n%#v\n\n",
			chance, payload.exception.code, payload))
	}
	return
}

type stateChange64 struct {
	state          uint32
	processorLevel uint16
	processor      uint16
	numProcessors  uint32
	thread         uint64
	pc             uint64
	exception      exception64
	report         controlReport
}

type exception64 struct {
	code        uint32
	flags       uint32
	record      uint64
	address     uint64
	numParams   uint32
	unused      uint32
	params      [15]uint64
	firstChance uint32
}

type controlReport struct {
	dr6         uint64
	dr7         uint64
	eflags      uint32
	numInstr    uint16
	reportFlags uint16
	instr       [16]byte
	cs          uint16
	ds          uint16
	es          uint16
	fs          uint16
}
