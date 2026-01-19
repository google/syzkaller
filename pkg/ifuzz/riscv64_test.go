// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ifuzz

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"testing"

	"github.com/google/syzkaller/pkg/ifuzz/iset"
	"github.com/google/syzkaller/pkg/ifuzz/riscv64"
)

func PrintInsnRv(insn riscv64.Insn) {
	operands := ""
	for i, op := range insn.Operands {
		field := insn.Fields[i]
		operands += fmt.Sprintf("%s:%d=%x ", field.Name, field.Length, op)
	}
	fmt.Printf("{ \"%s\" [0x%x] %s }\n", insn.Name, insn.AsUInt32, operands)
}

func parseAndPrintRv(from uint32) {
	insn, _ := riscv64.ParseInsn(from)
	PrintInsnRv(insn)
}

func TestSomethingRv(t *testing.T) {
	// add	a0,a0,a1
	parseAndPrintRv(0x00b50533)
	// li	t0,0
	parseAndPrintRv(0x00000293)
	// mul	a0,a0,a1
	parseAndPrintRv(0x02b50533)
	// csrr	a0,sstatus
	parseAndPrintRv(0x10002573)
	// ecall
	parseAndPrintRv(0x00000073)
}

func TestSumRv(t *testing.T) {
	data := [][2]string{
		{"00100073", "ebreak"},
		{"18029073", "csrw	satp,t0"},
		{"c01025f3", "rdtime	a1"},
		{"c0002573", "rdcycle	a0"},
		{"02b56533", "rem	a0,a0,a1"},
		{"02b54533", "div	a0,a0,a1"},
		{"00030513", "mv	a0,t1"},
		{"00c5a023", "sw	a2,0(a1)"},
	}
	for _, pair := range data {
		opcode, err := strconv.ParseUint(pair[0], 16, 32)
		if err != nil {
			t.Fatalf("failed to parse opcode")
		}
		fmt.Printf("%s\n", pair[1])
		parseAndPrintRv(uint32(opcode))
	}
}

func decodeRvText(t *testing.T, insnset iset.InsnSet, text []byte) {
	for len(text) > 0 {
		size, err := insnset.Decode(iset.ModeLong64, text)
		if size == 0 || err != nil {
			t.Errorf("failed to decode text: %v", text)
			return
		}
		parseAndPrintRv(binary.LittleEndian.Uint32(text[:4]))
		text = text[size:]
	}
}

func TestDecodeSamplesRv(t *testing.T) {
	testData := []string{
		"7300100073900918",
		"f32510c0732500c0",
		"3365b5023345b502",
		"1305030023a0c500",
		// 007302b3 -> add t0, t1, t2 -> "add" [0x7302b3] xs2:5=7 xs1:5=6 xd:5=5
		"b3027300",
	}
	insnset := iset.Arches["riscv64"]
	for _, str := range testData {
		text, err := hex.DecodeString(str)
		if err != nil {
			t.Fatalf("invalid hex string")
		}
		fmt.Printf("Decoding % x\n", text)
		decodeRvText(t, insnset, text)
	}
}
