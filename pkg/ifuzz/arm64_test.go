// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ifuzz

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"testing"

	"github.com/google/syzkaller/pkg/ifuzz/arm64"
	"github.com/google/syzkaller/pkg/ifuzz/iset"
)

func PrintInsn(insn arm64.Insn) {
	operands := ""
	for i, op := range insn.Operands {
		field := insn.Fields[i]
		operands += fmt.Sprintf("%s:%d=%x ", field.Name, field.Length, op)
	}
	fmt.Printf("{ \"%s\" [0x%x] %s }\n", insn.Name, insn.AsUInt32, operands)
}

func parseAndPrint(from uint32) {
	insn, _ := arm64.ParseInsn(from)
	PrintInsn(insn)
}

func TestSomething(t *testing.T) {
	parseAndPrint(0x0)
	parseAndPrint(0xff3ffc00)
	parseAndPrint(0x5e20b800)
	parseAndPrint(0x52800021)
	parseAndPrint(0x1b020020)
	parseAndPrint(0x1b007c21)
	parseAndPrint(0xb9400fe0)
}

func TestSum(t *testing.T) {
	data := [][2]string{
		{"d10043ff", "sub	sp, sp, #0x10"},
		{"b9000fe0", "str	w0, [sp, #12]"},
		{"b9000be1", "str	w1, [sp, #8]"},
		{"b90007e2", "str	w2, [sp, #4]"},
		{"b9400be1", "ldr	w1, [sp, #8]"},
		{"b94007e0", "ldr	w0, [sp, #4]"},
		{"1b007c21", "mul	w1, w1, w0"},
		{"b9400fe0", "ldr	w0, [sp, #12]"},
		{"0b000020", "add	w0, w1, w0"},
		{"910043ff", "add	sp, sp, #0x10"},
		{"d65f03c0", "ret"},
	}
	for _, pair := range data {
		opcode, err := strconv.ParseUint(pair[0], 16, 32)
		if err != nil {
			t.Fatalf("failed to parse opcode")
		}
		fmt.Printf("%s\n", pair[1])
		parseAndPrint(uint32(opcode))
	}
}

func TestDecodeSamples(t *testing.T) {
	testData := []string{
		"2000000b",
		"0000409b000028d5007008d5008080880000000e0038201e007008d5000028d50020000c0000181e",
		"000cc0380094002f0100a0d40000600d000880b8000000fa0000208a000c40380068284e000008d5",
		// x0[*x1] = *x2
		"280080b9490040b9097828b8",
		// hvc(x0, x1, x2, x3, x4)
		"e00180d2210080d2420080d2630080d2840080d2020000d4",
		"20e09fd200c0b0f2210080d2420080d2630080d2840080d2020000d4",
		"000080d200c0b0f2210080d2420080d2630080d2840080d2020000d4",
	}
	insnset := iset.Arches["arm64"]
	for _, str := range testData {
		text, err := hex.DecodeString(str)
		fmt.Printf("Decoding % x\n", text)
		if err != nil {
			t.Fatalf("invalid hex string")
		}
		for len(text) != 0 {
			size, err := insnset.Decode(iset.ModeLong64, text)
			if size == 0 || err != nil {
				t.Errorf("failed to decode text: %v", text)
				break
			}
			parseAndPrint(binary.LittleEndian.Uint32(text[0:4]))
			text = text[size:]
		}
	}
}
