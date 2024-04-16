// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Pseudo instructions for arm64 architecture.

package arm64

import (
	"math/rand"

	"github.com/google/syzkaller/pkg/ifuzz/iset"
)

var pseudo = []*Insn{
	{
		Name:   "PSEUDO_HCALL",
		Pseudo: true,
		Priv:   true,
		Generator: func(cfg *iset.Config, r *rand.Rand) []byte {
			gen := makeGen(cfg, r)
			gen.smcccHvc()
			return gen.text
		},
	},
}

type generator struct {
	r    *rand.Rand
	text []byte
}

func makeGen(cfg *iset.Config, r *rand.Rand) *generator {
	return &generator{
		r: r,
	}
}

func (gen *generator) smcccHvc() {
	cmd := (1 << 31) | (gen.r.Intn(2) << 30) | ((gen.r.Intn(8) & 0x3F) << 24) | (gen.r.Intn(0x10000) & 0xFFFF)
	gen.movRegImm32(0, cmd)
	gen.movRegImm16(1, gen.r.Intn(16))
	gen.movRegImm16(2, gen.r.Intn(16))
	gen.movRegImm16(3, gen.r.Intn(16))
	gen.movRegImm16(4, gen.r.Intn(16))
	gen.byte(0x02, 0x00, 0x00, 0xd4)
}

func (gen *generator) movRegImm32(reg, imm int) {
	gen.movRegImm16(reg, imm)
	// Encoding `movk reg, imm16, LSL #16`.
	upper := (imm >> 16) & 0xffff
	opcode := uint32(0xf2a00000)
	opcode |= uint32(upper) << 5
	opcode |= uint32(reg & 0xf)
	gen.imm32(opcode)
}

func (gen *generator) movRegImm16(reg, imm int) {
	// Encoding `mov reg, imm16`.
	imm = imm & 0xffff
	opcode := uint32(0xd2800000)
	opcode |= uint32(imm) << 5
	opcode |= uint32(reg & 0xf)
	gen.imm32(opcode)
}

func (gen *generator) imm32(v uint32) {
	gen.byte(byte(v>>0), byte(v>>8), byte(v>>16), byte(v>>24))
}

func (gen *generator) byte(v ...uint8) {
	gen.text = append(gen.text, v...)
}
