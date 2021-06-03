// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:generate bash -c "go run gen/gen.go gen/all-enc-instructions.txt > generated/insns.go"

// Package x86 allows to generate and mutate x86 machine code.
package x86

import (
	"math/rand"

	"github.com/google/syzkaller/pkg/ifuzz/iset"
)

type Insn struct {
	Name      string
	Extension string

	Mode   iset.Mode // bitmask of compatible modes
	Priv   bool      // CPL=0
	Pseudo bool      // pseudo instructions can consist of several real instructions

	Opcode      []byte
	Prefix      []byte
	Suffix      []byte
	Modrm       bool
	Mod         int8
	Reg         int8 // -6 - segment register, -8 - control register
	Rm          int8
	Srm         bool // register is embed in the first byte
	NoSibDisp   bool // no SIB/disp even if modrm says otherwise
	Imm         int8 // immediate size, -1 - immediate size, -2 - address size, -3 - operand size
	Imm2        int8
	NoRepPrefix bool
	No66Prefix  bool
	Rexw        int8 // 1 must be set, -1 must not be set
	Mem32       bool // instruction always references 32-bit memory operand, 0x67 is illegal
	Mem16       bool // instruction always references 16-bit memory operand

	Vex        byte
	VexMap     byte
	VexL       int8
	VexNoR     bool
	VexP       int8
	Avx2Gather bool

	generator func(cfg *iset.Config, r *rand.Rand) []byte // for pseudo instructions
}

type InsnSet struct {
	modeInsns iset.ModeInsns
	Insns     []*Insn
}

func Register(insns []*Insn) {
	if len(insns) == 0 {
		panic("no instructions")
	}
	insnset := &InsnSet{
		Insns: append(insns, pseudo...),
	}
	for _, insn := range insnset.Insns {
		insnset.modeInsns.Add(insn)
	}
	iset.Arches[iset.ArchX86] = insnset
}

func (insnset *InsnSet) GetInsns(mode iset.Mode, typ iset.Type) []iset.Insn {
	return insnset.modeInsns[mode][typ]
}

func (insn *Insn) Info() (string, iset.Mode, bool, bool) {
	return insn.Name, insn.Mode, insn.Pseudo, insn.Priv
}

func generateArg(cfg *iset.Config, r *rand.Rand, size int) []byte {
	v := iset.GenerateInt(cfg, r, size)
	arg := make([]byte, size)
	for i := 0; i < size; i++ {
		arg[i] = byte(v)
		v >>= 8
	}
	return arg
}
