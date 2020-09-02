// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:generate bash -c "go run gen/gen.go gen/all-enc-instructions.txt > generated/insns.go"

// Package x86 allows to generate and mutate x86 machine code.
package x86

import (
	"github.com/google/syzkaller/pkg/ifuzz"
	"github.com/google/syzkaller/pkg/ifuzz/ifuzzimpl"
	"math/rand"
)

type Insn struct {
	Name      string
	Extension string

	Mode   int  // bitmask of compatible modes
	Priv   bool // CPL=0
	Pseudo bool // pseudo instructions can consist of several real instructions

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

	generator func(cfg *ifuzz.Config, r *rand.Rand) []byte // for pseudo instructions
}

const (
	typeExec = iota
	typePriv
	typeUser
	typeAll
	typeLast
)

type InsnSetX86 struct {
	modeInsns [ifuzz.ModeLast][typeLast][]ifuzz.Insn
	Insns     []*Insn
}

func Register(insns []*Insn) {
	var insnset InsnSetX86

	insnset.Insns = insns
	if len(insnset.Insns) == 0 {
		panic("no instructions")
	}
	insnset.initPseudo()
	for mode := 0; mode < ifuzz.ModeLast; mode++ {
		for _, insn := range insnset.Insns {
			if insn.Mode&(1<<uint(mode)) == 0 {
				continue
			}
			if insn.Pseudo {
				insnset.modeInsns[mode][typeExec] =
					append(insnset.modeInsns[mode][typeExec], ifuzz.Insn(insn))
			} else if insn.Priv {
				insnset.modeInsns[mode][typePriv] =
					append(insnset.modeInsns[mode][typePriv], ifuzz.Insn(insn))
				insnset.modeInsns[mode][typeAll] =
					append(insnset.modeInsns[mode][typeAll], ifuzz.Insn(insn))
			} else {
				insnset.modeInsns[mode][typeUser] =
					append(insnset.modeInsns[mode][typeUser], ifuzz.Insn(insn))
				insnset.modeInsns[mode][typeAll] =
					append(insnset.modeInsns[mode][typeAll], ifuzz.Insn(insn))
			}
		}
	}

	ifuzzimpl.Register(ifuzz.ArchX86, ifuzz.InsnSet(&insnset))
}

func (insnset *InsnSetX86) GetInsns(mode, insntype int) []ifuzz.Insn {
	return insnset.modeInsns[mode][insntype]
}

func (insn Insn) GetName() string {
	return insn.Name
}

func (insn Insn) GetMode() int {
	return insn.Mode
}

func (insn Insn) GetPriv() bool {
	return insn.Priv
}

func (insn Insn) GetPseudo() bool {
	return insn.Pseudo
}

func generateArg(cfg *ifuzz.Config, r *rand.Rand, size int) []byte {
	v := generateInt(cfg, r, size)
	arg := make([]byte, size)
	for i := 0; i < size; i++ {
		arg[i] = byte(v)
		v >>= 8
	}
	return arg
}

func (insn Insn) IsCompatible(cfg *ifuzz.Config) bool {
	if cfg.Mode < 0 || cfg.Mode >= ifuzz.ModeLast {
		panic("bad mode")
	}
	if insn.Priv && !cfg.Priv {
		return false
	}
	if insn.Pseudo && !cfg.Exec {
		return false
	}
	if insn.Mode&(1<<uint(cfg.Mode)) == 0 {
		return false
	}
	return true
}

func generateInt(cfg *ifuzz.Config, r *rand.Rand, size int) uint64 {
	if size != 1 && size != 2 && size != 4 && size != 8 {
		panic("bad arg size")
	}
	var v uint64
	switch x := r.Intn(60); {
	case x < 10:
		v = uint64(r.Intn(1 << 4))
	case x < 20:
		v = uint64(r.Intn(1 << 16))
	case x < 25:
		v = uint64(r.Int63()) % (1 << 32)
	case x < 30:
		v = uint64(r.Int63())
	case x < 40:
		v = ifuzz.SpecialNumbers[r.Intn(len(ifuzz.SpecialNumbers))]
		if r.Intn(5) == 0 {
			v += uint64(r.Intn(33)) - 16
		}
	case x < 50 && len(cfg.MemRegions) != 0:
		mem := cfg.MemRegions[r.Intn(len(cfg.MemRegions))]
		switch x := r.Intn(100); {
		case x < 25:
			v = mem.Start
		case x < 50:
			v = mem.Start + mem.Size
		case x < 75:
			v = mem.Start + mem.Size/2
		default:
			v = mem.Start + uint64(r.Int63())%mem.Size
		}
		if r.Intn(10) == 0 {
			v += uint64(r.Intn(33)) - 16
		}
	default:
		v = uint64(r.Intn(1 << 8))
	}
	if r.Intn(50) == 0 {
		v = uint64(-int64(v))
	}
	if r.Intn(50) == 0 && size != 1 {
		v &^= 1<<12 - 1
	}
	return v
}
