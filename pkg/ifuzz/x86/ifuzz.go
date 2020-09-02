// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:generate bash -c "go run gen/gen.go gen/all-enc-instructions.txt > generated/insns.go"

// Package ifuzz allows to generate and mutate x86 machine code.
package x86

import (
	"math/rand"
	"sync"
	. "github.com/google/syzkaller/pkg/ifuzz/common"
)

type InsnX86 struct {
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

	generator func(cfg *Config, r *rand.Rand) []byte // for pseudo instructions
}

const (
	typeExec = iota
	typePriv
	typeUser
	typeAll
	typeLast
)


type InsnSetX86 struct {
	modeInsns [ModeLast][typeLast][]Insn
	insns    []*InsnX86
	initOnce sync.Once
}

var insns InsnSetX86

func init() {
	insns.insns = insns_x86
	initInsns()
	Register("x86", InsnSet(insns))
}

func initInsns() {
	if len(insns.insns) == 0 {
		panic("no instructions")
	}
	initPseudo()
	for mode := 0; mode < ModeLast; mode++ {
		for _, insn := range insns.insns {
			if insn.Mode&(1<<uint(mode)) == 0 {
				continue
			}
			if insn.Pseudo {
				insns.modeInsns[mode][typeExec] =
					append(insns.modeInsns[mode][typeExec], Insn(insn))
			} else if insn.Priv {
				insns.modeInsns[mode][typePriv] =
					append(insns.modeInsns[mode][typePriv], Insn(insn))
				insns.modeInsns[mode][typeAll] =
					append(insns.modeInsns[mode][typeAll], Insn(insn))
			} else {
				insns.modeInsns[mode][typeUser] =
					append(insns.modeInsns[mode][typeUser], Insn(insn))
				insns.modeInsns[mode][typeAll] =
					append(insns.modeInsns[mode][typeAll], Insn(insn))
			}
		}
	}
}

func (insn InsnSetX86) Insns(mode, insntype int) []Insn {
	insns.initOnce.Do(initInsns)
	return insn.modeInsns[mode][insntype]
}

func (insn InsnSetX86) Decode(mode int, text []byte) (int, error) {
	return 0, nil
}

func (insn InsnX86) GetName() string {
	return insn.Name
}

func (insn InsnX86) GetMode() int {
	return insn.Mode
}

func (insn InsnX86) GetPriv() bool {
	return insn.Priv
}

func (insn InsnX86) GetPseudo() bool {
	return insn.Pseudo
}

func generateArg(cfg *Config, r *rand.Rand, size int) []byte {
	v := generateInt(cfg, r, size)
	arg := make([]byte, size)
	for i := 0; i < size; i++ {
		arg[i] = byte(v)
		v >>= 8
	}
	return arg
}

func (insn InsnX86) IsCompatible(cfg *Config) bool {
	if cfg.Mode < 0 || cfg.Mode >= ModeLast {
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

func generateInt(cfg *Config, r *rand.Rand, size int) uint64 {
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
		v = specialNumbers[r.Intn(len(specialNumbers))]
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

var specialNumbers = []uint64{0, 1 << 15, 1 << 16, 1 << 31, 1 << 32, 1 << 47, 1 << 47, 1 << 63}
