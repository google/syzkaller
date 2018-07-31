// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:generate bash -c "go run gen/gen.go gen/all-enc-instructions.txt > generated/insns.go"

// Package ifuzz allows to generate and mutate x86 machine code.
package ifuzz

import (
	"math/rand"
	"sync"
)

const (
	ModeLong64 = iota
	ModeProt32
	ModeProt16
	ModeReal16
	ModeLast
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

	generator func(cfg *Config, r *rand.Rand) []byte // for pseudo instructions
}

type Config struct {
	Len        int         // number of instructions to generate
	Mode       int         // one of ModeXXX
	Priv       bool        // generate CPL=0 instructions
	Exec       bool        // generate instructions sequences interesting for execution
	MemRegions []MemRegion // generated instructions will reference these regions
}

type MemRegion struct {
	Start uint64
	Size  uint64
}

const (
	typeExec = iota
	typePriv
	typeUser
	typeAll
	typeLast
)

var modeInsns [ModeLast][typeLast][]*Insn

var (
	Insns    []*Insn
	initOnce sync.Once
)

func initInsns() {
	if len(Insns) == 0 {
		panic("no instructions")
	}
	initPseudo()
	for mode := 0; mode < ModeLast; mode++ {
		for _, insn := range Insns {
			if insn.Mode&(1<<uint(mode)) == 0 {
				continue
			}
			if insn.Pseudo {
				modeInsns[mode][typeExec] = append(modeInsns[mode][typeExec], insn)
			} else if insn.Priv {
				modeInsns[mode][typePriv] = append(modeInsns[mode][typePriv], insn)
				modeInsns[mode][typeAll] = append(modeInsns[mode][typeAll], insn)
			} else {
				modeInsns[mode][typeUser] = append(modeInsns[mode][typeUser], insn)
				modeInsns[mode][typeAll] = append(modeInsns[mode][typeAll], insn)
			}
		}
	}
}

// ModeInsns returns list of all instructions for the given mode.
func ModeInsns(cfg *Config) []*Insn {
	initOnce.Do(initInsns)
	if cfg.Mode < 0 || cfg.Mode >= ModeLast {
		panic("bad mode")
	}
	var insns []*Insn
	insns = append(insns, modeInsns[cfg.Mode][typeUser]...)
	if cfg.Priv {
		insns = append(insns, modeInsns[cfg.Mode][typePriv]...)
		if cfg.Exec {
			insns = append(insns, modeInsns[cfg.Mode][typeExec]...)
		}
	}
	return insns
}

func Generate(cfg *Config, r *rand.Rand) []byte {
	initOnce.Do(initInsns)
	var text []byte
	for i := 0; i < cfg.Len; i++ {
		insn := randInsn(cfg, r)
		text = append(text, insn.Encode(cfg, r)...)
	}
	return text
}

func Mutate(cfg *Config, r *rand.Rand, text []byte) []byte {
	initOnce.Do(initInsns)
	insns := split(cfg, text)
	retry := false
	for stop := false; !stop || retry || len(insns) == 0; stop = r.Intn(2) == 0 {
		retry = false
		switch x := r.Intn(100); {
		case x < 10 && len(insns) != 0:
			// delete instruction
			i := r.Intn(len(insns))
			copy(insns[i:], insns[i+1:])
			insns = insns[:len(insns)-1]
		case x < 40 && len(insns) != 0:
			// replace instruction with another
			insn := randInsn(cfg, r)
			text1 := insn.Encode(cfg, r)
			i := r.Intn(len(insns))
			insns[i] = text1
		case x < 70 && len(insns) != 0:
			// mutate instruction
			i := r.Intn(len(insns))
			text1 := insns[i]
			for stop := false; !stop || len(text1) == 0; stop = r.Intn(2) == 0 {
				switch x := r.Intn(100); {
				case x < 5 && len(text1) != 0:
					// delete byte
					pos := r.Intn(len(text1))
					copy(text1[pos:], text1[pos+1:])
					text1 = text1[:len(text1)-1]
				case x < 40 && len(text1) != 0:
					// replace a byte
					pos := r.Intn(len(text1))
					text1[pos] = byte(r.Intn(256))
				case x < 70 && len(text1) != 0:
					// flip a bit
					pos := r.Intn(len(text1))
					text1[pos] ^= 1 << byte(r.Intn(8))
				default:
					// insert a byte
					pos := r.Intn(len(text1) + 1)
					text1 = append(text1, 0)
					copy(text1[pos+1:], text1[pos:])
					text1[pos] = byte(r.Intn(256))
				}
			}
			insns[i] = text1
		case len(insns) < cfg.Len:
			// insert a new instruction
			insn := randInsn(cfg, r)
			text1 := insn.Encode(cfg, r)
			i := r.Intn(len(insns) + 1)
			insns = append(insns, nil)
			copy(insns[i+1:], insns[i:])
			insns[i] = text1
		default:
			retry = true
		}
	}
	text = nil
	for _, insn := range insns {
		text = append(text, insn...)
	}
	return text
}

func randInsn(cfg *Config, r *rand.Rand) *Insn {
	var insns []*Insn
	if cfg.Priv && cfg.Exec {
		insns = modeInsns[cfg.Mode][r.Intn(3)]
	} else if cfg.Priv {
		insns = modeInsns[cfg.Mode][r.Intn(2)]
	} else {
		insns = modeInsns[cfg.Mode][typeUser]
	}
	return insns[r.Intn(len(insns))]
}

func split(cfg *Config, text []byte) [][]byte {
	text = append([]byte{}, text...)
	var insns [][]byte
	var bad []byte
	for len(text) != 0 {
		n, err := Decode(cfg.Mode, text)
		if err != nil || n == 0 {
			bad = append(bad, text[0])
			text = text[1:]
			continue
		}
		if bad != nil {
			insns = append(insns, bad)
			bad = nil
		}
		insns = append(insns, text[:n])
		text = text[n:]
	}
	if bad != nil {
		insns = append(insns, bad)
	}
	return insns
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

func (insn *Insn) isCompatible(cfg *Config) bool {
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
