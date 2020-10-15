// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:generate bash -c "go run gen/gen.go gen/all-enc-instructions.txt > generated/insns.go"

// Package ifuzz allows to generate and mutate x86 machine code.
package ifuzz

import (
	"math/rand"
	. "github.com/google/syzkaller/pkg/ifuzz/common"
	_ "github.com/google/syzkaller/pkg/ifuzz/x86"
	_ "github.com/google/syzkaller/pkg/ifuzz/ppc64"
)

// ModeInsns returns list of all instructions for the given mode.
func ModeInsns(cfg *Config) []Insn {
	insnset := Types[cfg.Arch]
	if cfg.Mode < 0 || cfg.Mode >= ModeLast {
		panic("bad mode")
	}
	var insns []Insn
	insns = append(insns, insnset.Insns(cfg.Mode, TypeUser)...)
	if cfg.Priv {
		insns = append(insns, insnset.Insns(cfg.Mode, TypePriv)...)
		if cfg.Exec {
			insns = append(insns, insnset.Insns(cfg.Mode, TypeExec)...)
		}
	}
	return insns
}

func Generate(cfg *Config, r *rand.Rand) []byte {
	var text []byte
	for i := 0; i < cfg.Len; i++ {
		insn := randInsn(cfg, r)
		text = append(text, insn.Encode(cfg, r)...)
	}
	return text
}

func Mutate(cfg *Config, r *rand.Rand, text []byte) []byte {
	insns := split(cfg, text)
	retry := false
	for stop := false; !stop || retry || len(insns) == 0; stop = r.Intn(2) == 0 {
		retry = false
		switch x := r.Intn(100); {
		case x < 10 && len(insns) != 0:
			// Delete instruction.
			i := r.Intn(len(insns))
			copy(insns[i:], insns[i+1:])
			insns = insns[:len(insns)-1]
		case x < 40 && len(insns) != 0:
			// Replace instruction with another.
			insn := randInsn(cfg, r)
			text1 := insn.Encode(cfg, r)
			i := r.Intn(len(insns))
			insns[i] = text1
		case x < 70 && len(insns) != 0:
			// Mutate instruction.
			i := r.Intn(len(insns))
			text1 := insns[i]
			for stop := false; !stop || len(text1) == 0; stop = r.Intn(2) == 0 {
				switch x := r.Intn(100); {
				case x < 5 && len(text1) != 0:
					// Delete byte.
					pos := r.Intn(len(text1))
					copy(text1[pos:], text1[pos+1:])
					text1 = text1[:len(text1)-1]
				case x < 40 && len(text1) != 0:
					// Replace a byte.
					pos := r.Intn(len(text1))
					text1[pos] = byte(r.Intn(256))
				case x < 70 && len(text1) != 0:
					// Flip a bit.
					pos := r.Intn(len(text1))
					text1[pos] ^= 1 << byte(r.Intn(8))
				default:
					// Insert a byte.
					pos := r.Intn(len(text1) + 1)
					text1 = append(text1, 0)
					copy(text1[pos+1:], text1[pos:])
					text1[pos] = byte(r.Intn(256))
				}
			}
			insns[i] = text1
		case len(insns) < cfg.Len:
			// Insert a new instruction.
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

func randInsn(cfg *Config, r *rand.Rand) Insn {
	insnset := Types[cfg.Arch]
	var insns []Insn
	if cfg.Priv && cfg.Exec {
		insns = insnset.Insns(cfg.Mode, r.Intn(3))
	} else if cfg.Priv {
		insns = insnset.Insns(cfg.Mode, r.Intn(2))
	} else {
		insns = insnset.Insns(cfg.Mode, TypeUser)
	}
	return insns[r.Intn(len(insns))]
}

func split(cfg *Config, text []byte) [][]byte {
	insnset := Types[cfg.Arch]
	text = append([]byte{}, text...)
	var insns [][]byte
	var bad []byte
	for len(text) != 0 {
		n, err := insnset.Decode(cfg.Mode, text)
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
