// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ifuzz

import (
	"math/rand"

	"github.com/google/syzkaller/pkg/ifuzz/iset"
	_ "github.com/google/syzkaller/pkg/ifuzz/powerpc/generated" // pull in generated instruction descriptions
	_ "github.com/google/syzkaller/pkg/ifuzz/x86/generated"     // pull in generated instruction descriptions
)

type (
	Config    = iset.Config
	MemRegion = iset.MemRegion
	Mode      = iset.Mode
)

const (
	ArchX86     = iset.ArchX86
	ArchPowerPC = iset.ArchPowerPC
	ModeLong64  = iset.ModeLong64
	ModeProt32  = iset.ModeProt32
	ModeProt16  = iset.ModeProt16
	ModeReal16  = iset.ModeReal16
)

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

func randInsn(cfg *Config, r *rand.Rand) iset.Insn {
	insnset := iset.Arches[cfg.Arch]
	var insns []iset.Insn
	if cfg.Priv && cfg.Exec {
		insns = insnset.GetInsns(cfg.Mode, iset.Type(r.Intn(3)))
	} else if cfg.Priv {
		insns = insnset.GetInsns(cfg.Mode, iset.Type(r.Intn(2)))
	} else {
		insns = insnset.GetInsns(cfg.Mode, iset.TypeUser)
	}
	return insns[r.Intn(len(insns))]
}

func split(cfg *Config, text []byte) [][]byte {
	insnset := iset.Arches[cfg.Arch]
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
