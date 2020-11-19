// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package ifuzz allows to generate and mutate PPC64 PowerISA 3.0B machine code.

// The ISA for POWER9 (the latest available at the moment) is at:
// https://openpowerfoundation.org/?resource_lib=power-isa-version-3-0
//
// A script on top of pdftotext was used to produce insns.go:
// ./powerisa30_to_syz /home/aik/Documents/ppc/power9/PowerISA_public.v3.0B.pdf > 1.go
// .

package powerpc

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/google/syzkaller/pkg/ifuzz"
	"github.com/google/syzkaller/pkg/ifuzz/ifuzzimpl"
	"math/rand"
)

type InsnBits struct {
	Start  uint // Big endian bit order.
	Length uint
}

type Insn struct {
	Name   string
	M64    bool // true if the instruction is 64bit _only_.
	Priv   bool
	Pseudo bool
	Fields map[string]InsnBits // for ra/rb/rt/si/...
	Opcode uint32
	Mask   uint32

	generator func(cfg *ifuzz.Config, r *rand.Rand) []byte
}

type InsnSetPowerPC struct {
	Insns     []*Insn
	modeInsns [ifuzz.ModeLast][ifuzz.TypeLast][]ifuzz.Insn
	insnMap   map[string]*Insn
}

func (insnset *InsnSetPowerPC) GetInsns(mode, insntype int) []ifuzz.Insn {
	return insnset.modeInsns[mode][insntype]
}

func (insnset *InsnSetPowerPC) Decode(mode int, text []byte) (int, error) {
	if len(text) < 4 {
		return 0, errors.New("must be at least 4 bytes")
	}
	insn32 := binary.LittleEndian.Uint32(text)
	for _, ins := range insnset.Insns {
		if ins.Mask&insn32 == ins.Opcode {
			return 4, nil
		}
	}
	return 0, fmt.Errorf("unrecognised instruction %08x", insn32)
}

func (insnset *InsnSetPowerPC) DecodeExt(mode int, text []byte) (int, error) {
	return 0, fmt.Errorf("no external decoder")
}

func encodeBits(n uint, f InsnBits) uint32 {
	mask := uint(1<<f.Length) - 1
	return uint32((n & mask) << (31 - (f.Start + f.Length - 1)))
}

func (insn *Insn) EncodeParam(v map[string]uint, r *rand.Rand) []byte {
	insn32 := insn.Opcode
	for reg, bits := range insn.Fields {
		if val, ok := v[reg]; ok {
			insn32 |= encodeBits(val, bits)
		} else if r != nil {
			insn32 |= encodeBits(uint(r.Intn(1<<16)), bits)
		}
	}

	ret := make([]byte, 4)
	binary.LittleEndian.PutUint32(ret, insn32)
	return ret
}

func (insn Insn) Encode(cfg *ifuzz.Config, r *rand.Rand) []byte {
	if insn.Pseudo {
		return insn.generator(cfg, r)
	}

	return insn.EncodeParam(nil, r)
}

func Register(insns []*Insn) {
	var insnset InsnSetPowerPC

	insnset.Insns = insns
	if len(insnset.Insns) == 0 {
		panic("no instructions")
	}
	insnset.insnMap = make(map[string]*Insn)
	for _, insn := range insnset.Insns {
		insnset.insnMap[insn.GetName()] = insn
	}
	insnset.initPseudo()
	for mode := 0; mode < ifuzz.ModeLast; mode++ {
		for _, insn := range insnset.Insns {
			if insn.GetMode()&(1<<uint(mode)) == 0 {
				continue
			}
			if insn.GetPseudo() {
				insnset.modeInsns[mode][ifuzz.TypeExec] =
					append(insnset.modeInsns[mode][ifuzz.TypeExec], ifuzz.Insn(insn))
			} else if insn.GetPriv() {
				insnset.modeInsns[mode][ifuzz.TypePriv] =
					append(insnset.modeInsns[mode][ifuzz.TypePriv], ifuzz.Insn(insn))
				insnset.modeInsns[mode][ifuzz.TypeAll] =
					append(insnset.modeInsns[mode][ifuzz.TypeAll], ifuzz.Insn(insn))
			} else {
				insnset.modeInsns[mode][ifuzz.TypeUser] =
					append(insnset.modeInsns[mode][ifuzz.TypeUser], ifuzz.Insn(insn))
				insnset.modeInsns[mode][ifuzz.TypeAll] =
					append(insnset.modeInsns[mode][ifuzz.TypeAll], ifuzz.Insn(insn))
			}
		}
	}
	ifuzzimpl.Register(ifuzz.ArchPowerPC, ifuzz.InsnSet(&insnset))
}

func (insn Insn) GetName() string {
	return insn.Name
}

func (insn Insn) GetMode() int {
	if insn.M64 {
		return (1 << ifuzz.ModeLong64)
	}
	return (1 << ifuzz.ModeLong64) | (1 << ifuzz.ModeProt32)
}

func (insn Insn) GetPriv() bool {
	return insn.Priv
}

func (insn Insn) GetPseudo() bool {
	return insn.Pseudo
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
	if insn.M64 && ((1 << uint(cfg.Mode)) != ifuzz.ModeLong64) {
		return false
	}
	return true
}
