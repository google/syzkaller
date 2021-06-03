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
	"math/rand"

	"github.com/google/syzkaller/pkg/ifuzz/iset"
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

	generator func(cfg *iset.Config, r *rand.Rand) []byte
}

type insnSetMap map[string]*Insn

type InsnSet struct {
	Insns     []*Insn
	modeInsns iset.ModeInsns
	insnMap   insnSetMap
}

func (insnset *InsnSet) GetInsns(mode iset.Mode, typ iset.Type) []iset.Insn {
	return insnset.modeInsns[mode][typ]
}

func (insnset *InsnSet) Decode(mode iset.Mode, text []byte) (int, error) {
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

func (insnset *InsnSet) DecodeExt(mode iset.Mode, text []byte) (int, error) {
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

func (insn Insn) Encode(cfg *iset.Config, r *rand.Rand) []byte {
	if insn.Pseudo {
		return insn.generator(cfg, r)
	}

	return insn.EncodeParam(nil, r)
}

func Register(insns []*Insn) {
	if len(insns) == 0 {
		panic("no instructions")
	}
	insnset := &InsnSet{
		Insns:   insns,
		insnMap: make(map[string]*Insn),
	}
	for _, insn := range insnset.Insns {
		insnset.insnMap[insn.Name] = insn
	}
	insnset.initPseudo()
	for _, insn := range insnset.Insns {
		insnset.modeInsns.Add(insn)
	}
	iset.Arches[iset.ArchPowerPC] = insnset
}

func (insn *Insn) Info() (string, iset.Mode, bool, bool) {
	return insn.Name, insn.mode(), insn.Pseudo, insn.Priv
}

func (insn Insn) mode() iset.Mode {
	if insn.M64 {
		return (1 << iset.ModeLong64)
	}
	return (1 << iset.ModeLong64) | (1 << iset.ModeProt32)
}
