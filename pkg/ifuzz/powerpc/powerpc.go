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

type InsnField struct {
	Name string
	Bits []InsnBits
}

type Insn struct {
	Name   string
	Priv   bool
	Pseudo bool
	Fields []InsnField // for ra/rb/rt/si/...
	Opcode uint32
	Mask   uint32

	FieldsSuffix []InsnField
	OpcodeSuffix uint32
	MaskSuffix   uint32

	insnMap   *insnSetMap
	generator func(cfg *iset.Config, r *rand.Rand) []byte
}

type insnSetMap map[string]*Insn

type InsnSet struct {
	Insns     []*Insn
	modeInsns iset.ModeInsns
	insnMap   insnSetMap
}

const (
	prefixShift  = 32 - 6
	prefixMask   = uint32(0x3f) << prefixShift
	prefixOpcode = uint32(1) << prefixShift
)

func (insn Insn) isPrefixed() bool {
	return insn.Opcode&prefixMask == prefixOpcode
}

func (insnset *InsnSet) GetInsns(mode iset.Mode, typ iset.Type) []iset.Insn {
	return insnset.modeInsns[mode][typ]
}

func (insnset *InsnSet) Decode(mode iset.Mode, text []byte) (int, error) {
	if len(text) < 4 {
		return 0, errors.New("must be at least 4 bytes")
	}
	insn32 := binary.LittleEndian.Uint32(text)
	if insn32&prefixMask == prefixOpcode {
		insn2 := uint32(0)
		for _, ins := range insnset.Insns {
			if !ins.isPrefixed() || ins.Mask&insn32 != ins.Opcode {
				continue
			}
			if len(text) < 8 {
				return 0, errors.New("prefixed instruction must be at least 8 bytes")
			}
			insn2 = binary.LittleEndian.Uint32(text[4:])
			for _, ins := range insnset.Insns {
				if !ins.isPrefixed() {
					continue
				}
				if ins.MaskSuffix&insn2 == ins.OpcodeSuffix {
					return 8, nil
				}
			}
			break
		}
		return 0, fmt.Errorf("unrecognised prefixed instruction %08x %08x", insn32, insn2)
	}
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

func encodeBits(n uint, ff []InsnBits) uint32 {
	ret := uint32(0)
	for _, f := range ff {
		mask := uint(1<<f.Length) - 1
		field := uint32((n & mask) << (31 - (f.Start + f.Length - 1)))
		ret = ret | field
		n = n >> f.Length
	}
	return ret
}

func (insn Insn) Encode(cfg *iset.Config, r *rand.Rand) []byte {
	if insn.Pseudo {
		return insn.generator(cfg, r)
	}

	ret := make([]byte, 0)
	ret = append(ret, insn.encodeOpcode(cfg, r, insn.Opcode, insn.Mask, insn.Fields)...)
	if insn.isPrefixed() {
		ret = append(ret, insn.encodeOpcode(cfg, r, insn.OpcodeSuffix, insn.MaskSuffix, insn.FieldsSuffix)...)
	}
	return ret
}

func (insn Insn) encodeOpcode(cfg *iset.Config, r *rand.Rand, opcode, mask uint32, f []InsnField) []byte {
	ret := make([]byte, 0)
	insn32 := opcode
	if len(cfg.MemRegions) != 0 {
		// The PowerISA pdf parser could have missed some fields,
		// randomize them there.
		insn32 |= r.Uint32() & ^mask
	}
	for _, f := range f {
		field := uint(r.Intn(1 << 16))
		if f.Name == "Ap" || f.Name == "FRAp" || f.Name == "FRBp" || f.Name == "FRTp" || f.Name == "FRSp" {
			// These are pairs and have to be even numbers.
			field &^= 1
		}
		insn32 |= encodeBits(field, f.Bits)
		if len(cfg.MemRegions) != 0 && (f.Name == "RA" || f.Name == "RB" || f.Name == "RS") {
			val := iset.GenerateInt(cfg, r, 8)
			ret = append(ret, insn.insnMap.ld64(field, val)...)
		}
	}

	return append(ret, uint32toBytes(insn32)...)
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
		insn.insnMap = &insnset.insnMap
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
	return (1 << iset.ModeLong64) | (1 << iset.ModeProt32)
}

func uint32toBytes(v uint32) []byte {
	ret := make([]byte, 4)
	binary.LittleEndian.PutUint32(ret, v)

	return ret
}

func (insn *Insn) enc(v map[string]uint) []byte {
	ret := make([]byte, 0)
	ret = append(ret, insn.encOpcode(v, insn.Opcode, insn.Fields)...)
	if insn.isPrefixed() {
		ret = append(ret, insn.encOpcode(v, insn.OpcodeSuffix, insn.FieldsSuffix)...)
	}
	return ret
}

func (insn *Insn) encOpcode(v map[string]uint, opcode uint32, f []InsnField) []byte {
	insn32 := opcode
	for _, f := range insn.Fields {
		if val, ok := v[f.Name]; ok {
			insn32 |= encodeBits(val, f.Bits)
		}
	}
	return uint32toBytes(insn32)
}

func (imap insnSetMap) ld64(reg uint, v uint64) []byte {
	ret := make([]byte, 0)

	// This is a widely used macro to load immediate on ppc64
	// #define LOAD64(rn,name)
	//	addis   rn,0,name##@highest \ lis     rn,name##@highest
	//	ori     rn,rn,name##@higher
	//	rldicr  rn,rn,32,31
	//	oris    rn,rn,name##@h
	//	ori     rn,rn,name##@l
	ret = append(ret, imap["addis"].enc(map[string]uint{
		"RT": reg,
		"RA": 0, // In "addis", '0' means 0, not GPR0 .
		"SI": uint((v >> 48) & 0xffff)})...)
	ret = append(ret, imap["ori"].enc(map[string]uint{
		"RA": reg,
		"RS": reg,
		"UI": uint((v >> 32) & 0xffff)})...)
	ret = append(ret, imap["rldicr"].enc(map[string]uint{
		"RA": reg,
		"RS": reg,
		"SH": 32,
		"ME": 31})...)
	ret = append(ret, imap["oris"].enc(map[string]uint{
		"RA": reg,
		"RS": reg,
		"UI": uint((v >> 16) & 0xffff)})...)
	ret = append(ret, imap["ori"].enc(map[string]uint{
		"RA": reg,
		"RS": reg,
		"UI": uint(v & 0xffff)})...)

	return ret
}

func (imap insnSetMap) ld32(reg uint, v uint32) []byte {
	ret := make([]byte, 0)

	ret = append(ret, imap["addis"].enc(map[string]uint{
		"RT": reg,
		"RA": 0, // In "addis", '0' means 0, not GPR0
		"SI": uint((v >> 16) & 0xffff)})...)
	ret = append(ret, imap["ori"].enc(map[string]uint{
		"RA": reg,
		"RS": reg,
		"UI": uint(v & 0xffff)})...)

	return ret
}

func (imap insnSetMap) ldgpr32(regaddr, regval uint, addr uint64, v uint32) []byte {
	ret := make([]byte, 0)

	ret = append(ret, imap.ld64(regaddr, addr)...)
	ret = append(ret, imap.ld32(regval, v)...)
	ret = append(ret, imap["stw"].enc(map[string]uint{
		"RA": regaddr,
		"RS": regval})...)

	return ret
}

func (imap insnSetMap) sc(lev uint) []byte {
	return imap["sc"].enc(map[string]uint{"LEV": lev})
}
