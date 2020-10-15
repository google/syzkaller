// Copyright 2020 IBM Corp. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package ifuzz allows to generate and mutate PPC64 PowerISA 3.0B machine code.

// The ISA for POWER9 (the latest available at the moment) is at:
// https://openpowerfoundation.org/?resource_lib=power-isa-version-3-0
//
// A script on top of pdftotext was used to produce insns.go:
// ./powerisa30_to_syz /home/aik/Documents/ppc/power9/PowerISA_public.v3.0B.pdf > 1.go

package ppc64

import (
	"math/rand"
	"sync"
	"fmt"
	"errors"
	"encoding/binary"
	. "github.com/google/syzkaller/pkg/ifuzz/common"
)

type InsnBits struct {
	Start uint // Big endian bit order
	Length uint
}

type InsnPowerPC struct {
	Name string
	M64    bool // true if the instruction is 64bit _only_
	Priv   bool
	Pseudo bool
	Fields map[string]InsnBits // for ra/rb/rt/si/...
	Opcode uint32
	Mask   uint32

	generator func(cfg *Config, r *rand.Rand) []byte
}

type InsnSetPowerPC struct {
	insns []*InsnPowerPC
	modeInsns [ModeLast][TypeLast][]Insn
	insnMap map[string]*InsnPowerPC
	initOnce sync.Once
}

var insns InsnSetPowerPC

func (insn InsnSetPowerPC) Insns(mode, insntype int) []Insn {
	insns.initOnce.Do(initInsns)
	return insn.modeInsns[mode][insntype]
}

func (insn InsnSetPowerPC) Decode(mode int, text []byte) (int, error) {
	if len(text) < 4 {
		return 0, errors.New("Must be at least 4 bytes")
	}
	insn32 := binary.LittleEndian.Uint32(text)
	for _, ins := range insns.insns {
		if ins.Mask & insn32 == ins.Opcode {
			return 4, nil
		}
	}
	return 0, errors.New(fmt.Sprintf("Unrecognised instruction %08x", insn32))
}

func encode_bit_field(n uint, f InsnBits) uint32 {
	mask := uint(1 << f.Length) - 1
	return uint32((n & mask) << (31 - (f.Start + f.Length - 1)))
}

func (insn *InsnPowerPC) EncodeParam(v map[string]uint, r *rand.Rand) []byte {
	insn32 := insn.Opcode
	for reg, bits := range insn.Fields {
		if val, ok := v[reg]; ok {
			insn32 |= encode_bit_field(val, bits)
		} else if r != nil {
			insn32 |= encode_bit_field(uint(r.Intn(1<<16)), bits)
		}
	}

	ret := make([]byte, 4)
	binary.LittleEndian.PutUint32(ret, insn32)
	return ret
}

func (insn InsnPowerPC) Encode(cfg *Config, r *rand.Rand) []byte {
	if insn.Pseudo {
		return insn.generator(cfg, r)
	}

	return insn.EncodeParam(nil, r)
}

func init() {
	insns.insns = insns_ppc
	initInsns()
	Register("ppc64", InsnSet(insns))
}

func initInsns() {
	if len(insns.insns) == 0 {
		panic("no instructions")
	}
	insns.insnMap = make(map[string]*InsnPowerPC)
	for _, insn := range insns.insns {
		insns.insnMap[insn.GetName()] = insn
	}
	initPseudo()
	for mode := 0; mode < ModeLast; mode++ {
		for _, insn := range insns.insns {
			if insn.GetMode() & (1<<uint(mode)) == 0 {
				continue
			}
			if insn.GetPseudo() {
				insns.modeInsns[mode][TypeExec] =
					append(insns.modeInsns[mode][TypeExec], Insn(insn))
			} else if insn.GetPriv() {
				insns.modeInsns[mode][TypePriv] =
					append(insns.modeInsns[mode][TypePriv], Insn(insn))
				insns.modeInsns[mode][TypeAll] =
					append(insns.modeInsns[mode][TypeAll], Insn(insn))

			} else {
				insns.modeInsns[mode][TypeUser] =
					append(insns.modeInsns[mode][TypeUser], Insn(insn))
				insns.modeInsns[mode][TypeAll] =
					append(insns.modeInsns[mode][TypeAll], Insn(insn))
			}
		}
	}
}

func (insn InsnPowerPC) GetName() string {
	return insn.Name
}

func (insn InsnPowerPC) GetMode() int {
	if insn.M64 {
		return (1 << ModeLong64)
	}
	return (1 << ModeLong64) | (1 << ModeProt32)
}

func (insn InsnPowerPC) GetPriv() bool {
	return insn.Priv
}

func (insn InsnPowerPC) GetPseudo() bool {
	return insn.Pseudo
}

func (insn InsnPowerPC) IsCompatible(cfg *Config) bool {
	if cfg.Mode < 0 || cfg.Mode >= ModeLast {
		panic("bad mode")
	}
	if insn.Priv && !cfg.Priv {
		return false
	}
	if insn.Pseudo && !cfg.Exec {
		return false
	}
	if insn.M64 && ((1<<uint(cfg.Mode)) != ModeLong64) {
		return false
	}
	return true
}
