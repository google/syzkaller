// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package iset ("instruction set") provides base and helper types for ifuzz arch implementations.
package iset

import (
	"math/rand"
)

const (
	ArchX86     = "x86"
	ArchPowerPC = "powerpc"
)

var Arches = make(map[string]InsnSet)

type (
	Mode uint
	Type uint
)

type Insn interface {
	Info() (name string, mode Mode, pseudo, priv bool)
	Encode(cfg *Config, r *rand.Rand) []byte
}

type InsnSet interface {
	GetInsns(mode Mode, typ Type) []Insn
	Decode(mode Mode, text []byte) (int, error)
	DecodeExt(mode Mode, text []byte) (int, error) // XED, to keep ifuzz_test happy
}

type Config struct {
	Arch       string
	Len        int         // number of instructions to generate
	Mode       Mode        // one of ModeXXX
	Priv       bool        // generate CPL=0 instructions (x86), HV/!PR mode (PPC)
	Exec       bool        // generate instructions sequences interesting for execution
	MemRegions []MemRegion // generated instructions will reference these regions
}

type MemRegion struct {
	Start uint64
	Size  uint64
}

const (
	ModeLong64 Mode = iota
	ModeProt32
	ModeProt16
	ModeReal16
	ModeLast
)

const (
	TypeExec Type = iota
	TypePriv
	TypeUser
	TypeAll
	TypeLast
)

var SpecialNumbers = [...]uint64{0, 1 << 15, 1 << 16, 1 << 31, 1 << 32, 1 << 47, 1 << 47, 1 << 63}

type ModeInsns [ModeLast][TypeLast][]Insn

func (modeInsns *ModeInsns) Add(insn Insn) {
	_, mode, pseudo, priv := insn.Info()
	for m := Mode(0); m < ModeLast; m++ {
		if mode&(1<<uint(m)) == 0 {
			continue
		}
		set := &modeInsns[m]
		if pseudo {
			set[TypeExec] = append(set[TypeExec], insn)
		} else if priv {
			set[TypePriv] = append(set[TypePriv], insn)
			set[TypeAll] = append(set[TypeAll], insn)
		} else {
			set[TypeUser] = append(set[TypeUser], insn)
			set[TypeAll] = append(set[TypeAll], insn)
		}
	}
}

func (cfg *Config) IsCompatible(insn Insn) bool {
	_, mode, pseudo, priv := insn.Info()
	if cfg.Mode >= ModeLast {
		panic("bad mode")
	}
	if priv && !cfg.Priv {
		return false
	}
	if pseudo && !cfg.Exec {
		return false
	}
	if mode&(1<<uint(cfg.Mode)) == 0 {
		return false
	}
	return true
}
