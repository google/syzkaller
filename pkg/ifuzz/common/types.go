// Copyright 2020 IBM Corp. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ifuzz_types

import (
	"math/rand"
)

type TextKind int

const (
	TextTarget TextKind = iota
	TextX86Real
	TextX86bit16
	TextX86bit32
	TextX86bit64
	TextArm64
	TextPpc64
)

const (
	ModeLong64 = iota
	ModeProt32
	ModeProt16
	ModeReal16
	ModeLast
)

type Insn interface {
	GetName() string
	GetMode() int
	GetPseudo() bool
	GetPriv() bool
	IsCompatible(cfg *Config) bool
	Encode(cfg *Config, r *rand.Rand) []byte
}

type Config struct {
	Arch	   string
	Len        int         // number of instructions to generate
	Mode       int         // one of ModeXXX
	Priv       bool        // generate CPL=0 instructions (was on x86, no idea for PPC)
	Exec       bool        // generate instructions sequences interesting for execution
	MemRegions []MemRegion // generated instructions will reference these regions
}

type MemRegion struct {
	Start uint64
	Size  uint64
}

const (
	TypeExec = iota
	TypePriv
	TypeUser
	TypeAll
	TypeLast
)

type InsnSet interface {
	Insns(mode, insntype int) []Insn
	Decode(mode int, text []byte) (int, error)
}

func Register(arch string, insns InsnSet) {
	Types[arch] = insns
}

var (
	Types = make(map[string]InsnSet)
)
