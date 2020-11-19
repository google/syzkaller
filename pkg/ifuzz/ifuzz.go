// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ifuzz

import (
	"math/rand"
)

const (
	ModeLong64 = iota
	ModeProt32
	ModeProt16
	ModeReal16
	ModeLast
)

type Config struct {
	Arch       string
	Len        int         // number of instructions to generate
	Mode       int         // one of ModeXXX
	Priv       bool        // generate CPL=0 instructions (x86), HV/!PR mode (PPC)
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

type Insn interface {
	GetName() string
	GetMode() int
	GetPseudo() bool
	GetPriv() bool
	IsCompatible(cfg *Config) bool
	Encode(cfg *Config, r *rand.Rand) []byte
}

type InsnSet interface {
	GetInsns(mode, insntype int) []Insn
	Decode(mode int, text []byte) (int, error)
	DecodeExt(mode int, text []byte) (int, error) // XED, to keep ifuzz_test happy
}

const (
	ArchX86     = "x86"
	ArchPowerPC = "powerpc"
)

var SpecialNumbers = [...]uint64{0, 1 << 15, 1 << 16, 1 << 31, 1 << 32, 1 << 47, 1 << 47, 1 << 63}
