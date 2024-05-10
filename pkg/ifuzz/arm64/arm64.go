// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:generate bash -c "go run gen/gen.go gen/json/arm64.json | gofmt > generated/insns.go"

// Package arm64 allows to generate and mutate arm64 machine code.
package arm64

import (
	"encoding/binary"
	"fmt"
	"math/rand"

	"github.com/google/syzkaller/pkg/ifuzz/iset"
)

type InsnField struct {
	Name   string
	Start  uint // Little endian bit order.
	Length uint
}

type Insn struct {
	Name       string
	OpcodeMask uint32
	Opcode     uint32
	Fields     []InsnField
	AsUInt32   uint32
	Operands   []uint32
	Pseudo     bool
	Priv       bool
	Generator  func(cfg *iset.Config, r *rand.Rand) []byte // for pseudo instructions
}

type InsnSet struct {
	modeInsns iset.ModeInsns
	Insns     []*Insn
}

func Register(insns []*Insn) {
	if len(insns) == 0 {
		panic("no instructions")
	}
	insnset := &InsnSet{
		Insns: append(insns, pseudo...),
	}
	for _, insn := range insnset.Insns {
		insnset.modeInsns.Add(insn)
	}
	iset.Arches[iset.ArchArm64] = insnset
	templates = insns
}

func (insnset *InsnSet) GetInsns(mode iset.Mode, typ iset.Type) []iset.Insn {
	return insnset.modeInsns[mode][typ]
}

func (insn *Insn) Info() (string, iset.Mode, bool, bool) {
	return insn.Name, 1 << iset.ModeLong64, insn.Pseudo, insn.Priv
}

func (insn *Insn) Encode(cfg *iset.Config, r *rand.Rand) []byte {
	if insn.Pseudo {
		return insn.Generator(cfg, r)
	}
	ret := make([]byte, 4)
	binary.LittleEndian.PutUint32(ret, insn.AsUInt32)
	return ret
}

func (insnset *InsnSet) Decode(mode iset.Mode, text []byte) (int, error) {
	if len(text) < 4 {
		return 0, fmt.Errorf("must be at least 4 bytes")
	}
	opcode := binary.LittleEndian.Uint32(text[:4])
	_, err := ParseInsn(opcode)
	if err != nil {
		return 0, fmt.Errorf("failed to decode %x", opcode)
	}
	return 4, nil
}

func (insnset *InsnSet) DecodeExt(mode iset.Mode, text []byte) (int, error) {
	return 0, fmt.Errorf("no external decoder")
}

var templates []*Insn

func (insn *Insn) initFromValue(val uint32) {
	operands := []uint32{}
	for _, field := range insn.Fields {
		extracted := extractBits(val, field.Start, field.Length)
		operands = append(operands, extracted)
	}
	insn.Operands = operands
	insn.AsUInt32 = val
}

func (insn *Insn) matchesValue(val uint32) bool {
	opcode := val & insn.OpcodeMask
	return opcode == insn.Opcode
}

func ParseInsn(val uint32) (Insn, error) {
	for _, tmpl := range templates {
		if tmpl.matchesValue(val) {
			newInsn := *tmpl
			newInsn.initFromValue(val)
			return newInsn, nil
		}
	}
	unknown := Insn{
		Name: "unknown",
	}
	return unknown, fmt.Errorf("unrecognized instruction: %08x", val)
}
