// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package powerpc

import (
	"math/rand"

	"github.com/google/syzkaller/pkg/ifuzz/iset"
)

// nolint:dupl
func (insnset *InsnSet) initPseudo() {
	insnset.Insns = append(insnset.Insns, &Insn{
		Name:   "PSEUDO_hypercall",
		Priv:   true,
		Pseudo: true,
		generator: func(cfg *iset.Config, r *rand.Rand) []byte {
			gen := makeGen(insnset, cfg, r)
			gen.sc(1)
			return gen.text
		},
	})
	insnset.Insns = append(insnset.Insns, &Insn{
		Name:   "PSEUDO_syscall",
		Priv:   true,
		Pseudo: true,
		generator: func(cfg *iset.Config, r *rand.Rand) []byte {
			gen := makeGen(insnset, cfg, r)
			gen.sc(0)
			return gen.text
		},
	})
	insnset.Insns = append(insnset.Insns, &Insn{
		Name:   "PSEUDO_ultracall",
		Priv:   true,
		Pseudo: true,
		generator: func(cfg *iset.Config, r *rand.Rand) []byte {
			gen := makeGen(insnset, cfg, r)
			gen.sc(2)
			return gen.text
		},
	})
}

type generator struct {
	imap map[string]*Insn
	mode iset.Mode
	r    *rand.Rand
	text []byte
}

func makeGen(insnset *InsnSet, cfg *iset.Config, r *rand.Rand) *generator {
	return &generator{
		imap: insnset.insnMap,
		mode: cfg.Mode,
		r:    r,
	}
}

func (gen *generator) byte(v []byte) {
	gen.text = append(gen.text, v...)
}

func (gen *generator) ld64(reg uint, v uint64) {
	// This is a widely used macro to load immediate on ppc64
	// #define LOAD64(rn,name)
	//	addis   rn,0,name##@highest \ lis     rn,name##@highest
	//	ori     rn,rn,name##@higher
	//	rldicr  rn,rn,32,31
	//	oris    rn,rn,name##@h
	//	ori     rn,rn,name##@l
	gen.byte(gen.imap["addis"].EncodeParam(map[string]uint{
		"RT": reg,
		"RA": 0, // In "addis", '0' means 0, not GPR0 .
		"SI": uint((v >> 48) & 0xffff)},
		nil))
	gen.byte(gen.imap["ori"].EncodeParam(map[string]uint{
		"RA": reg,
		"RS": reg,
		"UI": uint((v >> 32) & 0xffff)},
		nil))
	gen.byte(gen.imap["rldicr"].EncodeParam(map[string]uint{
		"RA": reg,
		"RS": reg,
		"SH": 32,
		"ME": 31},
		nil))
	gen.byte(gen.imap["oris"].EncodeParam(map[string]uint{
		"RA": reg,
		"RS": reg,
		"UI": uint((v >> 16) & 0xffff)},
		nil))
	gen.byte(gen.imap["ori"].EncodeParam(map[string]uint{
		"RA": reg,
		"RS": reg,
		"UI": uint(v & 0xffff)},
		nil))
}

func (gen *generator) sc(lev uint) {
	n := gen.r.Intn(9)
	// Valid hcall humbers at the momemt are: 4..0x450
	gen.ld64(3, uint64(gen.r.Intn(4+(0x450-4)/4)))
	for i := 4; i < n+4; i++ {
		gen.ld64(uint(i), gen.r.Uint64())
	}
	gen.byte(gen.imap["sc"].EncodeParam(map[string]uint{"LEV": lev}, nil))
}
