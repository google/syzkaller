// Copyright 2020 IBM Corp. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ppc64

import (
	"math/rand"
	. "github.com/google/syzkaller/pkg/ifuzz/common"
)

func initPseudo() {
	insns.insns = append(insns.insns, &InsnPowerPC{
		Name:   "PSEUDO_hypercall",
		Priv:   true,
		Pseudo: true,
		generator: func(cfg *Config, r *rand.Rand) []byte {
			gen := makeGen(cfg, r)
			gen.sc(1)
			return gen.text
		},
	})
	insns.insns = append(insns.insns, &InsnPowerPC{
		Name:   "PSEUDO_syscall",
		Priv:   true,
		Pseudo: true,
		generator: func(cfg *Config, r *rand.Rand) []byte {
			gen := makeGen(cfg, r)
			gen.sc(0)
			return gen.text
		},
	})
	insns.insns = append(insns.insns, &InsnPowerPC{
		Name:   "PSEUDO_ultracall",
		Priv:   true,
		Pseudo: true,
		generator: func(cfg *Config, r *rand.Rand) []byte {
			gen := makeGen(cfg, r)
			gen.sc(2)
			return gen.text
		},
	})
}

type generator struct {
	mode int
	r    *rand.Rand
	text []byte
}

func makeGen(cfg *Config, r *rand.Rand) *generator {
	return &generator{
		mode: cfg.Mode,
		r:    r,
	}
}

func (gen *generator) byte(v []byte) {
	gen.text = append(gen.text, v...)
}

func (gen *generator) ld64(reg uint, v uint64) {
	// This is a widely used macro to load immediate on ppc64
	//#define LOAD64(rn,name)
	//	addis   rn,0,name##@highest \ lis     rn,name##@highest
	//	ori     rn,rn,name##@higher
	//	rldicr  rn,rn,32,31
	//	oris    rn,rn,name##@h
	//	ori     rn,rn,name##@l
	gen.byte(insns.insnMap["addis"].EncodeParam(map[string]uint{
		"rt": reg,
		"ra": 0, // In "addis", '0' means 0, not GPR0
		"si": uint((v >> 48) & 0xffff)},
		nil))
	gen.byte(insns.insnMap["ori"].EncodeParam(map[string]uint{
		"ra": reg,
		"rs": reg,
		"ui": uint((v >> 32) & 0xffff)},
		nil))
	gen.byte(insns.insnMap["rldicr"].EncodeParam(map[string]uint{
		"ra": reg,
		"rs": reg,
		"sh": 32,
		"me": 31},
		nil))
	gen.byte(insns.insnMap["oris"].EncodeParam(map[string]uint{
		"ra": reg,
		"rs": reg,
		"ui": uint((v >> 16) & 0xffff)},
		nil))
	gen.byte(insns.insnMap["ori"].EncodeParam(map[string]uint{
		"ra": reg,
		"rs": reg,
		"ui": uint(v & 0xffff)},
		nil))
}

func (gen *generator) sc(lev uint) {
	n := gen.r.Intn(9)
	// Valid hcall humbers at the momemt are: 4..0x450
	gen.ld64(3, uint64(gen.r.Intn(4 + (0x450 - 4) / 4)))
	for i := 4; i < n + 4; i++ {
		gen.ld64(uint(i), gen.r.Uint64())
	}
	gen.byte(insns.insnMap["sc"].EncodeParam(map[string]uint{"lev": lev}, nil))
}
