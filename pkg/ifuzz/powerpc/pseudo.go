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
	imap insnSetMap
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

func (gen *generator) sc(lev uint) {
	n := gen.r.Intn(9)
	// Valid hcall humbers at the momemt are: 4..0x450
	gen.byte(gen.imap.ld64(3, uint64(gen.r.Intn(4+(0x450-4)/4))))
	for i := 4; i < n+4; i++ {
		gen.byte(gen.imap.ld64(uint(i), gen.r.Uint64()))
	}
	gen.byte(gen.imap["sc"].enc(map[string]uint{"LEV": lev}))
}
