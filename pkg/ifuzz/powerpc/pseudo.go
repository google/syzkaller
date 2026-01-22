// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package powerpc

import (
	"math/rand"

	"github.com/google/syzkaller/pkg/ifuzz/iset"
)

const (
	// Valid hcall humbers at the momemt are: 4..0x450.
	MaxHcall = 0x450 // MAX_HCALL
	SprnSrr0 = 0x01A // pc for rfid (SPRN_SRR0)
	SprnSrr1 = 0x01B // msr for rfid (SPRN_SRR1)
)

func (insnset *InsnSet) initPseudo() {
	type pseudoInsn struct {
		Name      string
		generator func(cfg *iset.Config, r *rand.Rand) []byte
	}
	for _, insn := range []pseudoInsn{
		{
			Name: "PSEUDO_hypercall",
			generator: func(cfg *iset.Config, r *rand.Rand) []byte {
				gen := makeGen(insnset, cfg, r)
				gen.sc(1)
				return gen.text
			},
		},
		{
			Name: "PSEUDO_syscall",
			generator: func(cfg *iset.Config, r *rand.Rand) []byte {
				gen := makeGen(insnset, cfg, r)
				gen.sc(0)
				return gen.text
			},
		},
		{
			Name: "PSEUDO_ultracall",
			generator: func(cfg *iset.Config, r *rand.Rand) []byte {
				gen := makeGen(insnset, cfg, r)
				gen.sc(2)
				return gen.text
			},
		},
		{
			Name: "PSEUDO_rtas",
			generator: func(cfg *iset.Config, r *rand.Rand) []byte {
				gen := makeGen(insnset, cfg, r)
				gen.rtas()
				return gen.text
			},
		},
		{
			Name: "PSEUDO_rfid",
			generator: func(cfg *iset.Config, r *rand.Rand) []byte {
				gen := makeGen(insnset, cfg, r)
				gen.rfid()
				return gen.text
			},
		},
	} {
		insnset.Insns = append(insnset.Insns, &Insn{
			Name:      insn.Name,
			Priv:      true,
			Pseudo:    true,
			generator: insn.generator,
		})
	}
}

type generator struct {
	imap insnSetMap
	cfg  *iset.Config
	r    *rand.Rand
	text []byte
}

func makeGen(insnset *InsnSet, cfg *iset.Config, r *rand.Rand) *generator {
	return &generator{
		imap: insnset.insnMap,
		cfg:  cfg,
		r:    r,
	}
}

func (gen *generator) byte(v []byte) {
	gen.text = append(gen.text, v...)
}

func (gen *generator) sc(lev uint) {
	imap := gen.imap

	n := gen.r.Intn(9)
	hcrange := gen.r.Intn(3)
	offset := 4
	maxhc := MaxHcall
	switch hcrange {
	case 1:
		offset = 0xf000
		maxhc = 0xf810
	case 2:
		offset = 0xef00
		maxhc = 0xef20
	}
	hc := gen.r.Intn((maxhc-offset)/4)*4 + offset
	gen.byte(imap.ld64(3, uint64(hc)))
	for i := 4; i < n+4; i++ {
		gen.byte(imap.ld64(uint(i), gen.r.Uint64()))
	}
	gen.byte(imap.sc(lev))
}

func (gen *generator) rtas() {
	imap := gen.imap

	addr := iset.GenerateInt(gen.cfg, gen.r, 8)
	token := uint32(gen.r.Intn(8) << 24) // There are only 4 tokens handled by KVM and it is BigEndian.
	reg := uint(iset.GenerateInt(gen.cfg, gen.r, 4))

	gen.byte(imap.ldgpr32(reg, reg+uint(1), addr, token))
	for i := 0; i < gen.r.Intn(4)+1; i++ {
		gen.byte(imap.ldgpr32(reg, reg+uint(1), addr+uint64(i*4),
			uint32(iset.GenerateInt(gen.cfg, gen.r, 4))))
	}
	gen.byte(imap.ld64(3, 0xF000)) // 0xF000 is a custom H_RTAS hypercall
	gen.byte(imap.ld64(4, addr))

	gen.byte(imap.sc(1))
}

func (gen *generator) rfid() {
	imap := gen.imap
	tmpreg := uint(gen.r.Intn(32))

	// SRR0 contains a PC
	gen.byte(imap.ld64(tmpreg, iset.GenerateInt(gen.cfg, gen.r, 8)))
	gen.byte(imap["mtspr"].enc(map[string]uint{"RS": tmpreg, "SPR": SprnSrr0}))

	// SRR1 contains an MSR
	gen.byte(imap.ld64(tmpreg, gen.r.Uint64()))
	gen.byte(imap["mtspr"].enc(map[string]uint{"RS": tmpreg, "SPR": SprnSrr1}))

	gen.byte(imap["rfid"].enc(map[string]uint{}))
}
