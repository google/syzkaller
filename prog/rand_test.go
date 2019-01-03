// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"math/rand"
	"testing"
)

func TestNotEscaping(t *testing.T) {
	r := newRand(nil, rand.NewSource(0))
	s := &state{
		files: map[string]bool{"./file0": true},
	}
	bound := 1000000
	if testing.Short() {
		bound = 1000
	}
	for i := 0; i < bound; i++ {
		fn := r.filenameImpl(s)
		if escapingFilename(fn) {
			t.Errorf("sandbox escaping file name %q", fn)
		}
	}
}

func TestDeterminism(t *testing.T) {
	target, rs, iters := initTest(t)
	iters /= 10 // takes too long
	for i := 0; i < iters; i++ {
		seed := rs.Int63()
		rs1 := rand.NewSource(seed)
		p1 := generateProg(t, target, rs1)
		rs2 := rand.NewSource(seed)
		p2 := generateProg(t, target, rs2)
		ps1 := string(p1.Serialize())
		ps2 := string(p2.Serialize())
		r1 := rs1.Int63()
		r2 := rs2.Int63()
		if r1 != r2 || ps1 != ps2 {
			t.Errorf("seed=%v\nprog 1 (%v):\n%v\nprog 2 (%v):\n%v", seed, r1, ps1, r2, ps2)
		}
	}
}

func generateProg(t *testing.T, target *Target, rs rand.Source) *Prog {
	p := target.Generate(rs, 5, nil)
	p.Mutate(rs, 10, nil, nil)
	for i, c := range p.Calls {
		comps := make(CompMap)
		for v := range extractValues(c) {
			comps.AddComp(v, v+1)
			comps.AddComp(v, v+10)
		}
		p.MutateWithHints(i, comps, func(p1 *Prog) {
			p = p1.Clone()
		})
	}
	for _, crash := range []bool{false, true} {
		p, _ = Minimize(p, -1, crash, func(*Prog, int) bool {
			return rs.Int63()%10 == 0
		})
	}
	data := p.Serialize()
	var err error
	p, err = target.Deserialize(data, NonStrict)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
