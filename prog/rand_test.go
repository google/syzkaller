// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"bytes"
	"fmt"
	"math/rand"
	"sort"
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
	var corpus []*Prog
	for i := 0; i < iters; i++ {
		seed := rs.Int63()
		rs1 := rand.NewSource(seed)
		p1 := generateProg(t, target, rs1, corpus)
		rs2 := rand.NewSource(seed)
		p2 := generateProg(t, target, rs2, corpus)
		ps1 := string(p1.Serialize())
		ps2 := string(p2.Serialize())
		r1 := rs1.Int63()
		r2 := rs2.Int63()
		if r1 != r2 || ps1 != ps2 {
			t.Errorf("seed=%v\nprog 1 (%v):\n%v\nprog 2 (%v):\n%v", seed, r1, ps1, r2, ps2)
		}
		corpus = append(corpus, p1)
	}
}

func generateProg(t *testing.T, target *Target, rs rand.Source, corpus []*Prog) *Prog {
	p := target.Generate(rs, 5, nil)
	p.Mutate(rs, 10, nil, corpus)
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

// Checks that a generated program contains only enabled syscalls.
func TestEnabledCalls(t *testing.T) {
	target, rs, iters := initTest(t)
	enabledCalls := map[string]bool{"open": true, "read": true, "dup3": true, "write": true, "close": true}
	enabled := make(map[*Syscall]bool)
	for c := range enabledCalls {
		enabled[target.SyscallMap[c]] = true
	}
	ct := target.BuildChoiceTable(nil, enabled)
	for i := 0; i < 100; i++ {
		p := target.Generate(rs, 50, ct)
		for it := 0; it < iters/10; it++ {
			p.Mutate(rs, 50, ct, nil)
		}
		for _, c := range p.Calls {
			if _, ok := enabledCalls[c.Meta.Name]; !ok {
				t.Fatalf("program contains a syscall that is not enabled: %v\n", c.Meta.Name)
			}
		}
	}
}

func TestSizeGenerateConstArg(t *testing.T) {
	target, rs, iters := initRandomTargetTest(t, "test", "64")
	r := newRand(target, rs)
	for _, c := range target.Syscalls {
		ForeachType(c, func(typ Type) {
			if _, ok := typ.(*IntType); !ok {
				return
			}
			bits := typ.TypeBitSize()
			limit := uint64(1<<bits - 1)
			for i := 0; i < iters; i++ {
				newArg, _ := typ.generate(r, nil)
				newVal := newArg.(*ConstArg).Val
				if newVal > limit {
					t.Fatalf("invalid generated value: %d. (arg bitsize: %d; max value: %d)", newVal, bits, limit)
				}
			}
		})
	}
}

func TestFlags(t *testing.T) {
	// This test does not test anything, it just prints resulting
	// distribution of values for different scenarios.
	tests := []struct {
		vv      []uint64
		bitmask bool
		old     uint64
	}{
		{[]uint64{0, 1, 2, 3}, false, 0},
		{[]uint64{0, 1, 2, 3}, false, 2},
		{[]uint64{1, 2, 3, 4}, false, 0},
		{[]uint64{1, 2, 3, 4}, false, 2},
		{[]uint64{1, 2, 4, 8}, true, 0},
		{[]uint64{1, 2, 4, 8}, true, 2},
		{[]uint64{7}, false, 0},
		{[]uint64{7}, false, 7},
		{[]uint64{1, 2}, true, 0},
		{[]uint64{1, 2}, true, 2},
	}
	target, rs, _ := initRandomTargetTest(t, "test", "64")
	r := newRand(target, rs)
	for _, test := range tests {
		results := make(map[uint64]uint64)
		const throws = 1e4
		for i := 0; i < throws; i++ {
			var v uint64
			for {
				v = r.flags(test.vv, test.bitmask, test.old)
				if test.old == 0 || test.old != v {
					break
				}
			}
			if v > 100 {
				v = 999 // to not print all possible random values we generated
			}
			results[v]++
		}
		var sorted [][2]uint64
		for v, c := range results {
			sorted = append(sorted, [2]uint64{v, c})
		}
		sort.Slice(sorted, func(i, j int) bool {
			return sorted[i][0] < sorted[j][0]
		})
		buf := new(bytes.Buffer)
		for _, p := range sorted {
			fmt.Fprintf(buf, "%v\t%v\n", p[0], p[1])
		}
		t.Logf("test: vv=%+v bitmask=%v old=%v\nvalue\ttimes (out of %v)\n%v",
			test.vv, test.bitmask, test.old, throws, buf.String())
	}
}
