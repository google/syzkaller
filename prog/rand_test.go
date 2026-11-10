// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"bytes"
	"cmp"
	"fmt"
	"math/rand"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNotEscaping(t *testing.T) {
	target, err := GetTarget("test", "64")
	if err != nil {
		t.Fatal(err)
	}
	r := newRand(target, rand.NewSource(0))
	s := &state{
		files: map[string]bool{"./file0": true},
	}
	bound := 1000000
	if testing.Short() {
		bound = 1000
	}
	for range bound {
		fn := r.filenameImpl(s)
		if escapingFilename(fn) {
			t.Errorf("sandbox escaping file name %q", fn)
		}
	}
}

func TestDeterminism(t *testing.T) {
	target, rs, iters := initTest(t)
	iters /= 10 // takes too long
	ct := target.DefaultChoiceTable()
	var corpus []*Prog
	for range iters {
		seed := rs.Int63()
		rs1 := rand.NewSource(seed)
		p1 := generateProg(t, target, rs1, ct, corpus)
		if p1 == nil {
			continue
		}
		rs2 := rand.NewSource(seed)
		p2 := generateProg(t, target, rs2, ct, corpus)
		if p2 == nil {
			continue
		}
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

func generateProg(t *testing.T, target *Target, rs rand.Source, ct *ChoiceTable, corpus []*Prog) *Prog {
	p := target.Generate(rs, 5, ct)
	p.Mutate(rs, 10, ct, nil, corpus)
	if p.countArgs() > maxArgCutoff {
		return nil
	}
	for i, c := range p.Calls {
		comps := make(CompMap)
		for v := range extractValues(c) {
			comps.Add(1, v, v+1, true)
			comps.Add(1, v, v+10, true)
		}
		// If unbounded, this code may take O(N^2) time to complete.
		// Since large programs are not uncommon, let's limit the number of hint iterations.
		limit := 100
		p.MutateWithHints(i, comps, func(p1 *Prog) bool {
			p = p1.Clone()
			limit--
			return limit > 0
		})
	}
	for _, mode := range []MinimizeMode{MinimizeCorpus, MinimizeCrash} {
		p, _ = Minimize(p, -1, mode, func(*Prog, int) bool {
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
	enabledCalls := make(map[string]bool)
	enabled := make(map[*Syscall]bool)
	rnd := rand.New(rs)
	for range len(target.Syscalls) / 10 {
		c := target.Syscalls[rnd.Intn(len(target.Syscalls))]
		enabled[c] = true
		enabledCalls[c.Name] = true
	}
	c := target.SyscallMap["clock_gettime"]
	enabled[c] = true
	enabledCalls[c.Name] = true

	ct := target.BuildChoiceTable(nil, enabled)
	const tries = 10
	for range tries {
		p := target.Generate(rs, 50, ct)
		for range iters / tries {
			p.Mutate(rs, 50, ct, nil, nil)
		}
		for _, c := range p.Calls {
			if _, ok := enabledCalls[c.Meta.Name]; !ok {
				t.Fatalf("program contains a syscall that is not enabled: %v", c.Meta.Name)
			}
		}
	}
}

func TestSizeGenerateConstArg(t *testing.T) {
	target, rs, iters := initRandomTargetTest(t, "test", "64")
	r := newRand(target, rs)
	ForeachType(target.Syscalls, func(typ Type, ctx *TypeCtx) {
		if _, ok := typ.(*IntType); !ok {
			return
		}
		bits := typ.TypeBitSize()
		limit := uint64(1<<bits - 1)
		for range iters {
			newArg, _ := typ.generate(r, nil, ctx.Dir)
			newVal := newArg.(*ConstArg).Val
			if newVal > limit {
				t.Fatalf("invalid generated value: %d. (arg bitsize: %d; max value: %d)", newVal, bits, limit)
			}
		}
	})
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
		const throws = 10000
		for range throws {
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
		slices.SortFunc(sorted, func(a, b [2]uint64) int {
			return cmp.Compare(a[0], b[0])
		})
		buf := new(bytes.Buffer)
		for _, p := range sorted {
			fmt.Fprintf(buf, "%v\t%v\n", p[0], p[1])
		}
		t.Logf("test: vv=%+v bitmask=%v old=%v\nvalue\ttimes (out of %v)\n%v",
			test.vv, test.bitmask, test.old, throws, buf.String())
	}
}

func TestTruncateToBitSize(t *testing.T) {
	tests := []struct{ v, bits, res uint64 }{
		{0, 1, 0},
		{1, 1, 1},
		{0x123, 4, 0x3},
		{0xabc, 4, 0xc},
		{0x123, 8, 0x23},
		{0xabc, 8, 0xbc},
		{0x12345678abcdabcd, 64, 0x12345678abcdabcd},
		{0xf2345678abcdabcd, 64, 0xf2345678abcdabcd},
	}
	for i, test := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			res := truncateToBitSize(test.v, test.bits)
			if res != test.res {
				t.Fatalf("truncateToBitSize(0x%x, %v)=0x%x, want 0x%x", test.v, test.bits, res, test.res)
			}
		})
	}
}

// Checks that a generated program does not contain any "no_generate" syscalls.
func TestNoGenerate(t *testing.T) {
	target, rs, iters := initTest(t)

	// Enable all "no_generate" syscalls and ~10% of all others.
	enabled := make(map[*Syscall]bool)
	rnd := newRand(target, rs)
	for range len(target.Syscalls) {
		syscall := target.Syscalls[rnd.Intn(len(target.Syscalls))]
		if syscall.Attrs.NoGenerate || rnd.oneOf(10) {
			enabled[syscall] = true
		}
	}
	c := target.SyscallMap["clock_gettime"]
	enabled[c] = true
	ct := target.BuildChoiceTable(nil, enabled)

	const tries = 10
	for range tries {
		p := target.Generate(rs, 50, ct)
		for range iters / tries {
			p.Mutate(rs, 50, ct, nil, nil)
		}
		for _, c := range p.Calls {
			if c.Meta.Attrs.NoGenerate {
				t.Fatalf("program contains a no_generate syscall: %v", c.Meta.Name)
			}
		}
	}
}

// Arrays of unions must combine distinct options rather than repeat the same one:
// with 4 options, independent uniform choice would give 75% distinct adjacent pairs.
func TestGenerateUnionArray(t *testing.T) {
	target := initTargetTest(t, "test", "64")
	r := newRand(target, rand.NewSource(0))
	s := newState(target, target.DefaultChoiceTable(), nil)
	arrType := target.SyscallMap["test$union_array"].Args[0].Type.(*PtrType).Elem.(*ArrayType)
	pairs, distinct := 0, 0
	for range 1000 {
		arg, _ := arrType.generate(r, s, DirIn)
		elems := arg.(*GroupArg).Inner
		for i := range len(elems) - 1 {
			pairs++
			if elems[i].(*UnionArg).Index != elems[i+1].(*UnionArg).Index {
				distinct++
			}
		}
	}
	assert.Greater(t, float64(distinct)/float64(pairs), 0.85)
}

// Single-element arrays of unions must be extended to several elements, but only up to
// the maxUnionArrayExtendDepth nesting level, so that nested arrays don't blow up the program.
func TestGenerateUnionArrayDepth(t *testing.T) {
	target := initTargetTest(t, "test", "64")
	r := newRand(target, rand.NewSource(0))
	s := newState(target, target.DefaultChoiceTable(), nil)
	arrType := target.SyscallMap["test$union_array"].Args[0].Type.(*PtrType).Elem.(*ArrayType)
	// singleShare returns the share of single-element arrays generated at the given nesting depth.
	singleShare := func(depth int) float64 {
		const iters = 2000
		r.unionArrayDepth = depth
		single := 0
		for range iters {
			arg, _ := arrType.generate(r, s, DirIn)
			if len(arg.(*GroupArg).Inner) == 1 {
				single++
			}
		}
		return float64(single) / iters
	}
	// Single-element arrays are extended in 3/4 (generateUnionArray) * 1/2 of the cases.
	assert.Less(t, singleShare(0), 0.75*singleShare(3))
	assert.Less(t, singleShare(maxUnionArrayExtendDepth), 0.75*singleShare(3))
}

// optional[T] that wraps a resource must mostly be set when a compatible resource already
// exists in the program, and mostly be left empty otherwise (to avoid generating resource
// producers for optional fields). Other unions must not be affected.
func TestGenerateOptionalResource(t *testing.T) {
	target := initTargetTest(t, "test", "64")
	r := newRand(target, rand.NewSource(0))
	fields := target.SyscallMap["test$optional_union"].Args[0].Type.(*PtrType).Elem.(*StructType).Fields
	optRes := fields[0].Type.(*UnionType)       // optional[subtype_of_common]
	optNestedRes := fields[1].Type.(*UnionType) // optional[union_gen_res], union_gen_res has a resource option
	plainUnion := fields[2].Type.(*UnionType)   // union_gen_res itself
	// stateAfter returns the generation state after the given program.
	stateAfter := func(prog string) *state {
		p, err := target.Deserialize([]byte(prog), Strict)
		require.NoError(t, err)
		return analyze(target.DefaultChoiceTable(), nil, p, nil)
	}
	// valShare returns the share of chooseUnionIndex() calls that chose the first ("val") option.
	valShare := func(s *state, u *UnionType) float64 {
		const iters = 1000
		val := 0
		for range iters {
			if r.chooseUnionIndex(s, u, DirIn) == 0 {
				val++
			}
		}
		return float64(val) / iters
	}
	noResources := newState(target, target.DefaultChoiceTable(), nil)
	unrelatedResource := stateAfter("test$r104_producer(&(0x7f0000000000)=<r0=>0x0)\n")
	compatibleResource := stateAfter("r0 = test$produce_subtype_of_common()\n")

	assert.InDelta(t, 0.25, valShare(noResources, optRes), 0.07)
	assert.InDelta(t, 0.25, valShare(noResources, optNestedRes), 0.07)
	assert.InDelta(t, 0.25, valShare(unrelatedResource, optRes), 0.07)
	assert.InDelta(t, 0.80, valShare(compatibleResource, optRes), 0.07)
	assert.InDelta(t, 0.80, valShare(compatibleResource, optNestedRes), 0.07)
	assert.InDelta(t, 0.50, valShare(compatibleResource, plainUnion), 0.07)
}
