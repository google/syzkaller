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

func TestChooseUnionIndexOptionalResource(t *testing.T) {
	target := initTargetTest(t, "test", "64")
	resArg := target.SyscallMap["test$consume_subtype_of_common"].Args[0].Type.(*ResourceType)
	voidType := &BufferType{TypeCommon: TypeCommon{TypeName: "void", IsVarlen: true}}
	optUnion := &UnionType{
		Fields: []Field{
			{Name: "val", Type: resArg},
			{Name: "void", Type: voidType},
		},
	}

	r := newRand(target, rand.NewSource(0))
	// Even when s.resources is completely empty (e.g. first call of a program),
	// optional[res] (and optional[union_wrapping_res]) should prefer "void" (index 1, 75%).
	sEmpty := newState(target, target.DefaultChoiceTable(), nil)
	nestedUnion := &UnionType{
		Fields: []Field{
			{Name: "res", Type: resArg},
			{Name: "other", Type: voidType},
		},
	}
	optNestedUnion := &UnionType{
		Fields: []Field{
			{Name: "val", Type: nestedUnion},
			{Name: "void", Type: voidType},
		},
	}
	const iters = 1000
	valEmpty := 0
	valNestedEmpty := 0
	for range iters {
		if r.chooseUnionIndex(sEmpty, optUnion, DirIn) == 0 {
			valEmpty++
		}
		if r.chooseUnionIndex(sEmpty, optNestedUnion, DirIn) == 0 {
			valNestedEmpty++
		}
	}
	assert.InDelta(t, iters*0.25, valEmpty, iters*0.07)
	assert.InDelta(t, iters*0.25, valNestedEmpty, iters*0.07)

	// When state has some unrelated resource (r104), subtype_of_common is absent and should prefer "void" (index 1).
	pOther, err := target.Deserialize([]byte("test$r104_producer(&(0x7f0000000000)=<r0=>0x0)\n"), Strict)
	require.NoError(t, err)
	sAbsent := analyze(target.DefaultChoiceTable(), nil, pOther, nil)

	valAbsent := 0
	for range iters {
		if r.chooseUnionIndex(sAbsent, optUnion, DirIn) == 0 {
			valAbsent++
		}
	}
	assert.InDelta(t, iters*0.25, valAbsent, iters*0.07)

	// When state has a compatible resource (subtype_of_common), it should prefer "val" (index 0).
	pPresent, err := target.Deserialize([]byte("r0 = test$produce_subtype_of_common()\n"), Strict)
	require.NoError(t, err)
	sPresent := analyze(target.DefaultChoiceTable(), nil, pPresent, nil)

	valPresent := 0
	for range iters {
		if r.chooseUnionIndex(sPresent, optUnion, DirIn) == 0 {
			valPresent++
		}
	}
	assert.InDelta(t, iters*0.80, valPresent, iters*0.07)
}

func TestArrayUnionPermutation(t *testing.T) {
	target := initTargetTest(t, "test", "64")
	arrType := target.SyscallMap["test$array0"].Args[0].Type.(*PtrType).Elem.(*StructType).Fields[1].Type.(*ArrayType)
	r := newRand(target, rand.NewSource(0))
	s := newState(target, target.DefaultChoiceTable(), nil)

	distinctPairs := 0
	twoElemArrays := 0
	const iters = 400
	for range iters {
		arg, _ := arrType.generate(r, s, DirIn)
		inner := arg.(*GroupArg).Inner
		if len(inner) == 2 {
			twoElemArrays++
			if inner[0].(*UnionArg).Index != inner[1].(*UnionArg).Index {
				distinctPairs++
			}
		}
	}
	require.Greater(t, twoElemArrays, 100)
	// With 2 union fields, uniform independent choice gives distinct pairs 50% of the time,
	// whereas 75% permutation sampling + 25% uniform gives ~87.5% distinct pairs.
	assert.Greater(t, distinctPairs, twoElemArrays*3/4)
}

func TestNestedUnionArrayDepth(t *testing.T) {
	target := initTargetTest(t, "test", "64")
	voidType := &BufferType{TypeCommon: TypeCommon{TypeName: "void", IsVarlen: true}}
	voidType.setRef(1)
	makeFiveWayUnionArray := func(elem Type) *ArrayType {
		fields := []Field{{Name: "child", Type: elem}}
		for i := range 4 {
			fields = append(fields, Field{Name: fmt.Sprintf("f%d", i), Type: voidType})
		}
		u := &UnionType{Fields: fields}
		u.setRef(1)
		arr := &ArrayType{
			TypeCommon: TypeCommon{TypeName: "array", IsVarlen: true},
			Elem:       u,
			Kind:       ArrayRandLen,
		}
		arr.setRef(1)
		return arr
	}
	// Build 4 nested levels of ArrayRandLen[Union] (depths 0, 1, 2, 3).
	leafArr := makeFiveWayUnionArray(voidType)
	depth2Arr := makeFiveWayUnionArray(leafArr)
	depth1Arr := makeFiveWayUnionArray(depth2Arr)
	depth0Arr := makeFiveWayUnionArray(depth1Arr)

	r := newRand(target, rand.NewSource(0))
	s := newState(target, target.DefaultChoiceTable(), nil)

	const iters = 300
	var boostDepth1, boostDepth2, boostDepth3 int
	for range iters {
		r.unionArrayDepth = 1
		a1, _ := leafArr.generate(r, s, DirIn)
		if len(a1.(*GroupArg).Inner) >= 3 {
			boostDepth1++
		}
		r.unionArrayDepth = 2
		a2, _ := leafArr.generate(r, s, DirIn)
		if len(a2.(*GroupArg).Inner) >= 3 {
			boostDepth2++
		}
		r.unionArrayDepth = 3
		a3, _ := leafArr.generate(r, s, DirIn)
		if len(a3.(*GroupArg).Inner) >= 3 {
			boostDepth3++
		}
	}
	r.unionArrayDepth = 0
	arg, _ := depth0Arr.generate(r, s, DirIn)
	require.NotNil(t, arg)
	assert.Equal(t, 0, r.unionArrayDepth)
	// Depths 1 and 2 get the 50% multi-attribute boost, whereas depth >= 3 does not.
	assert.Greater(t, boostDepth1, boostDepth3+40)
	assert.Greater(t, boostDepth2, boostDepth3+25)
}
