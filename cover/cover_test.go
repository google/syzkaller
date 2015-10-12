// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package cover

import (
	"math/rand"
	"reflect"
	"sort"
	"testing"
	"time"
)

func initTest(t *testing.T) (*rand.Rand, int) {
	iters := 1000
	if testing.Short() {
		iters = 100
	}
	seed := int64(time.Now().UnixNano())
	rs := rand.NewSource(seed)
	t.Logf("seed=%v", seed)
	return rand.New(rs), iters
}

type Test struct {
	V0 Cover
	V1 Cover
	R  Cover
}

func runTest(t *testing.T, f func(Cover, Cover) Cover, sorted, symmetric bool, tests []Test) {
	if symmetric {
		for _, test := range tests {
			tests = append(tests, Test{test.V1, test.V0, test.R})
		}
	}
	tests = append(tests, Test{Cover{}, Cover{}, Cover{}})
	for _, test := range tests {
		if sorted {
			if !sort.IsSorted(test.V0) {
				t.Fatalf("input is not sorted: %+v", test.V0)
			}
			if !sort.IsSorted(test.V1) {
				t.Fatalf("input is not sorted: %+v", test.V1)
			}
		}
		if !sort.IsSorted(test.R) {
			t.Fatalf("golden is not sorted: %+v", test.R)
		}
		res := f(test.V0, test.V1)
		if !sort.IsSorted(res) {
			t.Fatalf("output is not sorted: %+v", res)
		}
		if (len(res) != 0 || len(test.R) != 0) && !reflect.DeepEqual(res, test.R) {
			t.Fatalf("f(%+v, %+v) = %+v (expect: %+v)", test.V0, test.V1, res, test.R)
		}
	}
}

func TestCanonicalize(t *testing.T) {
	runTest(t, func(c0, c1 Cover) Cover { return Canonicalize([]uint32(c0)) }, false, false, []Test{
		{Cover{1, 1, 2, 3, 3, 4, 5, 5, 5, 6, 6}, Cover{}, Cover{1, 2, 3, 4, 5, 6}},
		{Cover{6, 2, 3, 4, 5, 1}, Cover{}, Cover{1, 2, 3, 4, 5, 6}},
		{Cover{6, 1, 2, 6, 3, 3, 4, 5, 1}, Cover{}, Cover{1, 2, 3, 4, 5, 6}},
	})
}

func TestDifference(t *testing.T) {
	runTest(t, Difference, true, false, []Test{
		{Cover{1, 2, 3, 4, 5, 6}, Cover{}, Cover{1, 2, 3, 4, 5, 6}},
		{Cover{1, 2, 3, 4, 5, 6}, Cover{3}, Cover{1, 2, 4, 5, 6}},
		{Cover{1, 2, 3, 4, 5, 6}, Cover{1, 6}, Cover{2, 3, 4, 5}},
		{Cover{1, 2, 3, 4, 5, 6}, Cover{0, 10}, Cover{1, 2, 3, 4, 5, 6}},
		{Cover{1, 2, 3, 4, 5, 6}, Cover{0, 3, 6}, Cover{1, 2, 4, 5}},
	})
}

func TestSymmetricDifference(t *testing.T) {
	runTest(t, SymmetricDifference, true, true, []Test{
		{Cover{1, 2, 3, 4, 5, 6}, Cover{}, Cover{1, 2, 3, 4, 5, 6}},
		{Cover{1, 2, 3, 4, 5, 6}, Cover{1, 2, 3, 4, 5, 6}, Cover{}},
		{Cover{1, 2, 3, 4, 5, 6}, Cover{2, 4, 6}, Cover{1, 3, 5}},
		{Cover{2, 4, 6}, Cover{1, 3, 5}, Cover{1, 2, 3, 4, 5, 6}},
	})
}

func TestUnion(t *testing.T) {
	runTest(t, Union, true, true, []Test{
		{Cover{1, 2, 3, 4, 5, 6}, Cover{}, Cover{1, 2, 3, 4, 5, 6}},
		{Cover{1, 2, 3, 4, 5, 6}, Cover{1, 2, 3, 4, 5, 6}, Cover{1, 2, 3, 4, 5, 6}},
		{Cover{1, 3, 5}, Cover{2, 4, 6}, Cover{1, 2, 3, 4, 5, 6}},
		{Cover{1, 2, 3, 5}, Cover{2, 4, 5, 6}, Cover{1, 2, 3, 4, 5, 6}},
	})
}

func TestIntersection(t *testing.T) {
	runTest(t, Intersection, true, true, []Test{
		{Cover{1, 2, 3, 4, 5, 6}, Cover{}, Cover{}},
		{Cover{1, 2, 3}, Cover{4, 5, 6}, Cover{}},
		{Cover{1, 2, 3}, Cover{2, 3, 5}, Cover{2, 3}},
	})
}

func TestMinimize(t *testing.T) {
	tests := []struct {
		inp []Cover
		out []int
	}{
		// Take all.
		{
			[]Cover{
				{1, 2, 3},
				{4, 5, 6},
				{7, 8, 9},
			},
			[]int{0, 1, 2},
		},
		// Take one.
		{
			[]Cover{
				{1, 2, 3, 4, 5, 6, 7, 8, 9},
				{1},
				{2, 3, 4, 5},
				{6, 7, 8},
			},
			[]int{0},
		},
		// Take two.
		{
			[]Cover{
				{1, 2, 3, 4, 5, 6, 7, 8, 9},
				{1},
				{2, 3, 4, 5},
				{10},
			},
			[]int{0, 3},
		},
		// Take another two.
		{
			[]Cover{
				{1, 2, 3, 4},
				{1, 2},
				{3, 4, 5, 6, 7},
				{3, 7},
			},
			[]int{2, 0},
		},
		// Take the largest one.
		{
			[]Cover{
				{1, 2},
				{1, 2, 3, 4, 5},
				{3, 4, 5},
			},
			[]int{1},
		},
	}
	for _, test := range tests {
		res := Minimize(test.inp)
		if !reflect.DeepEqual(res, test.out) {
			t.Logf("corpus:")
			for _, in := range test.inp {
				t.Logf("  %+v", in)
			}
			t.Fatalf("expect: %+v, got: %+v", test.out, res)
		}
	}
}

func TestMinimizeRandom(t *testing.T) {
	rnd, iters := initTest(t)
	for i := 0; i < iters; i++ {
		n := rnd.Intn(20)
		cov := make([]Cover, n)
		for i := range cov {
			tmp := make(Cover, rnd.Intn(10))
			for j := range tmp {
				tmp[j] = uint32(rnd.Intn(100))
			}
			cov[i] = Canonicalize(tmp)
		}
		var total Cover
		for _, c := range cov {
			total = Union(total, c)
		}
		mini := Minimize(cov)
		var minimized Cover
		for _, idx := range mini {
			minimized = Union(minimized, cov[idx])
		}
		t.Logf("minimized %v -> %v", len(cov), len(mini))
		if !reflect.DeepEqual(total, minimized) {
			t.Logf("corpus:")
			for _, in := range cov {
				t.Logf("  %+v", in)
			}
			t.Logf("minimized:")
			for _, in := range cov {
				t.Logf("  %+v", in)
			}

			t.Fatalf("better luck next time")
		}
	}
}
