// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

/* Package cover implements set operations on slices (arrays of coverage PCs). */
package cover

import (
	"sort"
)

type Cover []uint32

func (a Cover) Len() int           { return len(a) }
func (a Cover) Less(i, j int) bool { return a[i] < a[j] }
func (a Cover) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

const sent = ^uint32(0)

func Copy(cov Cover) Cover {
	return append(Cover{}, cov...)
}

func RestorePC(pc uint32, base uint32) uint64 {
	return uint64(base)<<32 + uint64(pc)
}

// Canonicalize sorts and removes duplicates.
func Canonicalize(cov []uint32) Cover {
	sort.Sort(Cover(cov))
	i := 0
	last := sent
	for _, pc := range cov {
		if pc != last {
			last = pc
			cov[i] = pc
			i++
		}
	}
	return Cover(cov[:i])
}

func Difference(cov0, cov1 Cover) Cover {
	return foreach(cov0, cov1, func(v0, v1 uint32) uint32 {
		if v0 < v1 {
			return v0
		}
		return sent
	})
}

func SymmetricDifference(cov0, cov1 Cover) Cover {
	return foreach(cov0, cov1, func(v0, v1 uint32) uint32 {
		if v0 < v1 {
			return v0
		}
		if v1 < v0 {
			return v1
		}
		return sent
	})
}

func Union(cov0, cov1 Cover) Cover {
	return foreach(cov0, cov1, func(v0, v1 uint32) uint32 {
		if v0 <= v1 {
			return v0
		}
		return v1
	})
}

func Intersection(cov0, cov1 Cover) Cover {
	return foreach(cov0, cov1, func(v0, v1 uint32) uint32 {
		if v0 == v1 {
			return v0
		}
		return sent
	})
}

func foreach(cov0, cov1 Cover, f func(uint32, uint32) uint32) Cover {
	var res []uint32
	for i0, i1 := 0, 0; i0 < len(cov0) || i1 < len(cov1); {
		v0, v1 := sent, sent
		if i0 < len(cov0) {
			v0 = cov0[i0]
		}
		if i1 < len(cov1) {
			v1 = cov1[i1]
		}
		if v0 <= v1 {
			i0++
		}
		if v1 <= v0 {
			i1++
		}
		if v := f(v0, v1); v != sent {
			res = append(res, v)
		}
	}
	return res
}

// HasDifference returns true if cov0 has some coverage that is not present in cov1.
// This is called on fuzzer hot path.
func HasDifference(cov0, cov1 Cover) bool {
	i1 := 0
	for _, v0 := range cov0 {
		for ; i1 < len(cov1) && cov1[i1] < v0; i1++ {
		}
		if i1 == len(cov1) || cov1[i1] > v0 {
			return true
		}
		i1++
	}
	return false
}

// Minimize returns a minimal set of inputs that give the same coverage as the full corpus.
func Minimize(corpus []Cover) []int {
	inputs := make([]*minInput, len(corpus))
	for i, cov := range corpus {
		inputs[i] = &minInput{
			idx: i,
			cov: cov,
		}
	}
	sort.Sort(minInputArray(inputs))
	var min []int
	covered := make(map[uint32]struct{})
	for _, inp := range inputs {
		hit := false
		for _, pc := range inp.cov {
			if !hit {
				if _, ok := covered[pc]; !ok {
					hit = true
					min = append(min, inp.idx)
				}
			}
			if hit {
				covered[pc] = struct{}{}
			}
		}
	}
	return min
}

type minInput struct {
	idx int
	cov Cover
}

type minInputArray []*minInput

// Inputs with larger coverage come first.
func (a minInputArray) Len() int           { return len(a) }
func (a minInputArray) Less(i, j int) bool { return len(a[i].cov) > len(a[j].cov) }
func (a minInputArray) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

func SignalNew(base map[uint32]struct{}, signal []uint32) bool {
	for _, s := range signal {
		if _, ok := base[s]; !ok {
			return true
		}
	}
	return false
}

func SignalDiff(base map[uint32]struct{}, signal []uint32) (diff []uint32) {
	for _, s := range signal {
		if _, ok := base[s]; !ok {
			diff = append(diff, s)
		}
	}
	return
}

func SignalAdd(base map[uint32]struct{}, signal []uint32) {
	for _, s := range signal {
		base[s] = struct{}{}
	}
}
