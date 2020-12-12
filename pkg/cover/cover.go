// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package cover provides types for working with coverage information (arrays of covered PCs).
package cover

type Cover map[uint32]struct{}

func (cov *Cover) Merge(raw []uint32) {
	c := *cov
	if c == nil {
		c = make(Cover)
		*cov = c
	}
	for _, pc := range raw {
		c[pc] = struct{}{}
	}
}

// Merge merges raw into coverage and returns newly added PCs. Overwrites/mutates raw.
func (cov *Cover) MergeDiff(raw []uint32) []uint32 {
	c := *cov
	if c == nil {
		c = make(Cover)
		*cov = c
	}
	n := 0
	for _, pc := range raw {
		if _, ok := c[pc]; ok {
			continue
		}
		c[pc] = struct{}{}
		raw[n] = pc
		n++
	}
	return raw[:n]
}

func (cov Cover) Serialize() []uint32 {
	res := make([]uint32, 0, len(cov))
	for pc := range cov {
		res = append(res, pc)
	}
	return res
}
