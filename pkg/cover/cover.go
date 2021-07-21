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

type Offsets map[string]map[uint32]struct{}

func (co *Offsets) Merge(raw map[string][]uint32) {
	c := *co
	if c == nil {
		c = make(Offsets)
		*co = c
	}
	for mod, offsets := range raw {
		for _, offset := range offsets {
			if _, ok := c[mod]; !ok {
				c[mod] = make(map[uint32]struct{})
			}
			c[mod][offset] = struct{}{}
		}
	}
}

// Merge merges raw into coverage and returns newly added PCs. Overwrites/mutates raw.
func (co *Offsets) MergeDiff(raw map[string][]uint32) map[string][]uint32 {
	c := *co
	if c == nil {
		c = make(Offsets)
		*co = c
	}
	added := make(map[string][]uint32)
	for mod, offsets := range raw {
		if _, ok := c[mod]; !ok {
			c[mod] = make(map[uint32]struct{})
			for _, offset := range offsets {
				c[mod][offset] = struct{}{}
			}
			added[mod] = offsets
			continue
		}
		for _, offset := range offsets {
			if _, ok := c[mod][offset]; ok {
				continue
			}
			c[mod][offset] = struct{}{}
			added[mod] = append(added[mod], offset)
		}
	}
	return added
}

func (co Offsets) Serialize() map[string][]uint32 {
	res := make(map[string][]uint32)

	for mod, offsets := range co {
		for offset := range offsets {
			res[mod] = append(res[mod], offset)
		}
	}

	return res
}

func (co Offsets) CountOffsets() int {
	var count int
	for _, offs := range co {
		for range offs {
			count++
		}
	}
	return count
}