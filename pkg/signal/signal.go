// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package signal provides types for working with feedback signal.
package signal

type (
	elemType uint64
	prioType int8
)

// Signal was hard to refactor when we enabled recvcheck.
type Signal map[elemType]prioType // nolint: recvcheck

func (s Signal) Len() int {
	return len(s)
}

func (s Signal) Empty() bool {
	return len(s) == 0
}

func (s Signal) Copy() Signal {
	c := make(Signal, len(s))
	for e, p := range s {
		c[e] = p
	}
	return c
}

func FromRaw(raw []uint64, prio uint8) Signal {
	if len(raw) == 0 {
		return nil
	}
	s := make(Signal, len(raw))
	for _, e := range raw {
		s[elemType(e)] = prioType(prio)
	}
	return s
}

func (s Signal) DiffRaw(raw []uint64, prio uint8) Signal {
	var res Signal
	for _, e := range raw {
		if p, ok := s[elemType(e)]; ok && p >= prioType(prio) {
			continue
		}
		if res == nil {
			res = make(Signal)
		}
		res[elemType(e)] = prioType(prio)
	}
	return res
}

func (s Signal) IntersectsWith(other Signal) bool {
	for e, p := range s {
		if p1, ok := other[e]; ok && p1 >= p {
			return true
		}
	}
	return false
}

func (s Signal) Intersection(s1 Signal) Signal {
	if s1.Empty() {
		return nil
	}
	res := make(Signal, len(s))
	for e, p := range s {
		if p1, ok := s1[e]; ok && p1 >= p {
			res[e] = p
		}
	}
	return res
}

func (s *Signal) Merge(s1 Signal) {
	if s1.Empty() {
		return
	}
	s0 := *s
	if s0 == nil {
		s0 = make(Signal, len(s1))
		*s = s0
	}
	for e, p1 := range s1 {
		if p, ok := s0[e]; !ok || p < p1 {
			s0[e] = p1
		}
	}
}

func (s Signal) ToRaw() []uint64 {
	var raw []uint64
	for e := range s {
		raw = append(raw, uint64(e))
	}
	return raw
}

type Context struct {
	Signal  Signal
	Context interface{}
}

func Minimize(corpus []Context) []interface{} {
	type ContextPrio struct {
		prio prioType
		idx  int
	}
	covered := make(map[elemType]ContextPrio)
	for i, inp := range corpus {
		for e, p := range inp.Signal {
			if prev, ok := covered[e]; !ok || p > prev.prio {
				covered[e] = ContextPrio{
					prio: p,
					idx:  i,
				}
			}
		}
	}
	indices := make(map[int]struct{}, len(corpus))
	for _, cp := range covered {
		indices[cp.idx] = struct{}{}
	}
	result := make([]interface{}, 0, len(indices))
	for idx := range indices {
		result = append(result, corpus[idx].Context)
	}
	return result
}
