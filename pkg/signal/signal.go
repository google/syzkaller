// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package signal provides types for working with feedback signal.
package signal

type (
	elemType uint32
	prioType int8
)

type Signal map[elemType]prioType

type Serial struct {
	Elems []elemType
	Prios []prioType
}

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

func (s *Signal) Split(n int) Signal {
	if n >= s.Len() {
		ret := *s
		*s = nil
		return ret
	}
	c := make(Signal, n)
	for e, p := range *s {
		delete(*s, e)
		c[e] = p
		n--
		if n == 0 {
			break
		}
	}
	if len(*s) == 0 {
		*s = nil
	}
	return c
}

func FromRaw(raw []uint32, prio uint8) Signal {
	if len(raw) == 0 {
		return nil
	}
	s := make(Signal, len(raw))
	for _, e := range raw {
		s[elemType(e)] = prioType(prio)
	}
	return s
}

func (s Signal) Serialize() Serial {
	if s.Empty() {
		return Serial{}
	}
	res := Serial{
		Elems: make([]elemType, len(s)),
		Prios: make([]prioType, len(s)),
	}
	i := 0
	for e, p := range s {
		res.Elems[i] = e
		res.Prios[i] = p
		i++
	}
	return res
}

func (ser *Serial) AddElem(elem uint32, prio prioType) {
	ser.Elems = append(ser.Elems, elemType(elem))
	ser.Prios = append(ser.Prios, prio)
}

func (ser Serial) Deserialize() Signal {
	if len(ser.Elems) != len(ser.Prios) {
		panic("corrupted Serial")
	}
	if len(ser.Elems) == 0 {
		return nil
	}
	s := make(Signal, len(ser.Elems))
	for i, e := range ser.Elems {
		s[e] = ser.Prios[i]
	}
	return s
}

func (s Signal) Diff(s1 Signal) Signal {
	if s1.Empty() {
		return nil
	}
	var res Signal
	for e, p1 := range s1 {
		if p, ok := s[e]; ok && p >= p1 {
			continue
		}
		if res == nil {
			res = make(Signal)
		}
		res[e] = p1
	}
	return res
}

func (s Signal) DiffRaw(raw []uint32, prio uint8) Signal {
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
