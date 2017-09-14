// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Conservative resource-related analysis of programs.
// The analysis figures out what files descriptors are [potentially] opened
// at a particular point in program, what pages are [potentially] mapped,
// what files were already referenced in calls, etc.

package prog

import (
	"fmt"
)

const (
	maxPages = 4 << 10
)

type state struct {
	target    *Target
	ct        *ChoiceTable
	files     map[string]bool
	resources map[string][]Arg
	strings   map[string]bool
	pages     [maxPages]bool
}

// analyze analyzes the program p up to but not including call c.
func analyze(ct *ChoiceTable, p *Prog, c *Call) *state {
	s := newState(p.Target, ct)
	for _, c1 := range p.Calls {
		if c1 == c {
			break
		}
		s.analyze(c1)
	}
	return s
}

func newState(target *Target, ct *ChoiceTable) *state {
	s := &state{
		target:    target,
		ct:        ct,
		files:     make(map[string]bool),
		resources: make(map[string][]Arg),
		strings:   make(map[string]bool),
	}
	return s
}

func (s *state) analyze(c *Call) {
	foreachArgArray(&c.Args, c.Ret, func(arg, base Arg, _ *[]Arg) {
		switch typ := arg.Type().(type) {
		case *ResourceType:
			if typ.Dir() != DirIn {
				s.resources[typ.Desc.Name] = append(s.resources[typ.Desc.Name], arg)
				// TODO: negative PIDs and add them as well (that's process groups).
			}
		case *BufferType:
			a := arg.(*DataArg)
			if typ.Dir() != DirOut && len(a.Data) != 0 {
				switch typ.Kind {
				case BufferString:
					s.strings[string(a.Data)] = true
				case BufferFilename:
					s.files[string(a.Data)] = true
				}
			}
		}
	})
	start, npages, mapped := s.target.AnalyzeMmap(c)
	if npages != 0 {
		if start+npages > uint64(len(s.pages)) {
			panic(fmt.Sprintf("address is out of bounds: page=%v len=%v bound=%v",
				start, npages, len(s.pages)))
		}
		for i := uint64(0); i < npages; i++ {
			s.pages[start+i] = mapped
		}
	}
}

func foreachSubargImpl(arg Arg, parent *[]Arg, f func(arg, base Arg, parent *[]Arg)) {
	var rec func(arg, base Arg, parent *[]Arg)
	rec = func(arg, base Arg, parent *[]Arg) {
		f(arg, base, parent)
		switch a := arg.(type) {
		case *GroupArg:
			for _, arg1 := range a.Inner {
				parent1 := parent
				if _, ok := arg.Type().(*StructType); ok {
					parent1 = &a.Inner
				}
				rec(arg1, base, parent1)
			}
		case *PointerArg:
			if a.Res != nil {
				rec(a.Res, arg, parent)
			}
		case *UnionArg:
			rec(a.Option, base, parent)
		}
	}
	rec(arg, nil, parent)
}

func foreachSubarg(arg Arg, f func(arg, base Arg, parent *[]Arg)) {
	foreachSubargImpl(arg, nil, f)
}

func foreachArgArray(args *[]Arg, ret Arg, f func(arg, base Arg, parent *[]Arg)) {
	for _, arg := range *args {
		foreachSubargImpl(arg, args, f)
	}
	if ret != nil {
		foreachSubargImpl(ret, nil, f)
	}
}

func foreachArg(c *Call, f func(arg, base Arg, parent *[]Arg)) {
	foreachArgArray(&c.Args, nil, f)
}

func foreachSubargOffset(arg Arg, f func(arg Arg, offset uint64)) {
	var rec func(Arg, uint64) uint64
	rec = func(arg1 Arg, offset uint64) uint64 {
		switch a := arg1.(type) {
		case *GroupArg:
			f(arg1, offset)
			var totalSize uint64
			for _, arg2 := range a.Inner {
				size := rec(arg2, offset)
				if !arg2.Type().BitfieldMiddle() {
					offset += size
					totalSize += size
				}
			}
			if totalSize > arg1.Size() {
				panic(fmt.Sprintf("bad group arg size %v, should be <= %v for %+v", totalSize, arg1.Size(), arg1))
			}
		case *UnionArg:
			f(arg1, offset)
			size := rec(a.Option, offset)
			offset += size
			if size > arg1.Size() {
				panic(fmt.Sprintf("bad union arg size %v, should be <= %v for arg %+v with type %+v", size, arg1.Size(), arg1, arg1.Type()))
			}
		default:
			f(arg1, offset)
		}
		return arg1.Size()
	}
	rec(arg, 0)
}

func RequiresBitmasks(p *Prog) bool {
	result := false
	for _, c := range p.Calls {
		foreachArg(c, func(arg, _ Arg, _ *[]Arg) {
			if a, ok := arg.(*ConstArg); ok {
				if a.Type().BitfieldOffset() != 0 || a.Type().BitfieldLength() != 0 {
					result = true
				}
			}
		})
	}
	return result
}

func RequiresChecksums(p *Prog) bool {
	result := false
	for _, c := range p.Calls {
		foreachArg(c, func(arg, _ Arg, _ *[]Arg) {
			if _, ok := arg.Type().(*CsumType); ok {
				result = true
			}
		})
	}
	return result
}
