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
	ForeachArg(c, func(arg Arg, _ *ArgCtx) {
		switch typ := arg.Type().(type) {
		case *ResourceType:
			if typ.Dir() != DirIn {
				s.resources[typ.Desc.Name] = append(s.resources[typ.Desc.Name], arg)
				// TODO: negative PIDs and add them as well (that's process groups).
			}
		case *BufferType:
			a := arg.(*DataArg)
			if typ.Dir() != DirOut && len(a.Data()) != 0 {
				switch typ.Kind {
				case BufferString:
					s.strings[string(a.Data())] = true
				case BufferFilename:
					s.files[string(a.Data())] = true
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

type ArgCtx struct {
	Parent *[]Arg      // GroupArg.Inner (for structs) or Call.Args containing this arg
	Base   *PointerArg // pointer to the base of the heap object containing this arg
	Offset uint64      // offset of this arg from the base
	Stop   bool        // if set by the callback, subargs of this arg are not visited
}

func ForeachSubArg(arg Arg, f func(Arg, *ArgCtx)) {
	foreachArgImpl(arg, ArgCtx{}, f)
}

func ForeachArg(c *Call, f func(Arg, *ArgCtx)) {
	ctx := ArgCtx{}
	if c.Ret != nil {
		foreachArgImpl(c.Ret, ctx, f)
	}
	ctx.Parent = &c.Args
	for _, arg := range c.Args {
		foreachArgImpl(arg, ctx, f)
	}
}

func foreachArgImpl(arg Arg, ctx ArgCtx, f func(Arg, *ArgCtx)) {
	f(arg, &ctx)
	if ctx.Stop {
		return
	}
	switch a := arg.(type) {
	case *GroupArg:
		if _, ok := a.Type().(*StructType); ok {
			ctx.Parent = &a.Inner
		}
		var totalSize uint64
		for _, arg1 := range a.Inner {
			foreachArgImpl(arg1, ctx, f)
			if !arg1.Type().BitfieldMiddle() {
				size := arg1.Size()
				ctx.Offset += size
				totalSize += size
			}
		}
		if totalSize > a.Size() {
			panic(fmt.Sprintf("bad group arg size %v, should be <= %v for %+v",
				totalSize, a.Size(), a))
		}
	case *PointerArg:
		if a.Res != nil {
			ctx.Base = a
			ctx.Offset = 0
			foreachArgImpl(a.Res, ctx, f)
		}
	case *UnionArg:
		foreachArgImpl(a.Option, ctx, f)
	}
}

// TODO(dvyukov): combine RequiresBitmasks and RequiresChecksums into a single function
// to not walk the tree twice. They are always used together anyway.
func RequiresBitmasks(p *Prog) bool {
	result := false
	for _, c := range p.Calls {
		ForeachArg(c, func(arg Arg, _ *ArgCtx) {
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
		ForeachArg(c, func(arg Arg, _ *ArgCtx) {
			if _, ok := arg.Type().(*CsumType); ok {
				result = true
			}
		})
	}
	return result
}
