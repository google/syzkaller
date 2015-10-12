// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Conservative resource-related analysis of programs.
// The analysis figures out what files descriptors are [potentially] opened
// at a particular point in program, what pages are [potentially] mapped,
// what files were already referenced in calls, etc.

package prog

import (
	"fmt"

	"github.com/google/syzkaller/sys"
)

const (
	maxPages = 4 << 10
)

type state struct {
	enabledCalls []*sys.Call
	files        map[string]bool
	resources    map[sys.ResourceKind]map[sys.ResourceSubkind][]*Arg
	strings      map[string]bool
	pages        [maxPages]bool
}

// analyze analyzes the program p up to but not including call c.
func analyze(enabledCalls []*sys.Call, p *Prog, c *Call) *state {
	s := newState(enabledCalls)
	for _, c1 := range p.Calls {
		if c1 == c {
			break
		}
		s.analyze(c1)
	}
	return s
}

func newState(enabledCalls []*sys.Call) *state {
	s := &state{
		enabledCalls: enabledCalls,
		files:        make(map[string]bool),
		resources:    make(map[sys.ResourceKind]map[sys.ResourceSubkind][]*Arg),
		strings:      make(map[string]bool),
	}
	if len(s.enabledCalls) == 0 {
		s.enabledCalls = sys.Calls
	}
	return s
}

func (s *state) analyze(c *Call) {
	foreachArgArray(&c.Args, c.Ret, func(arg, base *Arg, _ *[]*Arg) {
		switch typ := arg.Type.(type) {
		case sys.FilenameType:
			if arg.Kind == ArgData && arg.Dir != DirOut {
				s.files[string(arg.Data)] = true
			}
		case sys.ResourceType:
			if arg.Dir != DirIn {
				if s.resources[typ.Kind] == nil {
					s.resources[typ.Kind] = make(map[sys.ResourceSubkind][]*Arg)
				}
				s.resources[typ.Kind][typ.Subkind] = append(s.resources[typ.Kind][typ.Subkind], arg)
			}
		case sys.BufferType:
			if typ.Kind == sys.BufferString && arg.Kind == ArgData && len(arg.Data) != 0 {
				s.strings[string(arg.Data)] = true
			}
		}
	})
	switch c.Meta.Name {
	case "mmap":
		// Filter out only very wrong arguments.
		length := c.Args[1]
		if length.AddrPage == 0 && length.AddrOffset == 0 {
			break
		}
		if flags, fd := c.Args[4], c.Args[3]; flags.Val&MAP_ANONYMOUS == 0 && fd.Kind == ArgConst && fd.Val == sys.InvalidFD {
			break
		}
		s.addressable(c.Args[0], length, true)
	case "munmap":
		s.addressable(c.Args[0], c.Args[1], false)
	case "mremap":
		s.addressable(c.Args[4], c.Args[2], true)
	}
}

func (s *state) addressable(addr, size *Arg, ok bool) {
	if addr.Kind != ArgPointer || size.Kind != ArgPageSize {
		panic("mmap/munmap/mremap args are not pages")
	}
	n := size.AddrPage
	if size.AddrOffset != 0 {
		n++
	}
	if addr.AddrPage+n > uintptr(len(s.pages)) {
		panic(fmt.Sprintf("address is out of bounds: page=%v len=%v (%v, %v) bound=%v", addr.AddrPage, n, size.AddrPage, size.AddrOffset, len(s.pages)))
	}
	for i := uintptr(0); i < n; i++ {
		s.pages[addr.AddrPage+i] = ok
	}
}

func foreachArgArray(args *[]*Arg, ret *Arg, f func(arg, base *Arg, parent *[]*Arg)) {
	var rec func(arg, base *Arg, parent *[]*Arg)
	rec = func(arg, base *Arg, parent *[]*Arg) {
		f(arg, base, parent)
		for _, arg1 := range arg.Inner {
			parent1 := parent
			if _, ok := arg.Type.(sys.StructType); ok {
				parent1 = &arg.Inner
			}
			rec(arg1, base, parent1)
		}
		if arg.Kind == ArgPointer && arg.Res != nil {
			rec(arg.Res, arg, parent)
		}
	}
	for _, arg := range *args {
		rec(arg, nil, args)
	}
	if ret != nil {
		rec(ret, nil, nil)
	}
}

func foreachArg(c *Call, f func(arg, base *Arg, parent *[]*Arg)) {
	foreachArgArray(&c.Args, nil, f)
}

func referencedArgs(args []*Arg, ret *Arg) (res []*Arg) {
	f := func(arg, _ *Arg, _ *[]*Arg) {
		for arg1 := range arg.Uses {
			if arg1.Kind != ArgResult {
				panic("use references not ArgResult")
			}
			res = append(res, arg1)
		}
	}
	foreachArgArray(&args, ret, f)
	return
}

func assignTypeAndDir(c *Call) {
	var rec func(arg *Arg, typ sys.Type, dir ArgDir)
	rec = func(arg *Arg, typ sys.Type, dir ArgDir) {
		if arg.Call != nil && arg.Call != c {
			panic(fmt.Sprintf("different call is already assigned: %p %p %v %v", arg.Call, c, arg.Call.Meta.Name, c.Meta.Name))
		}
		arg.Call = c
		if arg.Type != nil && arg.Type.Name() != typ.Name() {
			panic("different type is already assigned")
		}
		arg.Type = typ
		switch arg.Kind {
		case ArgPointer:
			arg.Dir = DirIn
			switch typ1 := typ.(type) {
			case sys.FilenameType:
				rec(arg.Res, typ, dir)
			case sys.PtrType:
				if arg.Res != nil {
					rec(arg.Res, typ1.Type, ArgDir(typ1.Dir))
				}
			}
		case ArgGroup:
			arg.Dir = dir
			switch typ1 := typ.(type) {
			case sys.StructType:
				for i, arg1 := range arg.Inner {
					rec(arg1, typ1.Fields[i], dir)
				}
			case sys.ArrayType:
				for _, arg1 := range arg.Inner {
					rec(arg1, typ1.Type, dir)
				}
			}
		default:
			arg.Dir = dir
		}
	}
	for i, arg := range c.Args {
		rec(arg, c.Meta.Args[i], DirIn)
	}
	if c.Ret == nil {
		c.Ret = returnArg()
		c.Ret.Call = c
		c.Ret.Type = c.Meta.Ret
		c.Ret.Dir = DirOut
	}
}

func sanitizeCall(c *Call) {
	switch c.Meta.Name {
	case "mmap":
		// Add MAP_FIXED flag, otherwise it produces non-deterministic results.
		addr := c.Args[0]
		if addr.Kind != ArgPointer {
			panic("mmap address is not ArgPointer")
		}
		length := c.Args[1]
		if length.Kind != ArgPageSize {
			panic("mmap length is not ArgPageSize")
		}
		flags := c.Args[3]
		if flags.Kind != ArgConst {
			panic("mmap flag arg is not const")
		}
		flags.Val |= MAP_FIXED
	case "mremap":
		// Add MREMAP_FIXED flag, otherwise it produces non-deterministic results.
		flags := c.Args[3]
		if flags.Kind != ArgConst {
			panic("mremap flag arg is not const")
		}
		if flags.Val&MREMAP_MAYMOVE != 0 {
			flags.Val |= MREMAP_FIXED
		}
	case "mknod":
		mode := c.Args[1]
		if mode.Kind != ArgConst {
			panic("mknod mode is not const")
		}
		// Char and block devices read/write io ports, kernel memory and do other nasty things.
		if mode.Val != S_IFREG && mode.Val != S_IFIFO && mode.Val != S_IFSOCK {
			mode.Val = S_IFIFO
		}
	case "syslog":
		cmd := c.Args[0]
		// These disable console output, but we need it.
		if cmd.Val == SYSLOG_ACTION_CONSOLE_OFF || cmd.Val == SYSLOG_ACTION_CONSOLE_ON {
			cmd.Val = SYSLOG_ACTION_SIZE_UNREAD
		}
	case "exit", "exit_group":
		code := c.Args[0]
		// These codes are reserved by executor.
		if code.Val%128 == 67 || code.Val%128 == 68 {
			code.Val = 1
		}
	}
}
