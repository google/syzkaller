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
	ct        *ChoiceTable
	files     map[string]bool
	resources map[string][]*Arg
	strings   map[string]bool
	pages     [maxPages]bool
}

// analyze analyzes the program p up to but not including call c.
func analyze(ct *ChoiceTable, p *Prog, c *Call) *state {
	s := newState(ct)
	for _, c1 := range p.Calls {
		if c1 == c {
			break
		}
		s.analyze(c1)
	}
	return s
}

func newState(ct *ChoiceTable) *state {
	s := &state{
		ct:        ct,
		files:     make(map[string]bool),
		resources: make(map[string][]*Arg),
		strings:   make(map[string]bool),
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
				s.resources[typ.Desc.Name] = append(s.resources[typ.Desc.Name], arg)
				// TODO: negative PIDs and add them as well (that's process groups).
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
		if flags, fd := c.Args[4], c.Args[3]; flags.Val&sys.MAP_ANONYMOUS == 0 && fd.Kind == ArgConst && fd.Val == sys.InvalidFD {
			break
		}
		s.addressable(c.Args[0], length, true)
	case "munmap":
		s.addressable(c.Args[0], c.Args[1], false)
	case "mremap":
		s.addressable(c.Args[4], c.Args[2], true)
	case "io_submit":
		if arr := c.Args[2].Res; arr != nil {
			for _, ptr := range arr.Inner {
				if ptr.Kind == ArgPointer {
					if ptr.Res != nil && ptr.Res.Type.Name() == "iocb" {
						s.resources["iocbptr"] = append(s.resources["iocbptr"], ptr)
					}
				}
			}
		}
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

func foreachSubargImpl(arg *Arg, parent *[]*Arg, f func(arg, base *Arg, parent *[]*Arg)) {
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
		if arg.Kind == ArgUnion {
			rec(arg.Option, base, parent)
		}
	}
	rec(arg, nil, parent)
}

func foreachSubarg(arg *Arg, f func(arg, base *Arg, parent *[]*Arg)) {
	foreachSubargImpl(arg, nil, f)
}

func foreachArgArray(args *[]*Arg, ret *Arg, f func(arg, base *Arg, parent *[]*Arg)) {
	for _, arg := range *args {
		foreachSubargImpl(arg, args, f)
	}
	if ret != nil {
		foreachSubargImpl(ret, nil, f)
	}
}

func foreachArg(c *Call, f func(arg, base *Arg, parent *[]*Arg)) {
	foreachArgArray(&c.Args, nil, f)
}

func assignTypeAndDir(c *Call) error {
	var rec func(arg *Arg, typ sys.Type, dir ArgDir) error
	rec = func(arg *Arg, typ sys.Type, dir ArgDir) error {
		if arg.Call != nil && arg.Call != c {
			panic(fmt.Sprintf("different call is already assigned: %p %p %v %v", arg.Call, c, arg.Call.Meta.Name, c.Meta.Name))
		}
		arg.Call = c
		if arg.Type != nil && arg.Type.Name() != typ.Name() {
			panic("different type is already assigned: " + arg.Type.Name() + " vs " + typ.Name())
		}
		arg.Type = typ
		switch arg.Kind {
		case ArgPointer:
			arg.Dir = DirIn
			switch typ1 := typ.(type) {
			case sys.PtrType:
				if arg.Res != nil {
					if err := rec(arg.Res, typ1.Type, ArgDir(typ1.Dir)); err != nil {
						return err
					}
				}
			}
		case ArgGroup:
			arg.Dir = dir
			switch typ1 := typ.(type) {
			case sys.StructType:
				if len(arg.Inner) != len(typ1.Fields) {
					return fmt.Errorf("wrong struct field count: %v, want %v", len(arg.Inner), len(typ1.Fields))
				}
				for i, arg1 := range arg.Inner {
					if err := rec(arg1, typ1.Fields[i], dir); err != nil {
						return err
					}
				}
			case sys.ArrayType:
				for _, arg1 := range arg.Inner {
					if err := rec(arg1, typ1.Type, dir); err != nil {
						return err
					}
				}
			}
		case ArgUnion:
			arg.Dir = dir
			if err := rec(arg.Option, arg.OptionType, dir); err != nil {
				return err
			}
		default:
			arg.Dir = dir
		}
		return nil
	}
	for i, arg := range c.Args {
		if c.Meta == nil {
			panic("nil meta")
		}
		if err := rec(arg, c.Meta.Args[i], DirIn); err != nil {
			return err
		}
	}
	if c.Ret == nil {
		c.Ret = returnArg()
		c.Ret.Call = c
		c.Ret.Type = c.Meta.Ret
		c.Ret.Dir = DirOut
	}
	return nil
}

func sanitizeCall(c *Call) {
	switch c.Meta.CallName {
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
		flags.Val |= sys.MAP_FIXED
	case "mremap":
		// Add MREMAP_FIXED flag, otherwise it produces non-deterministic results.
		flags := c.Args[3]
		if flags.Kind != ArgConst {
			panic("mremap flag arg is not const")
		}
		if flags.Val&sys.MREMAP_MAYMOVE != 0 {
			flags.Val |= sys.MREMAP_FIXED
		}
	case "mknod":
		mode := c.Args[1]
		if mode.Kind != ArgConst {
			panic("mknod mode is not const")
		}
		// Char and block devices read/write io ports, kernel memory and do other nasty things.
		// TODO: not required if executor drops privileges.
		if mode.Val != sys.S_IFREG && mode.Val != sys.S_IFIFO && mode.Val != sys.S_IFSOCK {
			mode.Val = sys.S_IFIFO
		}
	case "syslog":
		cmd := c.Args[0]
		// These disable console output, but we need it.
		if cmd.Val == sys.SYSLOG_ACTION_CONSOLE_OFF || cmd.Val == sys.SYSLOG_ACTION_CONSOLE_ON {
			cmd.Val = sys.SYSLOG_ACTION_SIZE_UNREAD
		}
	case "ioctl":
		cmd := c.Args[1]
		// Freeze kills machine. Though, it is an interesting functions,
		// so we need to test it somehow.
		// TODO: not required if executor drops privileges.
		if uint32(cmd.Val) == sys.FIFREEZE {
			cmd.Val = sys.FITHAW
		}
	case "ptrace":
		// PTRACE_TRACEME leads to unkillable processes, see:
		// https://groups.google.com/forum/#!topic/syzkaller/uGzwvhlCXAw
		if c.Args[0].Val == sys.PTRACE_TRACEME {
			c.Args[0].Val = ^uintptr(0)
		}
	case "exit", "exit_group":
		code := c.Args[0]
		// These codes are reserved by executor.
		if code.Val%128 == 67 || code.Val%128 == 68 {
			code.Val = 1
		}
	}
}
