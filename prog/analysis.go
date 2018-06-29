// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Conservative resource-related analysis of programs.
// The analysis figures out what files descriptors are [potentially] opened
// at a particular point in program, what pages are [potentially] mapped,
// what files were already referenced in calls, etc.

package prog

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
)

type state struct {
	target    *Target
	ct        *ChoiceTable
	files     map[string]bool
	resources map[string][]*ResultArg
	strings   map[string]bool
	ma        *memAlloc
	va        *vmaAlloc
}

// analyze analyzes the program p up to but not including call c.
func analyze(ct *ChoiceTable, p *Prog, c *Call) *state {
	s := newState(p.Target, ct)
	resources := true
	for _, c1 := range p.Calls {
		if c1 == c {
			resources = false
		}
		s.analyzeImpl(c1, resources)
	}
	return s
}

func newState(target *Target, ct *ChoiceTable) *state {
	s := &state{
		target:    target,
		ct:        ct,
		files:     make(map[string]bool),
		resources: make(map[string][]*ResultArg),
		strings:   make(map[string]bool),
		ma:        newMemAlloc(target.NumPages * target.PageSize),
		va:        newVmaAlloc(target.NumPages),
	}
	return s
}

func (s *state) analyze(c *Call) {
	s.analyzeImpl(c, true)
}

func (s *state) analyzeImpl(c *Call, resources bool) {
	ForeachArg(c, func(arg Arg, _ *ArgCtx) {
		switch a := arg.(type) {
		case *PointerArg:
			switch {
			case a.IsNull():
			case a.VmaSize != 0:
				s.va.noteAlloc(a.Address/s.target.PageSize, a.VmaSize/s.target.PageSize)
			default:
				s.ma.noteAlloc(a.Address, a.Res.Size())
			}
		}
		switch typ := arg.Type().(type) {
		case *ResourceType:
			a := arg.(*ResultArg)
			if resources && typ.Dir() != DirIn {
				s.resources[typ.Desc.Name] = append(s.resources[typ.Desc.Name], a)
				// TODO: negative PIDs and add them as well (that's process groups).
			}
		case *BufferType:
			a := arg.(*DataArg)
			if typ.Dir() != DirOut && len(a.Data()) != 0 {
				val := string(a.Data())
				// Remove trailing zero padding.
				for len(val) >= 2 && val[len(val)-1] == 0 && val[len(val)-2] == 0 {
					val = val[:len(val)-1]
				}
				switch typ.Kind {
				case BufferString:
					s.strings[val] = true
				case BufferFilename:
					if len(val) < 3 {
						// This is not our file, probalby one of specialFiles.
						return
					}
					if val[len(val)-1] == 0 {
						val = val[:len(val)-1]
					}
					s.files[val] = true
				}
			}
		}
	})
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
		claimedSize := a.Size()
		varlen := a.Type().Varlen()
		if varlen && totalSize > claimedSize || !varlen && totalSize != claimedSize {
			panic(fmt.Sprintf("bad group arg size %v, should be <= %v for %#v type %#v",
				totalSize, claimedSize, a, a.Type()))
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

func RequiredFeatures(p *Prog) (bitmasks, csums bool) {
	for _, c := range p.Calls {
		ForeachArg(c, func(arg Arg, _ *ArgCtx) {
			if a, ok := arg.(*ConstArg); ok {
				if a.Type().BitfieldOffset() != 0 || a.Type().BitfieldLength() != 0 {
					bitmasks = true
				}
			}
			if _, ok := arg.Type().(*CsumType); ok {
				csums = true
			}
		})
	}
	return
}

type CallInfo struct {
	Executed bool
	Errno    int
	Signal   []uint32
}

const (
	fallbackSignalErrno = iota
	fallbackSignalCtor
	fallbackSignalFlags
	fallbackCallMask = 0x3fff
)

func (p *Prog) FallbackSignal(info []CallInfo) {
	resources := make(map[*ResultArg]*Call)
	for i, c := range p.Calls {
		inf := &info[i]
		if !inf.Executed {
			continue
		}
		id := c.Meta.ID
		inf.Signal = append(inf.Signal, encodeFallbackSignal(fallbackSignalErrno, id, inf.Errno))
		if inf.Errno != 0 {
			continue
		}
		ForeachArg(c, func(arg Arg, _ *ArgCtx) {
			if a, ok := arg.(*ResultArg); ok {
				resources[a] = c
			}
		})
		// Specifically look only at top-level arguments,
		// deeper arguments can produce too much false signal.
		flags := new(bytes.Buffer)
		for _, arg := range c.Args {
			switch a := arg.(type) {
			case *ResultArg:
				if a.Res != nil {
					ctor := resources[a.Res]
					if ctor != nil {
						inf.Signal = append(inf.Signal,
							encodeFallbackSignal(fallbackSignalCtor, id, ctor.Meta.ID))
					}
				} else {
					for _, v := range a.Type().(*ResourceType).SpecialValues() {
						if a.Val == v {
							binary.Write(flags, binary.LittleEndian, v)
						}
					}
				}
			case *ConstArg:
				switch typ := a.Type().(type) {
				case *FlagsType:
					var mask uint64
					for _, v := range typ.Vals {
						mask |= v
					}
					binary.Write(flags, binary.LittleEndian, a.Val&mask)
				case *LenType:
					if a.Val == 0 {
						flags.WriteByte(0x42)
					}
				}
			case *PointerArg:
				if a.IsNull() {
					flags.WriteByte(0x43)
				}
			}
			if flags.Len() != 0 {
				hash := sha1.Sum(flags.Bytes())
				inf.Signal = append(inf.Signal,
					encodeFallbackSignal(fallbackSignalFlags, id, int(hash[0])))
			}
		}
	}
}

func DecodeFallbackSignal(s uint32) (callID, errno int) {
	typ, id, aux := decodeFallbackSignal(s)
	switch typ {
	case fallbackSignalErrno:
		return id, aux
	case fallbackSignalCtor, fallbackSignalFlags:
		return id, 0
	default:
		panic(fmt.Sprintf("bad fallback signal type %v", typ))
	}
}

func encodeFallbackSignal(typ, id, aux int) uint32 {
	if typ & ^3 != 0 {
		panic(fmt.Sprintf("bad fallback signal type %v", typ))
	}
	if id & ^fallbackCallMask != 0 {
		panic(fmt.Sprintf("bad call id in fallback signal %v", id))
	}
	return uint32(typ) | uint32(id&0x3fff)<<2 | uint32(aux)<<16
}

func decodeFallbackSignal(s uint32) (typ, id, aux int) {
	return int(s & 3), int((s >> 2) & fallbackCallMask), int(s >> 16)
}
