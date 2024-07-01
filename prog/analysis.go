// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Conservative resource-related analysis of programs.
// The analysis figures out what files descriptors are [potentially] opened
// at a particular point in program, what pages are [potentially] mapped,
// what files were already referenced in calls, etc.

package prog

import (
	"bytes"
	"fmt"
	"io"

	"github.com/google/syzkaller/pkg/image"
)

type state struct {
	target    *Target
	ct        *ChoiceTable
	corpus    []*Prog
	files     map[string]bool
	resources map[string][]*ResultArg
	strings   map[string]bool
	ma        *memAlloc
	va        *vmaAlloc
}

// analyze analyzes the program p up to but not including call c.
func analyze(ct *ChoiceTable, corpus []*Prog, p *Prog, c *Call) *state {
	s := newState(p.Target, ct, corpus)
	resources := true
	for _, c1 := range p.Calls {
		if c1 == c {
			resources = false
		}
		s.analyzeImpl(c1, resources)
	}
	return s
}

func newState(target *Target, ct *ChoiceTable, corpus []*Prog) *state {
	s := &state{
		target:    target,
		ct:        ct,
		corpus:    corpus,
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
			case a.IsSpecial():
			case a.VmaSize != 0:
				s.va.noteAlloc(a.Address/s.target.PageSize, a.VmaSize/s.target.PageSize)
			case a.Res != nil:
				s.ma.noteAlloc(a.Address, a.Res.Size())
			}
		}
		switch typ := arg.Type().(type) {
		case *ResourceType:
			a := arg.(*ResultArg)
			if resources && a.Dir() != DirIn {
				s.resources[typ.Desc.Name] = append(s.resources[typ.Desc.Name], a)
				// TODO: negative PIDs and add them as well (that's process groups).
			}
		case *BufferType:
			a := arg.(*DataArg)
			if a.Dir() != DirOut && len(a.Data()) != 0 &&
				(typ.Kind == BufferString || typ.Kind == BufferFilename) {
				val := string(a.Data())
				// Remove trailing zero padding.
				for len(val) >= 2 && val[len(val)-1] == 0 && val[len(val)-2] == 0 {
					val = val[:len(val)-1]
				}
				switch typ.Kind {
				case BufferString:
					s.strings[val] = true
				case BufferFilename:
					if len(val) < 3 || escapingFilename(val) {
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

type parentStack []Arg

func allocStack() parentStack {
	// Let's save some allocations during stack traversal.
	return make([]Arg, 0, 4)
}

func pushStack(ps parentStack, a Arg) parentStack {
	return append(ps, a)
}

func popStack(ps parentStack) (parentStack, Arg) {
	if len(ps) > 0 {
		return ps[:len(ps)-1], ps[len(ps)-1]
	}
	return ps, nil
}

type ArgCtx struct {
	Parent      *[]Arg      // GroupArg.Inner (for structs) or Call.Args containing this arg.
	Fields      []Field     // Fields of the parent struct/syscall.
	Field       *Field      // Syscall field for this arg, nil if there it's not a field.
	Base        *PointerArg // Pointer to the base of the heap object containing this arg.
	Offset      uint64      // Offset of this arg from the base.
	Stop        bool        // If set by the callback, subargs of this arg are not visited.
	parentStack parentStack // Struct and union arguments by which the argument can be reached.
}

func ForeachSubArg(arg Arg, f func(Arg, *ArgCtx)) {
	foreachArgImpl(arg, nil, &ArgCtx{}, f)
}

func foreachSubArgWithStack(arg Arg, f func(Arg, *ArgCtx)) {
	foreachArgImpl(arg, nil, &ArgCtx{parentStack: allocStack()}, f)
}

func ForeachArg(c *Call, f func(Arg, *ArgCtx)) {
	ctx := &ArgCtx{}
	if c.Ret != nil {
		foreachArgImpl(c.Ret, nil, ctx, f)
	}
	ctx.Parent = &c.Args
	ctx.Fields = c.Meta.Args
	for i, arg := range c.Args {
		foreachArgImpl(arg, &ctx.Fields[i], ctx, f)
	}
}

func foreachArgImpl(arg Arg, field *Field, ctx *ArgCtx, f func(Arg, *ArgCtx)) {
	ctx0 := *ctx
	defer func() { *ctx = ctx0 }()

	if ctx.parentStack != nil {
		switch arg.Type().(type) {
		case *StructType, *UnionType:
			ctx.parentStack = pushStack(ctx.parentStack, arg)
		}
	}
	ctx.Field = field
	f(arg, ctx)
	if ctx.Stop {
		return
	}
	switch a := arg.(type) {
	case *GroupArg:
		overlayField := 0
		if typ, ok := a.Type().(*StructType); ok {
			ctx.Parent = &a.Inner
			ctx.Fields = typ.Fields
			overlayField = typ.OverlayField
		}
		var totalSize uint64
		for i, arg1 := range a.Inner {
			if i == overlayField {
				ctx.Offset = ctx0.Offset
			}
			foreachArgImpl(arg1, nil, ctx, f)
			size := arg1.Size()
			ctx.Offset += size
			if totalSize < ctx.Offset {
				totalSize = ctx.Offset - ctx0.Offset
			}
		}
		if debug {
			claimedSize := a.Size()
			varlen := a.Type().Varlen()
			if varlen && totalSize > claimedSize || !varlen && totalSize != claimedSize {
				panic(fmt.Sprintf("bad group arg size %v, should be <= %v for %#v type %#v",
					totalSize, claimedSize, a, a.Type().Name()))
			}
		}
	case *PointerArg:
		if a.Res != nil {
			ctx.Base = a
			ctx.Offset = 0
			foreachArgImpl(a.Res, nil, ctx, f)
		}
	case *UnionArg:
		foreachArgImpl(a.Option, nil, ctx, f)
	}
}

type RequiredFeatures struct {
	Bitmasks       bool
	Csums          bool
	FaultInjection bool
	Async          bool
}

func (p *Prog) RequiredFeatures() RequiredFeatures {
	features := RequiredFeatures{}
	for _, c := range p.Calls {
		ForeachArg(c, func(arg Arg, _ *ArgCtx) {
			if a, ok := arg.(*ConstArg); ok {
				if a.Type().BitfieldOffset() != 0 || a.Type().BitfieldLength() != 0 {
					features.Bitmasks = true
				}
			}
			if _, ok := arg.Type().(*CsumType); ok {
				features.Csums = true
			}
		})
		if c.Props.FailNth > 0 {
			features.FaultInjection = true
		}
		if c.Props.Async {
			features.Async = true
		}
	}
	return features
}

type CallFlags int

const (
	CallExecuted CallFlags = 1 << iota // was started at all
	CallFinished                       // finished executing (rather than blocked forever)
	CallBlocked                        // finished but blocked during execution
)

type CallInfo struct {
	Flags  CallFlags
	Errno  int
	Signal []uint64
}

const (
	fallbackSignalErrno = iota
	fallbackSignalErrnoBlocked
	fallbackSignalCtor
	fallbackSignalFlags
	// This allows us to have 2M syscalls and leaves 8 bits for 256 errno values.
	// Linux currently have 133 errno's. Larger errno values will be truncated,
	// which is acceptable for fallback coverage.
	fallbackCallMask = 0x1fffff
)

func (p *Prog) FallbackSignal(info []CallInfo) {
	resources := make(map[*ResultArg]*Call)
	for i, c := range p.Calls {
		inf := &info[i]
		if inf.Flags&CallExecuted == 0 {
			continue
		}
		id := c.Meta.ID
		typ := fallbackSignalErrno
		if inf.Flags&CallFinished != 0 && inf.Flags&CallBlocked != 0 {
			typ = fallbackSignalErrnoBlocked
		}
		inf.Signal = append(inf.Signal, encodeFallbackSignal(typ, id, inf.Errno))
		if c.Meta.Attrs.BreaksReturns {
			break
		}
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
		flags := 0
		for _, arg := range c.Args {
			flags = extractArgSignal(arg, id, flags, inf, resources)
		}
		if flags != 0 {
			inf.Signal = append(inf.Signal,
				encodeFallbackSignal(fallbackSignalFlags, id, flags))
		}
	}
}

func extractArgSignal(arg Arg, callID, flags int, inf *CallInfo, resources map[*ResultArg]*Call) int {
	switch a := arg.(type) {
	case *ResultArg:
		flags <<= 1
		if a.Res != nil {
			ctor := resources[a.Res]
			if ctor != nil {
				inf.Signal = append(inf.Signal,
					encodeFallbackSignal(fallbackSignalCtor, callID, ctor.Meta.ID))
			}
		} else {
			if a.Val != a.Type().(*ResourceType).SpecialValues()[0] {
				flags |= 1
			}
		}
	case *ConstArg:
		const width = 3
		flags <<= width
		switch typ := a.Type().(type) {
		case *FlagsType:
			if typ.BitMask {
				for i, v := range typ.Vals {
					if a.Val&v != 0 {
						flags ^= 1 << (uint(i) % width)
					}
				}
			} else {
				for i, v := range typ.Vals {
					if a.Val == v {
						flags |= i % (1 << width)
						break
					}
				}
			}
		case *LenType:
			flags <<= 1
			if a.Val == 0 {
				flags |= 1
			}
		}
	case *PointerArg:
		flags <<= 1
		if a.IsSpecial() {
			flags |= 1
		}
	}
	return flags
}

func DecodeFallbackSignal(s uint64) (callID, errno int) {
	typ, id, aux := decodeFallbackSignal(s)
	switch typ {
	case fallbackSignalErrno, fallbackSignalErrnoBlocked:
		return id, aux
	case fallbackSignalCtor, fallbackSignalFlags:
		return id, 0
	default:
		panic(fmt.Sprintf("bad fallback signal type %v", typ))
	}
}

func encodeFallbackSignal(typ, id, aux int) uint64 {
	checkMaxCallID(id)
	if typ & ^7 != 0 {
		panic(fmt.Sprintf("bad fallback signal type %v", typ))
	}
	return uint64(typ) | uint64(id&fallbackCallMask)<<3 | uint64(aux)<<24
}

func decodeFallbackSignal(s uint64) (typ, id, aux int) {
	return int(s & 7), int((s >> 3) & fallbackCallMask), int(s >> 24)
}

func checkMaxCallID(id int) {
	if id & ^fallbackCallMask != 0 {
		panic(fmt.Sprintf("too many syscalls, have %v, max supported %v", id, fallbackCallMask+1))
	}
}

type AssetType int

const (
	MountInRepro AssetType = iota
)

func (p *Prog) ForEachAsset(cb func(name string, typ AssetType, r io.Reader)) {
	for id, c := range p.Calls {
		ForeachArg(c, func(arg Arg, _ *ArgCtx) {
			a, ok := arg.(*DataArg)
			if !ok || a.Type().(*BufferType).Kind != BufferCompressed {
				return
			}
			data, dtor := image.MustDecompress(a.Data())
			defer dtor()
			if len(data) == 0 {
				return
			}
			cb(fmt.Sprintf("mount_%v", id), MountInRepro, bytes.NewReader(data))
		})
	}
}

func (p *Prog) ContainsAny() bool {
	for _, c := range p.Calls {
		if p.Target.CallContainsAny(c) {
			return true
		}
	}
	return false
}
