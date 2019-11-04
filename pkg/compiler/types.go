// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package compiler

import (
	"fmt"
	"strconv"

	"github.com/google/syzkaller/pkg/ast"
	"github.com/google/syzkaller/prog"
)

// typeDesc is arg/field type descriptor.
type typeDesc struct {
	Names        []string
	CanBeTypedef bool       // can be type alias target?
	CantBeOpt    bool       // can't be marked as opt?
	NeedBase     bool       // needs base type when used as field?
	MaxColon     int        // max number of colons (int8:2) on fields
	OptArgs      int        // number of optional arguments in Args array
	Args         []namedArg // type arguments
	// CanBeArgRet returns if this type can be syscall argument/return (false if nil).
	CanBeArgRet func(comp *compiler, t *ast.Type) (bool, bool)
	// CanBeResourceBase returns if this type can be a resource base type (false if nil.
	CanBeResourceBase func(comp *compiler, t *ast.Type) bool
	// Check does custom verification of the type (optional, consts are not patched yet).
	Check func(comp *compiler, t *ast.Type, args []*ast.Type, base prog.IntTypeCommon)
	// CheckConsts does custom verification of the type (optional, consts are patched).
	CheckConsts func(comp *compiler, t *ast.Type, args []*ast.Type, base prog.IntTypeCommon)
	// Varlen returns if the type is variable-length (false if not set).
	Varlen func(comp *compiler, t *ast.Type, args []*ast.Type) bool
	// ZeroSize returns if the type has static 0 size (false if not set).
	ZeroSize func(comp *compiler, t *ast.Type, args []*ast.Type) bool
	// Gen generates corresponding prog.Type.
	Gen func(comp *compiler, t *ast.Type, args []*ast.Type, base prog.IntTypeCommon) prog.Type
}

// typeArg describes a type argument.
type typeArg struct {
	Names    []string
	Kind     int // int/ident/string
	MaxArgs  int // maxiumum number of subargs
	MaxColon int // max number of colons (2:3:4)
	// Check does custom verification of the arg (optional).
	Check       func(comp *compiler, t *ast.Type)
	CheckConsts func(comp *compiler, t *ast.Type)
}

type namedArg struct {
	Name  string
	Type  *typeArg
	IsArg bool // does not need base type
}

const (
	kindAny = iota
	kindInt
	kindIdent
	kindString
)

func canBeArg(comp *compiler, t *ast.Type) (bool, bool)    { return true, false }
func canBeArgRet(comp *compiler, t *ast.Type) (bool, bool) { return true, true }

var typeInt = &typeDesc{
	Names:        typeArgBase.Type.Names,
	CanBeArgRet:  canBeArg,
	CanBeTypedef: true,
	MaxColon:     1,
	OptArgs:      2,
	Args: []namedArg{
		{Name: "range", Type: typeArgIntRange},
		{Name: "align", Type: typeArgIntAlign},
	},
	CanBeResourceBase: func(comp *compiler, t *ast.Type) bool {
		// Big-endian resources can always be converted to non-big-endian,
		// since we will always revert bytes during copyout and during copyin,
		// so the result is the same as not reverting at all.
		// Big-endian resources are also not implemented and don't have tests.
		_, be := comp.parseIntType(t.Ident)
		return !be
	},
	Check: func(comp *compiler, t *ast.Type, args []*ast.Type, base prog.IntTypeCommon) {
		typeArgBase.Type.Check(comp, t)
		if len(args) > 0 && len(args[0].Colon) == 0 {
			comp.error(args[0].Pos, "first argument of %v needs to be a range", t.Ident)
		}
	},
	CheckConsts: func(comp *compiler, t *ast.Type, args []*ast.Type, base prog.IntTypeCommon) {
		if len(args) > 0 && len(args[0].Colon) != 0 {
			begin := args[0].Value
			end := args[0].Colon[0].Value
			size, _ := comp.parseIntType(t.Ident)
			size = size * 8
			if len(t.Colon) != 0 {
				// Integer is bitfield.
				size = t.Colon[0].Value
			}
			maxUInt := uint64(1<<size - 1)
			maxSInt := uint64(1<<(size-1) - 1)
			if len(args) > 1 && begin == 0 && int64(end) == -1 {
				// intN[0:-1, align] is a special value for 'all possible values', but aligned.
				end = maxUInt
			} else if end-begin > 1<<64-1<<32 {
				comp.error(args[0].Pos, "bad int range [%v:%v]", begin, end)
				return
			}
			// range is in [0:MAX_UINT]
			inUnsignedBase := begin <= maxUInt && end <= maxUInt
			// range is in [-MIN_SINT:MAX_SINT]
			inSignedBase := begin+maxSInt <= maxUInt && end+maxSInt <= maxUInt
			if size < 64 && !inUnsignedBase && !inSignedBase {
				comp.error(args[0].Colon[0].Pos, "int range [%v:%v] is too large for base type of size %v",
					begin, end, size)
				return
			}
			if len(args) > 1 && args[1].Value != 0 && (end-begin)/args[1].Value == 0 {
				comp.error(args[1].Pos, "int alignment %v is too large for range [%v:%v]",
					args[1].Value, begin, end)
			}
		}
	},
	Gen: func(comp *compiler, t *ast.Type, args []*ast.Type, base prog.IntTypeCommon) prog.Type {
		size, be := comp.parseIntType(t.Ident)
		kind, rangeBegin, rangeEnd, align := prog.IntPlain, uint64(0), uint64(0), uint64(0)
		if len(args) > 0 {
			rangeArg := args[0]
			kind, rangeBegin, rangeEnd = prog.IntRange, rangeArg.Value, rangeArg.Value
			if len(rangeArg.Colon) != 0 {
				rangeEnd = rangeArg.Colon[0].Value
			}
			if len(args) > 1 {
				align = args[1].Value
			}
		}
		var bitLen uint64
		if len(t.Colon) != 0 {
			bitLen = t.Colon[0].Value
		}
		base.TypeSize = size
		return &prog.IntType{
			IntTypeCommon: genIntCommon(base.TypeCommon, bitLen, be),
			Kind:          kind,
			RangeBegin:    rangeBegin,
			RangeEnd:      rangeEnd,
			Align:         align,
		}
	},
}

var typePtr = &typeDesc{
	Names:        []string{"ptr", "ptr64"},
	CanBeArgRet:  canBeArg,
	CanBeTypedef: true,
	Args:         []namedArg{{Name: "direction", Type: typeArgDir}, {Name: "type", Type: typeArgType}},
	Gen: func(comp *compiler, t *ast.Type, args []*ast.Type, base prog.IntTypeCommon) prog.Type {
		base.ArgDir = prog.DirIn // pointers are always in
		base.TypeSize = comp.ptrSize
		if t.Ident == "ptr64" {
			base.TypeSize = 8
		}
		return &prog.PtrType{
			TypeCommon: base.TypeCommon,
			Type:       comp.genType(args[1], "", genDir(args[0]), false),
		}
	},
}

var typeVoid = &typeDesc{
	Names:     []string{"void"},
	CantBeOpt: true,
	ZeroSize: func(comp *compiler, t *ast.Type, args []*ast.Type) bool {
		return true
	},
	Gen: func(comp *compiler, t *ast.Type, args []*ast.Type, base prog.IntTypeCommon) prog.Type {
		base.TypeSize = 0 // the only type with static size 0
		return &prog.BufferType{
			TypeCommon: base.TypeCommon,
			Kind:       prog.BufferBlobRange,
			RangeBegin: 0,
			RangeEnd:   0,
		}
	},
}

var typeArray = &typeDesc{
	Names:        []string{"array"},
	CanBeTypedef: true,
	CantBeOpt:    true,
	OptArgs:      1,
	Args:         []namedArg{{Name: "type", Type: typeArgType}, {Name: "size", Type: typeArgSizeRange}},
	CheckConsts: func(comp *compiler, t *ast.Type, args []*ast.Type, base prog.IntTypeCommon) {
		if len(args) > 1 && args[1].Value == 0 && (len(args[1].Colon) == 0 || args[1].Colon[0].Value == 0) {
			comp.error(args[1].Pos, "arrays of size 0 are not supported")
		}
	},
	Varlen: func(comp *compiler, t *ast.Type, args []*ast.Type) bool {
		if comp.isZeroSize(args[0]) {
			return false
		}
		if comp.isVarlen(args[0]) {
			return true
		}
		if len(args) > 1 {
			return len(args[1].Colon) != 0 && args[1].Value != args[1].Colon[0].Value
		}
		return true
	},
	ZeroSize: func(comp *compiler, t *ast.Type, args []*ast.Type) bool {
		return comp.isZeroSize(args[0])
	},
	Gen: func(comp *compiler, t *ast.Type, args []*ast.Type, base prog.IntTypeCommon) prog.Type {
		elemType := comp.genType(args[0], "", base.ArgDir, false)
		kind, begin, end := prog.ArrayRandLen, uint64(0), uint64(0)
		if len(args) > 1 {
			kind, begin, end = prog.ArrayRangeLen, args[1].Value, args[1].Value
			if len(args[1].Colon) != 0 {
				end = args[1].Colon[0].Value
			}
		}
		if it, ok := elemType.(*prog.IntType); ok && it.Kind == prog.IntPlain && it.TypeSize == 1 {
			// Special case: buffer is better mutated.
			bufKind := prog.BufferBlobRand
			base.TypeSize = 0
			if kind == prog.ArrayRangeLen {
				bufKind = prog.BufferBlobRange
				if begin == end {
					base.TypeSize = begin * elemType.Size()
				}
			}
			return &prog.BufferType{
				TypeCommon: base.TypeCommon,
				Kind:       bufKind,
				RangeBegin: begin,
				RangeEnd:   end,
			}
		}
		// TypeSize is assigned later in genStructDescs.
		return &prog.ArrayType{
			TypeCommon: base.TypeCommon,
			Type:       elemType,
			Kind:       kind,
			RangeBegin: begin,
			RangeEnd:   end,
		}
	},
}

var typeLen = &typeDesc{
	Names:       []string{"len", "bytesize", "bytesize2", "bytesize4", "bytesize8", "bitsize", "offsetof"},
	CanBeArgRet: canBeArg,
	CantBeOpt:   true,
	NeedBase:    true,
	Args:        []namedArg{{Name: "len target", Type: typeArgLenTarget}},
	Gen: func(comp *compiler, t *ast.Type, args []*ast.Type, base prog.IntTypeCommon) prog.Type {
		var bitSize uint64
		var offset bool
		switch t.Ident {
		case "bytesize":
			bitSize = 8
		case "bytesize2", "bytesize4", "bytesize8":
			byteSize, _ := strconv.ParseUint(t.Ident[8:], 10, 8)
			bitSize = byteSize * 8
		case "bitsize":
			bitSize = 1
		case "offsetof":
			bitSize = 8
			offset = true
		}
		path := []string{args[0].Ident}
		for _, col := range args[0].Colon {
			path = append(path, col.Ident)
		}
		return &prog.LenType{
			IntTypeCommon: base,
			Path:          path,
			BitSize:       bitSize,
			Offset:        offset,
		}
	},
}

var typeConst = &typeDesc{
	Names:        []string{"const"},
	CanBeArgRet:  canBeArg,
	CanBeTypedef: true,
	CantBeOpt:    true,
	NeedBase:     true,
	Args:         []namedArg{{Name: "value", Type: typeArgInt}},
	Gen: func(comp *compiler, t *ast.Type, args []*ast.Type, base prog.IntTypeCommon) prog.Type {
		return &prog.ConstType{
			IntTypeCommon: base,
			Val:           args[0].Value,
		}
	},
}

var typeArgLenTarget = &typeArg{
	Kind:     kindIdent,
	MaxColon: 10,
}

var typeFlags = &typeDesc{
	Names:        []string{"flags"},
	CanBeArgRet:  canBeArg,
	CanBeTypedef: true,
	CantBeOpt:    true,
	NeedBase:     true,
	Args:         []namedArg{{Name: "flags", Type: typeArgFlags}},
	Gen: func(comp *compiler, t *ast.Type, args []*ast.Type, base prog.IntTypeCommon) prog.Type {
		name := args[0].Ident
		base.TypeName = name
		f := comp.intFlags[name]
		if len(f.Values) == 0 {
			// We can get this if all values are unsupported consts.
			return &prog.IntType{
				IntTypeCommon: base,
				Kind:          prog.IntPlain,
			}
		}
		bitmask := true
		var combined uint64
		values := genIntArray(f.Values)
		for _, v := range values {
			if v&combined != 0 {
				bitmask = false
				break
			}
			combined |= v
		}
		return &prog.FlagsType{
			IntTypeCommon: base,
			Vals:          values,
			BitMask:       bitmask,
		}
	},
}

var typeArgFlags = &typeArg{
	Kind: kindIdent,
	Check: func(comp *compiler, t *ast.Type) {
		if comp.intFlags[t.Ident] == nil {
			comp.error(t.Pos, "unknown flags %v", t.Ident)
			return
		}
	},
}

var typeVMA = &typeDesc{
	Names:       []string{"vma", "vma64"},
	CanBeArgRet: canBeArg,
	OptArgs:     1,
	Args:        []namedArg{{Name: "size range", Type: typeArgSizeRange}},
	Gen: func(comp *compiler, t *ast.Type, args []*ast.Type, base prog.IntTypeCommon) prog.Type {
		var begin, end uint64
		if len(args) > 0 {
			begin, end = args[0].Value, args[0].Value
			if len(args[0].Colon) != 0 {
				end = args[0].Colon[0].Value
			}
		}
		base.TypeSize = comp.ptrSize
		if t.Ident == "vma64" {
			base.TypeSize = 8
		}
		return &prog.VmaType{
			TypeCommon: base.TypeCommon,
			RangeBegin: begin,
			RangeEnd:   end,
		}
	},
}

var typeCsum = &typeDesc{
	Names:     []string{"csum"},
	NeedBase:  true,
	CantBeOpt: true,
	OptArgs:   1,
	Args: []namedArg{
		{Name: "csum target", Type: typeArgLenTarget},
		{Name: "kind", Type: typeArgCsumType},
		{Name: "proto", Type: typeArgInt},
	},
	Check: func(comp *compiler, t *ast.Type, args []*ast.Type, base prog.IntTypeCommon) {
		if len(args) > 2 && genCsumKind(args[1]) != prog.CsumPseudo {
			comp.error(args[2].Pos, "only pseudo csum can have proto")
		}
		if len(args[0].Colon) != 0 {
			comp.error(args[0].Colon[0].Pos, "path expressions are not implemented for csum")
		}
	},
	Gen: func(comp *compiler, t *ast.Type, args []*ast.Type, base prog.IntTypeCommon) prog.Type {
		var proto uint64
		if len(args) > 2 {
			proto = args[2].Value
		}
		return &prog.CsumType{
			IntTypeCommon: base,
			Buf:           args[0].Ident,
			Kind:          genCsumKind(args[1]),
			Protocol:      proto,
		}
	},
}

var typeArgCsumType = &typeArg{
	Kind:  kindIdent,
	Names: []string{"inet", "pseudo"},
}

func genCsumKind(t *ast.Type) prog.CsumKind {
	switch t.Ident {
	case "inet":
		return prog.CsumInet
	case "pseudo":
		return prog.CsumPseudo
	default:
		panic(fmt.Sprintf("unknown csum kind %q", t.Ident))
	}
}

var typeProc = &typeDesc{
	Names:        []string{"proc"},
	CanBeArgRet:  canBeArg,
	CanBeTypedef: true,
	NeedBase:     true,
	Args: []namedArg{
		{Name: "range start", Type: typeArgInt},
		{Name: "per-proc values", Type: typeArgInt},
	},
	CheckConsts: func(comp *compiler, t *ast.Type, args []*ast.Type, base prog.IntTypeCommon) {
		start := args[0].Value
		perProc := args[1].Value
		if perProc == 0 {
			comp.error(args[1].Pos, "proc per-process values must not be 0")
			return
		}
		size := base.TypeSize * 8
		max := uint64(1) << size
		if size == 64 {
			max = ^uint64(0)
		}
		if start >= max {
			comp.error(args[0].Pos, "values starting from %v overflow base type", start)
		} else if perProc > (max-start)/prog.MaxPids {
			comp.error(args[0].Pos, "values starting from %v with step %v overflow base type for %v procs",
				start, perProc, prog.MaxPids)
		}
	},
	Gen: func(comp *compiler, t *ast.Type, args []*ast.Type, base prog.IntTypeCommon) prog.Type {
		return &prog.ProcType{
			IntTypeCommon: base,
			ValuesStart:   args[0].Value,
			ValuesPerProc: args[1].Value,
		}
	},
}

var typeText = &typeDesc{
	Names:     []string{"text"},
	CantBeOpt: true,
	Args:      []namedArg{{Name: "kind", Type: typeArgTextType}},
	Varlen: func(comp *compiler, t *ast.Type, args []*ast.Type) bool {
		return true
	},
	Gen: func(comp *compiler, t *ast.Type, args []*ast.Type, base prog.IntTypeCommon) prog.Type {
		base.TypeSize = 0
		return &prog.BufferType{
			TypeCommon: base.TypeCommon,
			Kind:       prog.BufferText,
			Text:       genTextType(args[0]),
		}
	},
}

var typeArgTextType = &typeArg{
	Kind:  kindIdent,
	Names: []string{"target", "x86_real", "x86_16", "x86_32", "x86_64", "arm64"},
}

func genTextType(t *ast.Type) prog.TextKind {
	switch t.Ident {
	case "target":
		return prog.TextTarget
	case "x86_real":
		return prog.TextX86Real
	case "x86_16":
		return prog.TextX86bit16
	case "x86_32":
		return prog.TextX86bit32
	case "x86_64":
		return prog.TextX86bit64
	case "arm64":
		return prog.TextArm64
	default:
		panic(fmt.Sprintf("unknown text type %q", t.Ident))
	}
}

const (
	stringnoz = "stringnoz"
)

var typeString = &typeDesc{
	Names:        []string{"string", stringnoz},
	CanBeTypedef: true,
	OptArgs:      2,
	Args: []namedArg{
		{Name: "literal or flags", Type: typeArgStringFlags},
		{Name: "size", Type: typeArgInt},
	},
	Check: func(comp *compiler, t *ast.Type, args []*ast.Type, base prog.IntTypeCommon) {
		if t.Ident == stringnoz && len(args) > 1 {
			comp.error(args[0].Pos, "fixed-size string can't be non-zero-terminated")
		}
	},
	CheckConsts: func(comp *compiler, t *ast.Type, args []*ast.Type, base prog.IntTypeCommon) {
		if len(args) > 1 {
			size := args[1].Value
			vals := comp.genStrings(t, args)
			for _, s := range vals {
				if uint64(len(s)) > size {
					comp.error(args[0].Pos, "string value %q exceeds buffer length %v",
						s, size)
				}
			}
		}
	},
	Varlen: func(comp *compiler, t *ast.Type, args []*ast.Type) bool {
		return comp.stringSize(t, args) == varlenString
	},
	ZeroSize: func(comp *compiler, t *ast.Type, args []*ast.Type) bool {
		return comp.stringSize(t, args) == 0
	},
	Gen: func(comp *compiler, t *ast.Type, args []*ast.Type, base prog.IntTypeCommon) prog.Type {
		if len(args) > 0 && args[0].Ident == "filename" {
			base.TypeName = "filename"
			base.TypeSize = 0
			if len(args) >= 2 {
				base.TypeSize = args[1].Value
			}
			return &prog.BufferType{
				TypeCommon: base.TypeCommon,
				Kind:       prog.BufferFilename,
				NoZ:        t.Ident == stringnoz,
			}
		}
		subkind := ""
		if len(args) > 0 && args[0].Ident != "" {
			subkind = args[0].Ident
		}
		vals := comp.genStrings(t, args)
		base.TypeSize = comp.stringSize(t, args)
		if base.TypeSize == varlenString {
			base.TypeSize = 0
		}
		return &prog.BufferType{
			TypeCommon: base.TypeCommon,
			Kind:       prog.BufferString,
			SubKind:    subkind,
			Values:     vals,
			NoZ:        t.Ident == stringnoz,
		}
	},
}

func (comp *compiler) genStrings(t *ast.Type, args []*ast.Type) []string {
	var vals []string
	if len(args) > 0 {
		if args[0].HasString {
			vals = append(vals, args[0].String)
		} else {
			vals = genStrArray(comp.strFlags[args[0].Ident].Values)
		}
	}
	if t.Ident == stringnoz {
		return vals
	}
	var size uint64
	if len(args) > 1 {
		size = args[1].Value
	}
	for i, s := range vals {
		s += "\x00"
		for uint64(len(s)) < size {
			s += "\x00"
		}
		vals[i] = s
	}
	return vals
}

const varlenString = ^uint64(0)

// stringSize returns static string size, or varlenString if it is variable length.
func (comp *compiler) stringSize(t *ast.Type, args []*ast.Type) uint64 {
	switch len(args) {
	case 0:
		return varlenString // a random string
	case 1:
		var z uint64
		if t.Ident == "string" {
			z = 1
		}
		if args[0].HasString {
			return uint64(len(args[0].String)) + z // string constant
		}
		size := varlenString
		for _, s := range comp.strFlags[args[0].Ident].Values {
			s1 := uint64(len(s.Value)) + z
			if size != varlenString && size != s1 {
				return varlenString // strings of different lengths
			}
			size = s1
		}
		return size // all strings have the same length
	case 2:
		return args[1].Value // have explicit length
	default:
		panic("too many string args")
	}
}

var typeArgStringFlags = &typeArg{
	Check: func(comp *compiler, t *ast.Type) {
		if !t.HasString && t.Ident == "" {
			comp.error(t.Pos, "unexpected int %v, string arg must be a string literal or string flags", t.Value)
			return
		}
		if t.Ident != "" && comp.strFlags[t.Ident] == nil {
			comp.error(t.Pos, "unknown string flags %v", t.Ident)
			return
		}
	},
}

var typeFmt = &typeDesc{
	Names:        []string{"fmt"},
	CanBeTypedef: true,
	CantBeOpt:    true,
	Args: []namedArg{
		{Name: "format", Type: typeFmtFormat},
		{Name: "value", Type: typeArgType, IsArg: true},
	},
	Check: func(comp *compiler, t *ast.Type, args []*ast.Type, base prog.IntTypeCommon) {
		desc, _, _ := comp.getArgsBase(args[1], "", base.TypeCommon.ArgDir, true)
		switch desc {
		case typeResource, typeInt, typeLen, typeFlags, typeProc:
		default:
			comp.error(t.Pos, "bad fmt value %v, expect an integer", args[1].Ident)
			return
		}
	},
	Gen: func(comp *compiler, t *ast.Type, args []*ast.Type, base prog.IntTypeCommon) prog.Type {
		var format prog.BinaryFormat
		var size uint64
		switch args[0].Ident {
		case "dec":
			format = prog.FormatStrDec
			size = 20
		case "hex":
			format = prog.FormatStrHex
			size = 18
		case "oct":
			format = prog.FormatStrOct
			size = 23
		}
		typ := comp.genType(args[1], "", base.TypeCommon.ArgDir, true)
		switch t := typ.(type) {
		case *prog.ResourceType:
			t.ArgFormat = format
			t.TypeSize = size
		case *prog.IntType:
			t.ArgFormat = format
			t.TypeSize = size
		case *prog.LenType:
			t.ArgFormat = format
			t.TypeSize = size
		case *prog.FlagsType:
			t.ArgFormat = format
			t.TypeSize = size
		case *prog.ProcType:
			t.ArgFormat = format
			t.TypeSize = size
		default:
			panic(fmt.Sprintf("unexpected type: %#v", typ))
		}
		return typ
	},
}

var typeFmtFormat = &typeArg{
	Names: []string{"dec", "hex", "oct"},
	Kind:  kindIdent,
}

// typeArgType is used as placeholder for any type (e.g. ptr target type).
var typeArgType = &typeArg{}

var typeResource = &typeDesc{
	// No Names, but getTypeDesc knows how to match it.
	CanBeArgRet: canBeArgRet,
	CanBeResourceBase: func(comp *compiler, t *ast.Type) bool {
		return true
	},
	// Gen is assigned below to avoid initialization loop.
}

func init() {
	typeResource.Gen = func(comp *compiler, t *ast.Type, args []*ast.Type, base prog.IntTypeCommon) prog.Type {
		// Find and generate base type to get its size.
		var baseType *ast.Type
		for r := comp.resources[t.Ident]; r != nil; {
			baseType = r.Base
			r = comp.resources[r.Base.Ident]
		}
		baseProgType := comp.genType(baseType, "", prog.DirIn, false)
		base.TypeSize = baseProgType.Size()
		return &prog.ResourceType{
			TypeCommon: base.TypeCommon,
			ArgFormat:  baseProgType.Format(),
		}
	}
}

var typeStruct = &typeDesc{
	// No Names, but getTypeDesc knows how to match it.
	CantBeOpt:    true,
	CanBeTypedef: true,
	// Varlen/Gen are assigned below due to initialization cycle.
}

func init() {
	typeStruct.CanBeArgRet = func(comp *compiler, t *ast.Type) (bool, bool) {
		// Allow unions to be arg if all options can be arg.
		s := comp.structs[t.Ident]
		if !s.IsUnion {
			return false, false
		}
		canBeArg := true
		for _, fld := range s.Fields {
			desc := comp.getTypeDesc(fld.Type)
			if desc == nil || desc == typeStruct || desc.CanBeArgRet == nil {
				return false, false
			}
			canBeArg1, _ := desc.CanBeArgRet(comp, fld.Type)
			if !canBeArg1 {
				canBeArg = false
			}
		}
		return canBeArg, false
	}
	typeStruct.Varlen = func(comp *compiler, t *ast.Type, args []*ast.Type) bool {
		return comp.structIsVarlen(t.Ident)
	}
	typeStruct.ZeroSize = func(comp *compiler, t *ast.Type, args []*ast.Type) bool {
		for _, fld := range comp.structs[t.Ident].Fields {
			if !comp.isZeroSize(fld.Type) {
				return false
			}
		}
		return true
	}
	typeStruct.Gen = func(comp *compiler, t *ast.Type, args []*ast.Type, base prog.IntTypeCommon) prog.Type {
		s := comp.structs[t.Ident]
		key := prog.StructKey{
			Name: t.Ident,
			Dir:  base.ArgDir,
		}
		desc := comp.structDescs[key]
		if desc == nil {
			// Need to assign to structDescs before calling genStructDesc to break recursion.
			desc = new(prog.StructDesc)
			comp.structDescs[key] = desc
			comp.genStructDesc(desc, s, base.ArgDir, typeStruct.Varlen(comp, t, args))
		}
		if s.IsUnion {
			return &prog.UnionType{
				Key:        key,
				FldName:    base.FldName,
				StructDesc: desc,
			}
		}
		return &prog.StructType{
			Key:        key,
			FldName:    base.FldName,
			StructDesc: desc,
		}
	}
}

var typeTypedef = &typeDesc{
	// No Names, but getTypeDesc knows how to match it.
	Check: func(comp *compiler, t *ast.Type, args []*ast.Type, base prog.IntTypeCommon) {
		panic("must not be called")
	},
}

var typeArgDir = &typeArg{
	Kind:  kindIdent,
	Names: []string{"in", "out", "inout"},
}

func genDir(t *ast.Type) prog.Dir {
	switch t.Ident {
	case "in":
		return prog.DirIn
	case "out":
		return prog.DirOut
	case "inout":
		return prog.DirInOut
	default:
		panic(fmt.Sprintf("unknown direction %q", t.Ident))
	}
}

var typeArgInt = &typeArg{
	Kind: kindInt,
}

var typeArgIntRange = &typeArg{
	Kind:     kindInt,
	MaxColon: 1,
}

var typeArgIntAlign = &typeArg{
	Kind:     kindInt,
	MaxColon: 0,
	CheckConsts: func(comp *compiler, t *ast.Type) {
		if t.Value <= 1 {
			comp.error(t.Pos, "bad int alignment %v", t.Value)
		}
	},
}

// Size of array and vma's.
var typeArgSizeRange = &typeArg{
	Kind:     kindInt,
	MaxColon: 1,
	CheckConsts: func(comp *compiler, t *ast.Type) {
		end := t.Value
		if len(t.Colon) != 0 {
			end = t.Colon[0].Value
		}
		const maxVal = 1e6
		if t.Value > end || t.Value > maxVal || end > maxVal {
			comp.error(t.Pos, "bad size range [%v:%v]", t.Value, end)
		}
	},
}

// Base type of const/len/etc. Same as typeInt, but can't have range.
var typeArgBase = namedArg{
	Name: "base type",
	Type: &typeArg{
		Names:    []string{"int8", "int16", "int32", "int64", "int16be", "int32be", "int64be", "intptr"},
		MaxColon: 1,
		Check: func(comp *compiler, t *ast.Type) {
			if len(t.Colon) != 0 {
				col := t.Colon[0]
				if col.Ident != "" {
					comp.error(col.Pos, "literal const bitfield sizes are not supported")
					return
				}
				if col.Value == 0 {
					// This was not supported historically
					// and does not work the way C bitfields of size 0 work.
					// We could allow this, but then we need to make
					// this work the way C bitfields work.
					comp.error(col.Pos, "bitfields of size 0 are not supported")
				}
				size, _ := comp.parseIntType(t.Ident)
				if col.Value > size*8 {
					comp.error(col.Pos, "bitfield of size %v is too large for base type of size %v",
						col.Value, size*8)
				}
			}
		},
	},
}

var (
	builtinTypes    = make(map[string]*typeDesc)
	builtinTypedefs = make(map[string]*ast.TypeDef)
	builtinStrFlags = make(map[string]*ast.StrFlags)

	// To avoid weird cases like ptr[in, in] and ptr[out, opt].
	reservedName = map[string]bool{
		"opt":   true,
		"in":    true,
		"out":   true,
		"inout": true,
	}
)

const builtinDefs = `
type bool8 int8[0:1]
type bool16 int16[0:1]
type bool32 int32[0:1]
type bool64 int64[0:1]
type boolptr intptr[0:1]

type fileoff[BASE] BASE

type filename string[filename]
filename = "", "."

type buffer[DIR] ptr[DIR, array[int8]]

type optional[T] [
	val	T
	void	void
] [varlen]
`

func init() {
	builtins := []*typeDesc{
		typeInt,
		typePtr,
		typeVoid,
		typeArray,
		typeLen,
		typeConst,
		typeFlags,
		typeVMA,
		typeCsum,
		typeProc,
		typeText,
		typeString,
		typeFmt,
	}
	for _, desc := range builtins {
		for _, name := range desc.Names {
			if builtinTypes[name] != nil {
				panic(fmt.Sprintf("duplicate builtin type %q", name))
			}
			builtinTypes[name] = desc
		}
	}
	builtinDesc := ast.Parse([]byte(builtinDefs), "builtins", func(pos ast.Pos, msg string) {
		panic(fmt.Sprintf("failed to parse builtins: %v: %v", pos, msg))
	})
	for _, decl := range builtinDesc.Nodes {
		switch n := decl.(type) {
		case *ast.TypeDef:
			builtinTypedefs[n.Name.Name] = n
		case *ast.StrFlags:
			builtinStrFlags[n.Name.Name] = n
		case *ast.NewLine:
		default:
			panic(fmt.Sprintf("unexpected node in builtins: %#v", n))
		}
	}
}
