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
	AllowColon   bool       // allow colon (int8:2) on fields?
	ResourceBase bool       // can be resource base type?
	OptArgs      int        // number of optional arguments in Args array
	Args         []namedArg // type arguments
	// CanBeArgRet returns if this type can be syscall argument/return (false if nil).
	CanBeArgRet func(comp *compiler, t *ast.Type) (bool, bool)
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
	Names      []string
	Kind       int  // int/ident/string
	AllowColon bool // allow colon (2:3)?
	// Check does custom verification of the arg (optional).
	Check       func(comp *compiler, t *ast.Type)
	CheckConsts func(comp *compiler, t *ast.Type)
}

type namedArg struct {
	Name string
	Type *typeArg
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
	AllowColon:   true,
	ResourceBase: true,
	OptArgs:      1,
	Args:         []namedArg{{"range", typeArgRange}},
	Check: func(comp *compiler, t *ast.Type, args []*ast.Type, base prog.IntTypeCommon) {
		typeArgBase.Type.Check(comp, t)
	},
	Gen: func(comp *compiler, t *ast.Type, args []*ast.Type, base prog.IntTypeCommon) prog.Type {
		size, be := comp.parseIntType(t.Ident)
		kind, rangeBegin, rangeEnd := prog.IntPlain, uint64(0), uint64(0)
		if len(args) > 0 {
			kind, rangeBegin, rangeEnd = prog.IntRange, args[0].Value, args[0].Value2
		}
		base.TypeSize = size
		return &prog.IntType{
			IntTypeCommon: genIntCommon(base.TypeCommon, t.Value2, be),
			Kind:          kind,
			RangeBegin:    rangeBegin,
			RangeEnd:      rangeEnd,
		}
	},
}

var typePtr = &typeDesc{
	Names:        []string{"ptr", "ptr64"},
	CanBeArgRet:  canBeArg,
	CanBeTypedef: true,
	Args:         []namedArg{{"direction", typeArgDir}, {"type", typeArgType}},
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
	Args:         []namedArg{{"type", typeArgType}, {"size", typeArgRange}},
	CheckConsts: func(comp *compiler, t *ast.Type, args []*ast.Type, base prog.IntTypeCommon) {
		if len(args) > 1 && args[1].Value == 0 && args[1].Value2 == 0 {
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
			return args[1].Value != args[1].Value2
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
			kind, begin, end = prog.ArrayRangeLen, args[1].Value, args[1].Value2
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
	Names:       []string{"len", "bytesize", "bytesize2", "bytesize4", "bytesize8", "bitsize"},
	CanBeArgRet: canBeArg,
	CantBeOpt:   true,
	NeedBase:    true,
	Args:        []namedArg{{"len target", typeArgLenTarget}},
	Gen: func(comp *compiler, t *ast.Type, args []*ast.Type, base prog.IntTypeCommon) prog.Type {
		var bitSize uint64
		switch t.Ident {
		case "bytesize":
			bitSize = 8
		case "bytesize2", "bytesize4", "bytesize8":
			byteSize, _ := strconv.ParseUint(t.Ident[8:], 10, 8)
			bitSize = byteSize * 8
		case "bitsize":
			bitSize = 1
		}
		return &prog.LenType{
			IntTypeCommon: base,
			Buf:           args[0].Ident,
			BitSize:       bitSize,
		}
	},
}

var typeConst = &typeDesc{
	Names:        []string{"const"},
	CanBeArgRet:  canBeArg,
	CanBeTypedef: true,
	CantBeOpt:    true,
	NeedBase:     true,
	Args:         []namedArg{{"value", typeArgInt}},
	Gen: func(comp *compiler, t *ast.Type, args []*ast.Type, base prog.IntTypeCommon) prog.Type {
		return &prog.ConstType{
			IntTypeCommon: base,
			Val:           args[0].Value,
		}
	},
}

var typeArgLenTarget = &typeArg{
	Kind: kindIdent,
}

var typeFlags = &typeDesc{
	Names:        []string{"flags"},
	CanBeArgRet:  canBeArg,
	CanBeTypedef: true,
	CantBeOpt:    true,
	NeedBase:     true,
	Args:         []namedArg{{"flags", typeArgFlags}},
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
		return &prog.FlagsType{
			IntTypeCommon: base,
			Vals:          genIntArray(f.Values),
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

var typeFileoff = &typeDesc{
	Names:       []string{"fileoff"},
	CanBeArgRet: canBeArg,
	CantBeOpt:   true,
	NeedBase:    true,
	Gen: func(comp *compiler, t *ast.Type, args []*ast.Type, base prog.IntTypeCommon) prog.Type {
		return &prog.IntType{
			IntTypeCommon: base,
			Kind:          prog.IntFileoff,
		}
	},
}

var typeVMA = &typeDesc{
	Names:       []string{"vma"},
	CanBeArgRet: canBeArg,
	OptArgs:     1,
	Args:        []namedArg{{"size range", typeArgRange}},
	Gen: func(comp *compiler, t *ast.Type, args []*ast.Type, base prog.IntTypeCommon) prog.Type {
		begin, end := uint64(0), uint64(0)
		if len(args) > 0 {
			begin, end = args[0].Value, args[0].Value2
		}
		base.TypeSize = comp.ptrSize
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
	Args:      []namedArg{{"csum target", typeArgLenTarget}, {"kind", typeArgCsumType}, {"proto", typeArgInt}},
	Check: func(comp *compiler, t *ast.Type, args []*ast.Type, base prog.IntTypeCommon) {
		if len(args) > 2 && genCsumKind(args[1]) != prog.CsumPseudo {
			comp.error(args[2].Pos, "only pseudo csum can have proto")
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
	Args:         []namedArg{{"range start", typeArgInt}, {"per-proc values", typeArgInt}},
	CheckConsts: func(comp *compiler, t *ast.Type, args []*ast.Type, base prog.IntTypeCommon) {
		start := args[0].Value
		perProc := args[1].Value
		if perProc == 0 {
			comp.error(args[1].Pos, "proc per-process values must not be 0")
			return
		}
		size := base.TypeSize * 8
		if size != 64 {
			const maxPids = 32 // executor knows about this constant (MAX_PIDS)
			if start >= 1<<size {
				comp.error(args[0].Pos, "values starting from %v overflow base type", start)
			} else if start+maxPids*perProc > 1<<size {
				comp.error(args[0].Pos, "values starting from %v with step %v overflow base type for %v procs",
					start, perProc, maxPids)
			}
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
	Args:      []namedArg{{"kind", typeArgTextType}},
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
	Names: []string{"x86_real", "x86_16", "x86_32", "x86_64", "arm64"},
}

func genTextType(t *ast.Type) prog.TextKind {
	switch t.Ident {
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

var typeBuffer = &typeDesc{
	Names:       []string{"buffer"},
	CanBeArgRet: canBeArg,
	Args:        []namedArg{{"direction", typeArgDir}},
	Gen: func(comp *compiler, t *ast.Type, args []*ast.Type, base prog.IntTypeCommon) prog.Type {
		base.TypeSize = comp.ptrSize
		common := genCommon("", "", 0, genDir(args[0]), false)
		// BufferBlobRand is always varlen.
		common.IsVarlen = true
		return &prog.PtrType{
			TypeCommon: base.TypeCommon,
			Type: &prog.BufferType{
				TypeCommon: common,
				Kind:       prog.BufferBlobRand,
			},
		}
	},
}

const (
	stringnoz = "stringnoz"
)

var typeString = &typeDesc{
	Names:        []string{"string", stringnoz},
	CanBeTypedef: true,
	OptArgs:      2,
	Args:         []namedArg{{"literal or flags", typeArgStringFlags}, {"size", typeArgInt}},
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

// typeArgType is used as placeholder for any type (e.g. ptr target type).
var typeArgType = &typeArg{}

var typeResource = &typeDesc{
	// No Names, but getTypeDesc knows how to match it.
	CanBeArgRet:  canBeArgRet,
	ResourceBase: true,
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
		base.TypeSize = comp.genType(baseType, "", prog.DirIn, false).Size()
		return &prog.ResourceType{
			TypeCommon: base.TypeCommon,
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
			if desc == nil || desc.CanBeArgRet == nil {
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

var typeArgRange = &typeArg{
	Kind:       kindInt,
	AllowColon: true,
	CheckConsts: func(comp *compiler, t *ast.Type) {
		if !t.HasColon {
			t.Value2 = t.Value
		}
		if t.Value > t.Value2 {
			comp.error(t.Pos, "bad int range [%v:%v]", t.Value, t.Value2)
		}
	},
}

// Base type of const/len/etc. Same as typeInt, but can't have range.
var typeArgBase = namedArg{
	Name: "base type",
	Type: &typeArg{
		Names:      []string{"int8", "int16", "int32", "int64", "int16be", "int32be", "int64be", "intptr"},
		AllowColon: true,
		Check: func(comp *compiler, t *ast.Type) {
			if t.HasColon {
				if t.Ident2 != "" {
					comp.error(t.Pos2, "literal const bitfield sizes are not supported")
					return
				}
				if t.Value2 == 0 {
					// This was not supported historically
					// and does not work the way C bitfields of size 0 work.
					// We could allow this, but then we need to make
					// this work the way C bitfields work.
					comp.error(t.Pos2, "bitfields of size 0 are not supported")
				}
				size, _ := comp.parseIntType(t.Ident)
				if t.Value2 > size*8 {
					comp.error(t.Pos2, "bitfield of size %v is too large for base type of size %v",
						t.Value2, size*8)
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

type filename string[filename]
filename = "", "."

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
		typeFileoff,
		typeVMA,
		typeCsum,
		typeProc,
		typeText,
		typeBuffer,
		typeString,
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
