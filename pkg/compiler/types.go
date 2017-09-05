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
	CanBeArg     bool       // can be argument of syscall?
	CantBeOpt    bool       // can't be marked as opt?
	CantBeRet    bool       // can't be syscall return (directly or indirectly)?
	NeedBase     bool       // needs base type when used as field?
	AllowColon   bool       // allow colon (int8:2) on fields?
	ResourceBase bool       // can be resource base type?
	OptArgs      int        // number of optional arguments in Args array
	Args         []namedArg // type arguments
	// Check does custom verification of the type (optional).
	Check func(comp *compiler, t *ast.Type, args []*ast.Type, base prog.IntTypeCommon)
	// Varlen returns if the type is variable-length (false if not set).
	Varlen func(comp *compiler, t *ast.Type, args []*ast.Type, base prog.IntTypeCommon) bool
	// Gen generates corresponding prog.Type.
	Gen func(comp *compiler, t *ast.Type, args []*ast.Type, base prog.IntTypeCommon) prog.Type
}

// typeArg describes a type argument.
type typeArg struct {
	Names      []string
	Kind       int  // int/ident/string
	AllowColon bool // allow colon (2:3)?
	// Check does custom verification of the arg (optional).
	Check func(comp *compiler, t *ast.Type)
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

var typeInt = &typeDesc{
	Names:        []string{"int8", "int16", "int32", "int64", "int16be", "int32be", "int64be", "intptr"},
	CanBeArg:     true,
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
	Names:    []string{"ptr", "ptr64"},
	CanBeArg: true,
	Args:     []namedArg{{"direction", typeArgDir}, {"type", typeArgType}},
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

var typeArray = &typeDesc{
	Names:     []string{"array"},
	CantBeOpt: true,
	OptArgs:   1,
	Args:      []namedArg{{"type", typeArgType}, {"size", typeArgRange}},
	Check: func(comp *compiler, t *ast.Type, args []*ast.Type, base prog.IntTypeCommon) {
		if len(args) > 1 && args[1].Value == 0 && args[1].Value2 == 0 {
			// This is the only case that can yield 0 static type size.
			comp.error(args[1].Pos, "arrays of size 0 are not supported")
		}
	},
	Varlen: func(comp *compiler, t *ast.Type, args []*ast.Type, base prog.IntTypeCommon) bool {
		if comp.isVarlen(args[0]) {
			return true
		}
		if len(args) > 1 {
			return args[1].Value != args[1].Value2
		}
		return true
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
	Names:     []string{"len", "bytesize", "bytesize2", "bytesize4", "bytesize8"},
	CanBeArg:  true,
	CantBeOpt: true,
	CantBeRet: true,
	NeedBase:  true,
	Args:      []namedArg{{"len target", typeArgLenTarget}},
	Gen: func(comp *compiler, t *ast.Type, args []*ast.Type, base prog.IntTypeCommon) prog.Type {
		var byteSize uint64
		switch t.Ident {
		case "bytesize":
			byteSize = 1
		case "bytesize2", "bytesize4", "bytesize8":
			byteSize, _ = strconv.ParseUint(t.Ident[8:], 10, 8)
		}
		return &prog.LenType{
			IntTypeCommon: base,
			Buf:           args[0].Ident,
			ByteSize:      byteSize,
		}
	},
}

var typeConst = &typeDesc{
	Names:     []string{"const"},
	CanBeArg:  true,
	CantBeOpt: true,
	NeedBase:  true,
	Args:      []namedArg{{"value", typeArgInt}},
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
	Names:     []string{"flags"},
	CanBeArg:  true,
	CantBeOpt: true,
	NeedBase:  true,
	Args:      []namedArg{{"flags", typeArgFlags}},
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

var typeFilename = &typeDesc{
	Names:     []string{"filename"},
	CantBeOpt: true,
	Varlen: func(comp *compiler, t *ast.Type, args []*ast.Type, base prog.IntTypeCommon) bool {
		return true
	},
	Gen: func(comp *compiler, t *ast.Type, args []*ast.Type, base prog.IntTypeCommon) prog.Type {
		base.TypeSize = 0
		return &prog.BufferType{
			TypeCommon: base.TypeCommon,
			Kind:       prog.BufferFilename,
		}
	},
}

var typeFileoff = &typeDesc{
	Names:     []string{"fileoff"},
	CanBeArg:  true,
	CantBeOpt: true,
	NeedBase:  true,
	Gen: func(comp *compiler, t *ast.Type, args []*ast.Type, base prog.IntTypeCommon) prog.Type {
		return &prog.IntType{
			IntTypeCommon: base,
			Kind:          prog.IntFileoff,
		}
	},
}

var typeVMA = &typeDesc{
	Names:    []string{"vma"},
	CanBeArg: true,
	OptArgs:  1,
	Args:     []namedArg{{"size range", typeArgRange}},
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

// TODO(dvyukov): perhaps, we need something like typedefs for such types.
// So that users can introduce them as necessary without modifying compiler:
// type signalno int32[0:64]
var typeSignalno = &typeDesc{
	Names:     []string{"signalno"},
	CanBeArg:  true,
	CantBeOpt: true,
	Gen: func(comp *compiler, t *ast.Type, args []*ast.Type, base prog.IntTypeCommon) prog.Type {
		base.TypeSize = 4
		return &prog.IntType{
			IntTypeCommon: base,
			Kind:          prog.IntRange,
			RangeBegin:    0,
			RangeEnd:      65,
		}
	},
}

var typeCsum = &typeDesc{
	Names:     []string{"csum"},
	NeedBase:  true,
	CantBeOpt: true,
	CantBeRet: true,
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
	Names:     []string{"proc"},
	CanBeArg:  true,
	CantBeOpt: true,
	NeedBase:  true,
	Args:      []namedArg{{"range start", typeArgInt}, {"per-proc values", typeArgInt}},
	Check: func(comp *compiler, t *ast.Type, args []*ast.Type, base prog.IntTypeCommon) {
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
			} else if start+maxPids*perProc >= 1<<size {
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
	Varlen: func(comp *compiler, t *ast.Type, args []*ast.Type, base prog.IntTypeCommon) bool {
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
		return prog.Text_x86_real
	case "x86_16":
		return prog.Text_x86_16
	case "x86_32":
		return prog.Text_x86_32
	case "x86_64":
		return prog.Text_x86_64
	case "arm64":
		return prog.Text_arm64
	default:
		panic(fmt.Sprintf("unknown text type %q", t.Ident))
	}
}

var typeBuffer = &typeDesc{
	Names:    []string{"buffer"},
	CanBeArg: true,
	Args:     []namedArg{{"direction", typeArgDir}},
	Gen: func(comp *compiler, t *ast.Type, args []*ast.Type, base prog.IntTypeCommon) prog.Type {
		base.TypeSize = comp.ptrSize
		return &prog.PtrType{
			TypeCommon: base.TypeCommon,
			Type: &prog.BufferType{
				// BufferBlobRand is always varlen.
				TypeCommon: genCommon("", "", 0, genDir(args[0]), false),
				Kind:       prog.BufferBlobRand,
			},
		}
	},
}

var typeString = &typeDesc{
	Names:   []string{"string"},
	OptArgs: 2,
	Args:    []namedArg{{"literal or flags", typeArgStringFlags}, {"size", typeArgInt}},
	Check: func(comp *compiler, t *ast.Type, args []*ast.Type, base prog.IntTypeCommon) {
		if len(args) > 1 {
			size := args[1].Value
			vals := []string{args[0].String}
			if args[0].Ident != "" {
				vals = genStrArray(comp.strFlags[args[0].Ident].Values)
			}
			for _, s := range vals {
				s += "\x00"
				if uint64(len(s)) > size {
					comp.error(args[0].Pos, "string value %q exceeds buffer length %v",
						s, size)
				}
			}
		}
	},
	Varlen: func(comp *compiler, t *ast.Type, args []*ast.Type, base prog.IntTypeCommon) bool {
		return comp.stringSize(args) == 0
	},
	Gen: func(comp *compiler, t *ast.Type, args []*ast.Type, base prog.IntTypeCommon) prog.Type {
		subkind := ""
		var vals []string
		if len(args) > 0 {
			if args[0].String != "" {
				vals = append(vals, args[0].String)
			} else {
				subkind = args[0].Ident
				vals = genStrArray(comp.strFlags[subkind].Values)
			}
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
		base.TypeSize = comp.stringSize(args)
		return &prog.BufferType{
			TypeCommon: base.TypeCommon,
			Kind:       prog.BufferString,
			SubKind:    subkind,
			Values:     vals,
		}
	},
}

// stringSize returns static string size, or 0 if it is variable length.
func (comp *compiler) stringSize(args []*ast.Type) uint64 {
	switch len(args) {
	case 0:
		return 0 // a random string
	case 1:
		if args[0].String != "" {
			return uint64(len(args[0].String)) + 1 // string constant
		}
		var size uint64
		for _, s := range comp.strFlags[args[0].Ident].Values {
			s1 := uint64(len(s.Value)) + 1
			if size != 0 && size != s1 {
				return 0 // strings of different lengths
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
		if t.String == "" && t.Ident == "" {
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
var typeArgType = &typeArg{
	Check: func(comp *compiler, t *ast.Type) {
		panic("must not be called")
	},
}

var typeResource = &typeDesc{
	// No Names, but compiler knows how to match it.
	CanBeArg:     true,
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
	// No Names, but compiler knows how to match it.
	CantBeOpt: true,
	// Varlen/Gen are assigned below due to initialization cycle.
}

func init() {
	typeStruct.Varlen = func(comp *compiler, t *ast.Type, args []*ast.Type, base prog.IntTypeCommon) bool {
		return comp.isStructVarlen(t.Ident)
	}
	typeStruct.Gen = func(comp *compiler, t *ast.Type, args []*ast.Type, base prog.IntTypeCommon) prog.Type {
		s := comp.structs[t.Ident]
		key := prog.StructKey{t.Ident, base.ArgDir}
		desc := comp.structDescs[key]
		if desc == nil {
			// Need to assign to structDescs before calling genStructDesc to break recursion.
			desc = new(prog.StructDesc)
			comp.structDescs[key] = desc
			comp.genStructDesc(desc, s, base.ArgDir)
		}
		if s.IsUnion {
			return &prog.UnionType{
				Key:        key,
				FldName:    base.FldName,
				StructDesc: desc,
			}
		} else {
			return &prog.StructType{
				Key:        key,
				FldName:    base.FldName,
				StructDesc: desc,
			}
		}
	}
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
	Check: func(comp *compiler, t *ast.Type) {
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
	builtinTypes = make(map[string]*typeDesc)

	// To avoid weird cases like ptr[in, in] and ptr[out, opt].
	reservedName = map[string]bool{
		"opt":   true,
		"in":    true,
		"out":   true,
		"inout": true,
	}
)

func init() {
	builtins := []*typeDesc{
		typeInt,
		typePtr,
		typeArray,
		typeLen,
		typeConst,
		typeFlags,
		typeFilename,
		typeFileoff,
		typeVMA,
		typeSignalno,
		typeCsum,
		typeProc,
		typeText,
		typeBuffer,
		typeString,
		typeResource,
		typeStruct,
	}
	for _, desc := range builtins {
		for _, name := range desc.Names {
			if builtinTypes[name] != nil {
				panic(fmt.Sprintf("duplicate builtin type %q", name))
			}
			builtinTypes[name] = desc
		}
	}
}
