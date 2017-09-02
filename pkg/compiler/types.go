// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package compiler

import (
	"fmt"
	"strconv"

	"github.com/google/syzkaller/pkg/ast"
	"github.com/google/syzkaller/sys"
)

// typeDesc is arg/field type descriptor.
type typeDesc struct {
	Names        []string
	CanBeArg     bool       // can be argument of syscall?
	CantBeOpt    bool       // can't be marked as opt?
	NeedBase     bool       // needs base type when used as field?
	AllowColon   bool       // allow colon (int8:2)?
	ResourceBase bool       // can be resource base type?
	OptArgs      int        // number of optional arguments in Args array
	Args         []namedArg // type arguments
	// Check does custom verification of the type (optional).
	Check func(comp *compiler, t *ast.Type, args []*ast.Type, base sys.IntTypeCommon)
	// Gen generates corresponding sys.Type.
	Gen func(comp *compiler, t *ast.Type, args []*ast.Type, base sys.IntTypeCommon) sys.Type
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
	Check: func(comp *compiler, t *ast.Type, args []*ast.Type, base sys.IntTypeCommon) {
		typeArgBase.Type.Check(comp, t)
	},
	Gen: func(comp *compiler, t *ast.Type, args []*ast.Type, base sys.IntTypeCommon) sys.Type {
		size, be := comp.parseIntType(t.Ident)
		kind, rangeBegin, rangeEnd := sys.IntPlain, uint64(0), uint64(0)
		if len(args) > 0 {
			kind, rangeBegin, rangeEnd = sys.IntRange, args[0].Value, args[0].Value2
		}
		return &sys.IntType{
			IntTypeCommon: genIntCommon(base.TypeCommon, size, t.Value2, be),
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
	Gen: func(comp *compiler, t *ast.Type, args []*ast.Type, base sys.IntTypeCommon) sys.Type {
		base.ArgDir = sys.DirIn // pointers are always in
		size := comp.ptrSize
		if t.Ident == "ptr64" {
			size = 8
		}
		return &sys.PtrType{
			TypeCommon: base.TypeCommon,
			TypeSize:   size,
			Type:       comp.genType(args[1], "", genDir(args[0]), false),
		}
	},
}

var typeArray = &typeDesc{
	Names:     []string{"array"},
	CantBeOpt: true,
	OptArgs:   1,
	Args:      []namedArg{{"type", typeArgType}, {"size", typeArgRange}},
	Gen: func(comp *compiler, t *ast.Type, args []*ast.Type, base sys.IntTypeCommon) sys.Type {
		elemType := comp.genType(args[0], "", base.ArgDir, false)
		kind, begin, end := sys.ArrayRandLen, uint64(0), uint64(0)
		if len(args) > 1 {
			kind, begin, end = sys.ArrayRangeLen, args[1].Value, args[1].Value2
		}
		if it, ok := elemType.(*sys.IntType); ok && it.TypeSize == 1 {
			// Special case: buffer is better mutated.
			bufKind := sys.BufferBlobRand
			if kind == sys.ArrayRangeLen {
				bufKind = sys.BufferBlobRange
			}
			return &sys.BufferType{
				TypeCommon: base.TypeCommon,
				Kind:       bufKind,
				RangeBegin: begin,
				RangeEnd:   end,
			}
		}
		return &sys.ArrayType{
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
	NeedBase:  true,
	Args:      []namedArg{{"len target", typeArgLenTarget}},
	Check: func(comp *compiler, t *ast.Type, args []*ast.Type, base sys.IntTypeCommon) {
		// TODO(dvyukov): check args[0].Ident as len target
	},
	Gen: func(comp *compiler, t *ast.Type, args []*ast.Type, base sys.IntTypeCommon) sys.Type {
		var byteSize uint64
		switch t.Ident {
		case "bytesize":
			byteSize = 1
		case "bytesize2", "bytesize4", "bytesize8":
			byteSize, _ = strconv.ParseUint(t.Ident[8:], 10, 8)
		}
		return &sys.LenType{
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
	Gen: func(comp *compiler, t *ast.Type, args []*ast.Type, base sys.IntTypeCommon) sys.Type {
		return &sys.ConstType{
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
	Gen: func(comp *compiler, t *ast.Type, args []*ast.Type, base sys.IntTypeCommon) sys.Type {
		name := args[0].Ident
		base.TypeName = name
		f := comp.intFlags[name]
		if len(f.Values) == 0 {
			// We can get this if all values are unsupported consts.
			return &sys.IntType{
				IntTypeCommon: base,
			}
		}
		return &sys.FlagsType{
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
	Gen: func(comp *compiler, t *ast.Type, args []*ast.Type, base sys.IntTypeCommon) sys.Type {
		return &sys.BufferType{
			TypeCommon: base.TypeCommon,
			Kind:       sys.BufferFilename,
		}
	},
}

var typeFileoff = &typeDesc{
	Names:     []string{"fileoff"},
	CanBeArg:  true,
	CantBeOpt: true,
	NeedBase:  true,
	Gen: func(comp *compiler, t *ast.Type, args []*ast.Type, base sys.IntTypeCommon) sys.Type {
		return &sys.IntType{
			IntTypeCommon: base,
			Kind:          sys.IntFileoff,
		}
	},
}

var typeVMA = &typeDesc{
	Names:    []string{"vma"},
	CanBeArg: true,
	OptArgs:  1,
	Args:     []namedArg{{"size range", typeArgRange}},
	Gen: func(comp *compiler, t *ast.Type, args []*ast.Type, base sys.IntTypeCommon) sys.Type {
		begin, end := uint64(0), uint64(0)
		if len(args) > 0 {
			begin, end = args[0].Value, args[0].Value2
		}
		return &sys.VmaType{
			TypeCommon: base.TypeCommon,
			RangeBegin: begin,
			RangeEnd:   end,
		}
	},
}

// TODO(dvyukov): replace with type with int flags.
// Or, perhaps, we need something like typedefs:
// typedef int32[0:32] signalno
var typeSignalno = &typeDesc{
	Names:     []string{"signalno"},
	CanBeArg:  true,
	CantBeOpt: true,
	Gen: func(comp *compiler, t *ast.Type, args []*ast.Type, base sys.IntTypeCommon) sys.Type {
		base.TypeSize = 4
		return &sys.IntType{
			IntTypeCommon: base,
			Kind:          sys.IntSignalno,
		}
	},
}

var typeCsum = &typeDesc{
	Names:     []string{"csum"},
	NeedBase:  true,
	CantBeOpt: true,
	OptArgs:   1,
	Args:      []namedArg{{"csum target", typeArgLenTarget}, {"kind", typeArgCsumType}, {"proto", typeArgInt}},
	Check: func(comp *compiler, t *ast.Type, args []*ast.Type, base sys.IntTypeCommon) {
		if len(args) > 2 && genCsumKind(args[1]) != sys.CsumPseudo {
			comp.error(args[2].Pos, "only pseudo csum can have proto")
		}
		// TODO(dvyukov): check args[0].Ident as len target
	},
	Gen: func(comp *compiler, t *ast.Type, args []*ast.Type, base sys.IntTypeCommon) sys.Type {
		var proto uint64
		if len(args) > 2 {
			proto = args[2].Value
		}
		return &sys.CsumType{
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

func genCsumKind(t *ast.Type) sys.CsumKind {
	switch t.Ident {
	case "inet":
		return sys.CsumInet
	case "pseudo":
		return sys.CsumPseudo
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
	Check: func(comp *compiler, t *ast.Type, args []*ast.Type, base sys.IntTypeCommon) {
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
	Gen: func(comp *compiler, t *ast.Type, args []*ast.Type, base sys.IntTypeCommon) sys.Type {
		return &sys.ProcType{
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
	Gen: func(comp *compiler, t *ast.Type, args []*ast.Type, base sys.IntTypeCommon) sys.Type {
		return &sys.BufferType{
			TypeCommon: base.TypeCommon,
			Kind:       sys.BufferText,
			Text:       genTextType(args[0]),
		}
	},
}

var typeArgTextType = &typeArg{
	Kind:  kindIdent,
	Names: []string{"x86_real", "x86_16", "x86_32", "x86_64", "arm64"},
}

func genTextType(t *ast.Type) sys.TextKind {
	switch t.Ident {
	case "x86_real":
		return sys.Text_x86_real
	case "x86_16":
		return sys.Text_x86_16
	case "x86_32":
		return sys.Text_x86_32
	case "x86_64":
		return sys.Text_x86_64
	case "arm64":
		return sys.Text_arm64
	default:
		panic(fmt.Sprintf("unknown text type %q", t.Ident))
	}
}

var typeBuffer = &typeDesc{
	Names:    []string{"buffer"},
	CanBeArg: true,
	Args:     []namedArg{{"direction", typeArgDir}},
	Gen: func(comp *compiler, t *ast.Type, args []*ast.Type, base sys.IntTypeCommon) sys.Type {
		return &sys.PtrType{
			TypeCommon: base.TypeCommon,
			TypeSize:   comp.ptrSize,
			Type: &sys.BufferType{
				TypeCommon: genCommon("", "", genDir(args[0]), false),
				Kind:       sys.BufferBlobRand,
			},
		}
	},
}

var typeString = &typeDesc{
	Names:   []string{"string"},
	OptArgs: 2,
	Args:    []namedArg{{"literal or flags", typeArgStringFlags}, {"size", typeArgInt}},
	Check: func(comp *compiler, t *ast.Type, args []*ast.Type, base sys.IntTypeCommon) {
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
	Gen: func(comp *compiler, t *ast.Type, args []*ast.Type, base sys.IntTypeCommon) sys.Type {
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
		for _, s := range vals {
			if size != 0 && size != uint64(len(s)) {
				size = 0
				break
			}
			size = uint64(len(s))
		}
		return &sys.BufferType{
			TypeCommon: base.TypeCommon,
			Kind:       sys.BufferString,
			SubKind:    subkind,
			Values:     vals,
			Length:     size,
		}
	},
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
	Gen: func(comp *compiler, t *ast.Type, args []*ast.Type, base sys.IntTypeCommon) sys.Type {
		return &sys.ResourceType{
			TypeCommon: base.TypeCommon,
		}
	},
}

var typeStruct = &typeDesc{
	// No Names, but compiler knows how to match it.
	CantBeOpt: true,
	Gen: func(comp *compiler, t *ast.Type, args []*ast.Type, base sys.IntTypeCommon) sys.Type {
		s := comp.structs[base.TypeName]
		comp.structUses[sys.StructKey{base.TypeName, base.ArgDir}] = s
		if s.IsUnion {
			return &sys.UnionType{
				TypeCommon: base.TypeCommon,
				IsVarlen:   comp.parseUnionAttrs(s),
			}
		} else {
			packed, align := comp.parseStructAttrs(s)
			return &sys.StructType{
				TypeCommon: base.TypeCommon,
				IsPacked:   packed,
				AlignAttr:  align,
			}
		}
	},
}

var typeArgDir = &typeArg{
	Kind:  kindIdent,
	Names: []string{"in", "out", "inout"},
}

func genDir(t *ast.Type) sys.Dir {
	switch t.Ident {
	case "in":
		return sys.DirIn
	case "out":
		return sys.DirOut
	case "inout":
		return sys.DirInOut
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
			size, _ := comp.parseIntType(t.Ident)
			if t.Value2 > size*8 {
				comp.error(t.Pos2, "bitfield of size %v is too large for base type of size %v",
					t.Value2, size*8)
			}
		},
	},
}

var builtinTypes = make(map[string]*typeDesc)

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
