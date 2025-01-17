// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package declextract

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"slices"
)

type Output struct {
	Functions       []*Function      `json:"functions,omitempty"`
	Consts          []*ConstInfo     `json:"consts,omitempty"`
	Enums           []*Enum          `json:"enums,omitempty"`
	Structs         []*Struct        `json:"structs,omitempty"`
	Syscalls        []*Syscall       `json:"syscalls,omitempty"`
	FileOps         []*FileOps       `json:"file_ops,omitempty"`
	Ioctls          []*Ioctl         `json:"ioctls,omitempty"`
	IouringOps      []*IouringOp     `json:"iouring_ops,omitempty"`
	NetlinkFamilies []*NetlinkFamily `json:"netlink_families,omitempty"`
	NetlinkPolicies []*NetlinkPolicy `json:"netlink_policies,omitempty"`
}

type Function struct {
	Name     string `json:"name,omitempty"`
	File     string `json:"file,omitempty"`
	IsStatic bool   `json:"is_static,omitempty"`
	// Information about function scopes. There is a global scope (with Arg=-1),
	// and scope for each switch case on the function argument.
	Scopes []*FunctionScope `json:"scopes,omitempty"`

	callers int
	calls   []*Function
	facts   map[string]*typingNode
}

type FunctionScope struct {
	// The function argument index that is switched on (-1 for the global scope).
	Arg int `json:"arg"`
	// The set of case values for this scope.
	// It's empt for the global scope for the default case scope.
	Values []string      `json:"values,omitempty"`
	LOC    int           `json:"loc,omitempty"`
	Calls  []string      `json:"calls,omitempty"`
	Facts  []*TypingFact `json:"facts,omitempty"`
}

type ConstInfo struct {
	Name     string `json:"name"`
	Filename string `json:"filename"`
	Value    int64  `json:"value"`
}

type Field struct {
	Name        string `json:"name,omitempty"`
	IsAnonymous bool   `json:"is_anonymous,omitempty"`
	BitWidth    int    `json:"bit_width,omitempty"`
	CountedBy   int    `json:"counted_by,omitempty"`
	Type        *Type  `json:"type,omitempty"`

	syzType string
}

type Syscall struct {
	Func       string   `json:"func,omitempty"`
	Args       []*Field `json:"args,omitempty"`
	SourceFile string   `json:"source_file,omitempty"`

	returnType string
}

// FileOps describes one file_operations variable.
type FileOps struct {
	Name string `json:"name,omitempty"`
	// Names of callback functions.
	Open       string `json:"open,omitempty"`
	Read       string `json:"read,omitempty"`
	Write      string `json:"write,omitempty"`
	Mmap       string `json:"mmap,omitempty"`
	Ioctl      string `json:"ioctl,omitempty"`
	SourceFile string `json:"source_file,omitempty"`
}

type Ioctl struct {
	// Literal name of the command (e.g. KCOV_REMOTE_ENABLE).
	Name string `json:"name,omitempty"`
	Type *Type  `json:"type,omitempty"`
}

type IouringOp struct {
	Name       string `json:"name,omitempty"`
	Func       string `json:"func,omitempty"`
	SourceFile string `json:"source_file,omitempty"`
}

type NetlinkFamily struct {
	Name       string       `json:"name,omitempty"`
	Ops        []*NetlinkOp `json:"ops,omitempty"`
	SourceFile string       `json:"source_file,omitempty"`
}

type NetlinkPolicy struct {
	Name  string         `json:"name,omitempty"`
	Attrs []*NetlinkAttr `json:"attrs,omitempty"`
}

type NetlinkOp struct {
	Name   string `json:"name,omitempty"`
	Func   string `json:"func,omitempty"`
	Access string `json:"access,omitempty"`
	Policy string `json:"policy,omitempty"`
}

type NetlinkAttr struct {
	Name         string `json:"name,omitempty"`
	Kind         string `json:"kind,omitempty"`
	MaxSize      int    `json:"max_size,omitempty"`
	NestedPolicy string `json:"nested_policy,omitempty"`
	Elem         *Type  `json:"elem,omitempty"`
}

type Struct struct {
	Name      string   `json:"name,omitempty"`
	ByteSize  int      `json:"byte_size,omitempty"`
	Align     int      `json:"align,omitempty"`
	IsUnion   bool     `json:"is_union,omitempty"`
	IsPacked  bool     `json:"is_packed,omitempty"`
	AlignAttr int      `json:"align_attr,omitempty"`
	Fields    []*Field `json:"fields,omitempty"`
}

type Enum struct {
	Name   string   `json:"name,omitempty"`
	Values []string `json:"values,omitempty"`
}

type Type struct {
	Int    *IntType    `json:"int,omitempty"`
	Ptr    *PtrType    `json:"ptr,omitempty"`
	Array  *ArrayType  `json:"array,omitempty"`
	Buffer *BufferType `json:"buffer,omitempty"`
	Struct string      `json:"struct,omitempty"`
}

type IntType struct {
	ByteSize int    `json:"byte_size,omitempty"`
	MinValue int    `json:"min_value,omitempty"`
	MaxValue int    `json:"max_value,omitempty"`
	IsConst  bool   `json:"is_const,omitempty"`
	Name     string `json:"name,omitempty"`
	Base     string `json:"base,omitempty"`
	Enum     string `json:"enum,omitempty"`

	isBigEndian bool
}

type PtrType struct {
	Elem    *Type `json:"elem,omitempty"`
	IsConst bool  `json:"is_const,omitempty"`
}

type ArrayType struct {
	Elem        *Type `json:"elem,omitempty"`
	MinSize     int   `json:"min_size,omitempty"`
	MaxSize     int   `json:"max_size,omitempty"`
	Align       int   `json:"align,omitempty"`
	IsConstSize bool  `json:"is_const_size,omitempty"`
}

type BufferType struct {
	MinSize         int  `json:"min_size,omitempty"`
	MaxSize         int  `json:"max_size,omitempty"`
	IsString        bool `json:"is_string,omitempty"`
	IsNonTerminated bool `json:"is_non_terminated,omitempty"`
}

type TypingFact struct {
	Src *TypingEntity `json:"src,omitempty"`
	Dst *TypingEntity `json:"dst,omitempty"`
}

type TypingEntity struct {
	Return     *EntityReturn     `json:"return,omitempty"`
	Argument   *EntityArgument   `json:"argument,omitempty"`
	Field      *EntityField      `json:"field,omitempty"`
	Local      *EntityLocal      `json:"local,omitempty"`
	GlobalAddr *EntityGlobalAddr `json:"global_addr,omitempty"`
}

type EntityReturn struct {
	Func string `json:"func,omitempty"`
}

type EntityArgument struct {
	Func string `json:"func,omitempty"`
	Arg  int    `json:"arg"`
}

type EntityField struct {
	Struct string `json:"struct"`
	Field  string `json:"field"`
}

type EntityLocal struct {
	Name string `json:"name"`
}

type EntityGlobalAddr struct {
	Name string
}

func (out *Output) Merge(other *Output) {
	out.Functions = append(out.Functions, other.Functions...)
	out.Consts = append(out.Consts, other.Consts...)
	out.Enums = append(out.Enums, other.Enums...)
	out.Structs = append(out.Structs, other.Structs...)
	out.Syscalls = append(out.Syscalls, other.Syscalls...)
	out.FileOps = append(out.FileOps, other.FileOps...)
	out.Ioctls = append(out.Ioctls, other.Ioctls...)
	out.IouringOps = append(out.IouringOps, other.IouringOps...)
	out.NetlinkFamilies = append(out.NetlinkFamilies, other.NetlinkFamilies...)
	out.NetlinkPolicies = append(out.NetlinkPolicies, other.NetlinkPolicies...)
}

func (out *Output) SortAndDedup() {
	out.Functions = sortAndDedupSlice(out.Functions)
	out.Consts = sortAndDedupSlice(out.Consts)
	out.Enums = sortAndDedupSlice(out.Enums)
	out.Structs = sortAndDedupSlice(out.Structs)
	out.Syscalls = sortAndDedupSlice(out.Syscalls)
	out.FileOps = sortAndDedupSlice(out.FileOps)
	out.Ioctls = sortAndDedupSlice(out.Ioctls)
	out.IouringOps = sortAndDedupSlice(out.IouringOps)
	out.NetlinkFamilies = sortAndDedupSlice(out.NetlinkFamilies)
	out.NetlinkPolicies = sortAndDedupSlice(out.NetlinkPolicies)
}

// SetSoureFile attaches the source file to the entities that need it.
// The clang tool could do it, but it looks easier to do it here.
func (out *Output) SetSourceFile(file string, updatePath func(string) string) {
	for _, fn := range out.Functions {
		fn.File = updatePath(fn.File)
	}
	for _, ci := range out.Consts {
		ci.Filename = updatePath(ci.Filename)
	}
	for _, call := range out.Syscalls {
		call.SourceFile = file
	}
	for _, fops := range out.FileOps {
		fops.SourceFile = file
	}
	for _, fam := range out.NetlinkFamilies {
		fam.SourceFile = file
	}
	for _, op := range out.IouringOps {
		op.SourceFile = file
	}
}

func sortAndDedupSlice[Slice ~[]E, E comparable](s Slice) Slice {
	dedup := make(map[[sha256.Size]byte]E)
	text := make(map[E][]byte)
	for _, e := range s {
		t, _ := json.Marshal(e)
		dedup[sha256.Sum256(t)] = e
		text[e] = t
	}
	s = make([]E, 0, len(dedup))
	for _, e := range dedup {
		s = append(s, e)
	}
	slices.SortFunc(s, func(a, b E) int {
		return bytes.Compare(text[a], text[b])
	})
	return s
}
