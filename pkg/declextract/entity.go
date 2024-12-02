// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package declextract

import (
	"bytes"
	"encoding/json"
	"slices"
)

type Output struct {
	Includes        []string         `json:"includes,omitempty"`
	Defines         []*Define        `json:"defines,omitempty"`
	Enums           []*Enum          `json:"enums,omitempty"`
	Structs         []*Struct        `json:"structs,omitempty"`
	Syscalls        []*Syscall       `json:"syscalls,omitempty"`
	FileOps         []*FileOps       `json:"file_ops,omitempty"`
	IouringOps      []*IouringOp     `json:"iouring_ops,omitempty"`
	NetlinkFamilies []*NetlinkFamily `json:"netlink_families,omitempty"`
	NetlinkPolicies []*NetlinkPolicy `json:"netlink_policies,omitempty"`
}

type Define struct {
	Name  string `json:"name,omitempty"`
	Value string `json:"value,omitempty"`
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
}

// FileOps describes one file_operations variable.
type FileOps struct {
	Name string `json:"name,omitempty"`
	// Names of callback functions.
	Open       string      `json:"open,omitempty"`
	Read       string      `json:"read,omitempty"`
	Write      string      `json:"write,omitempty"`
	Mmap       string      `json:"mmap,omitempty"`
	Ioctl      string      `json:"ioctl,omitempty"`
	IoctlCmds  []*IoctlCmd `json:"ioctl_cmds,omitempty"`
	SourceFile string      `json:"source_file,omitempty"`
}

type IoctlCmd struct {
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
	Name     string   `json:"name,omitempty"`
	ByteSize int      `json:"byte_size,omitempty"`
	IsUnion  bool     `json:"is_union,omitempty"`
	IsPacked bool     `json:"is_packed,omitempty"`
	Align    int      `json:"align,omitempty"`
	Fields   []*Field `json:"fields,omitempty"`
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
	Elem    *Type `json:"elem,omitempty"`
	MinSize int   `json:"min_size,omitempty"`
	MaxSize int   `json:"max_size,omitempty"`
}

type BufferType struct {
	MinSize         int  `json:"min_size,omitempty"`
	MaxSize         int  `json:"max_size,omitempty"`
	IsString        bool `json:"is_string,omitempty"`
	IsNonTerminated bool `json:"is_non_terminated,omitempty"`
}

func (out *Output) Merge(other *Output) {
	out.Includes = append(out.Includes, other.Includes...)
	out.Defines = append(out.Defines, other.Defines...)
	out.Enums = append(out.Enums, other.Enums...)
	out.Structs = append(out.Structs, other.Structs...)
	out.Syscalls = append(out.Syscalls, other.Syscalls...)
	out.FileOps = append(out.FileOps, other.FileOps...)
	out.IouringOps = append(out.IouringOps, other.IouringOps...)
	out.NetlinkFamilies = append(out.NetlinkFamilies, other.NetlinkFamilies...)
	out.NetlinkPolicies = append(out.NetlinkPolicies, other.NetlinkPolicies...)
}

func (out *Output) SortAndDedup() {
	out.Includes = sortAndDedupSlice(out.Includes)
	out.Defines = sortAndDedupSlice(out.Defines)
	out.Enums = sortAndDedupSlice(out.Enums)
	out.Structs = sortAndDedupSlice(out.Structs)
	out.Syscalls = sortAndDedupSlice(out.Syscalls)
	out.FileOps = sortAndDedupSlice(out.FileOps)
	out.IouringOps = sortAndDedupSlice(out.IouringOps)
	out.NetlinkFamilies = sortAndDedupSlice(out.NetlinkFamilies)
	out.NetlinkPolicies = sortAndDedupSlice(out.NetlinkPolicies)
}

// SetSoureFile attaches the source file to the entities that need it.
// The clang tool could do it, but it looks easier to do it here.
func (out *Output) SetSourceFile(file string) {
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

func sortAndDedupSlice[Slice ~[]E, E any](s Slice) Slice {
	slices.SortFunc(s, func(a, b E) int {
		aa, _ := json.Marshal(a)
		bb, _ := json.Marshal(b)
		return bytes.Compare(aa, bb)
	})
	return slices.CompactFunc(s, func(a, b E) bool {
		aa, _ := json.Marshal(a)
		bb, _ := json.Marshal(b)
		return bytes.Equal(aa, bb)
	})
}
