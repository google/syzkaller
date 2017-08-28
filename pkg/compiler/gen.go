// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package compiler

import (
	"sort"

	"github.com/google/syzkaller/pkg/ast"
	"github.com/google/syzkaller/sys"
)

func (comp *compiler) genResources() []*sys.ResourceDesc {
	var resources []*sys.ResourceDesc
	for _, decl := range comp.desc.Nodes {
		if n, ok := decl.(*ast.Resource); ok {
			resources = append(resources, comp.genResource(n))
		}
	}
	sort.Slice(resources, func(i, j int) bool {
		return resources[i].Name < resources[j].Name
	})
	return resources
}

func (comp *compiler) genResource(n *ast.Resource) *sys.ResourceDesc {
	res := &sys.ResourceDesc{
		Name: n.Name.Name,
	}
	var base *ast.Type
	for n != nil {
		res.Values = append(genIntArray(n.Values), res.Values...)
		res.Kind = append([]string{n.Name.Name}, res.Kind...)
		base = n.Base
		n = comp.resources[n.Base.Ident]
	}
	if len(res.Values) == 0 {
		res.Values = []uint64{0}
	}
	res.Type = comp.genType(base, "", sys.DirIn, false)
	return res
}

func (comp *compiler) genSyscalls() []*sys.Call {
	var calls []*sys.Call
	for _, decl := range comp.desc.Nodes {
		if n, ok := decl.(*ast.Call); ok {
			calls = append(calls, comp.genSyscall(n))
		}
	}
	sort.Slice(calls, func(i, j int) bool {
		return calls[i].Name < calls[j].Name
	})
	return calls
}

func (comp *compiler) genSyscall(n *ast.Call) *sys.Call {
	var ret sys.Type
	if n.Ret != nil {
		ret = comp.genType(n.Ret, "ret", sys.DirOut, true)
	}
	return &sys.Call{
		Name:     n.Name.Name,
		CallName: n.CallName,
		NR:       n.NR,
		Args:     comp.genFieldArray(n.Args, sys.DirIn, true),
		Ret:      ret,
	}
}

func (comp *compiler) genStructFields() []*sys.StructFields {
	var structs []*sys.StructFields
	generated := make(map[sys.StructKey]bool)
	for n := -1; n != len(generated); {
		n = len(generated)
		for key, n := range comp.structUses {
			if generated[key] {
				continue
			}
			generated[key] = true
			structs = append(structs, comp.genStructField(key, n))
		}
	}
	sort.Slice(structs, func(i, j int) bool {
		si, sj := structs[i], structs[j]
		if si.Key.Name != sj.Key.Name {
			return si.Key.Name < sj.Key.Name
		}
		return si.Key.Dir < sj.Key.Dir
	})
	return structs
}

func (comp *compiler) genStructField(key sys.StructKey, n *ast.Struct) *sys.StructFields {
	return &sys.StructFields{
		Key:    key,
		Fields: comp.genFieldArray(n.Fields, key.Dir, false),
	}
}

func (comp *compiler) genField(f *ast.Field, dir sys.Dir, isArg bool) sys.Type {
	return comp.genType(f.Type, f.Name.Name, dir, isArg)
}

func (comp *compiler) genFieldArray(fields []*ast.Field, dir sys.Dir, isArg bool) []sys.Type {
	var res []sys.Type
	for _, f := range fields {
		res = append(res, comp.genField(f, dir, isArg))
	}
	return res
}

func (comp *compiler) genType(t *ast.Type, field string, dir sys.Dir, isArg bool) sys.Type {
	desc, args, base := comp.getArgsBase(t, field, dir, isArg)
	return desc.Gen(comp, t, args, base)
}

func genCommon(name, field string, dir sys.Dir, opt bool) sys.TypeCommon {
	return sys.TypeCommon{
		TypeName:   name,
		FldName:    field,
		ArgDir:     dir,
		IsOptional: opt,
	}
}

func genIntCommon(com sys.TypeCommon, size, bitLen uint64, bigEndian bool) sys.IntTypeCommon {
	return sys.IntTypeCommon{
		TypeCommon:  com,
		BigEndian:   bigEndian,
		TypeSize:    size,
		BitfieldLen: bitLen,
	}
}

func genIntArray(a []*ast.Int) []uint64 {
	r := make([]uint64, len(a))
	for i, v := range a {
		r[i] = v.Value
	}
	return r
}

func genStrArray(a []*ast.String) []string {
	r := make([]string, len(a))
	for i, v := range a {
		r[i] = v.Value
	}
	return r
}
