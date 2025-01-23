// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package generated

import (
	"bytes"
	"compress/flate"
	"embed"
	"encoding/gob"
	"fmt"
	"path/filepath"

	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

type Desc struct {
	Syscalls  []*prog.Syscall
	Resources []*prog.ResourceDesc
	Consts    []prog.ConstValue
	Flags     []prog.FlagDesc
	Types     []prog.Type
}

func Register(os, arch, revision string, init func(*prog.Target), files embed.FS) {
	sysTarget := targets.Get(os, arch)
	target := &prog.Target{
		OS:         os,
		Arch:       arch,
		Revision:   revision,
		PtrSize:    sysTarget.PtrSize,
		PageSize:   sysTarget.PageSize,
		NumPages:   sysTarget.NumPages,
		DataOffset: sysTarget.DataOffset,
		BigEndian:  sysTarget.BigEndian,
	}
	filler := func(target *prog.Target) {
		fill(target, files)
	}
	prog.RegisterTarget(target, filler, init)
}

func fill(target *prog.Target, files embed.FS) {
	data, err := files.ReadFile(FileName(target.OS, target.Arch))
	if err != nil {
		panic(err)
	}
	desc := new(Desc)
	if err := gob.NewDecoder(flate.NewReader(bytes.NewReader(data))).Decode(desc); err != nil {
		panic(err)
	}
	target.Syscalls = desc.Syscalls
	target.Resources = desc.Resources
	target.Consts = desc.Consts
	target.Flags = desc.Flags
	target.Types = desc.Types
}

func Serialize(desc *Desc) ([]byte, error) {
	out := new(bytes.Buffer)
	compressor, err := flate.NewWriter(out, flate.DefaultCompression)
	if err != nil {
		return nil, err
	}
	enc := gob.NewEncoder(compressor)
	if err := enc.Encode(desc); err != nil {
		return nil, err
	}
	if err := compressor.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func FileName(os, arch string) string {
	return fileName(fmt.Sprintf("%v_%v", os, arch))
}

func Glob() string {
	return fileName("*")
}

func fileName(name string) string {
	return filepath.Join("gen", fmt.Sprintf("%v.gob.flate", name))
}

func init() {
	gob.Register(prog.Ref(0))
	gob.Register(&prog.ResourceType{})
	gob.Register(&prog.ConstType{})
	gob.Register(&prog.IntType{})
	gob.Register(&prog.FlagsType{})
	gob.Register(&prog.LenType{})
	gob.Register(&prog.ProcType{})
	gob.Register(&prog.CsumType{})
	gob.Register(&prog.VmaType{})
	gob.Register(&prog.BufferType{})
	gob.Register(&prog.ArrayType{})
	gob.Register(&prog.PtrType{})
	gob.Register(&prog.StructType{})
	gob.Register(&prog.UnionType{})
	gob.Register(&prog.BinaryExpression{})
	gob.Register(&prog.Value{})
}
