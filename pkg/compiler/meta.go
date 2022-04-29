// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package compiler

import (
	"path/filepath"

	"github.com/google/syzkaller/pkg/ast"
	"github.com/google/syzkaller/sys/targets"
)

type Meta struct {
	NoExtract bool
	Arches    map[string]bool
}

func (meta *Meta) SupportsArch(arch string) bool {
	return len(meta.Arches) == 0 || meta.Arches[arch]
}

func FileList(desc *ast.Description, OS string, eh ast.ErrorHandler) map[string]Meta {
	// Use any target for this OS.
	for _, target := range targets.List[OS] {
		return createCompiler(desc, target, eh).fileList()
	}
	return nil
}

func (comp *compiler) fileList() map[string]Meta {
	files := make(map[string]Meta)
	for _, n := range comp.desc.Nodes {
		pos, _, _ := n.Info()
		file := filepath.Base(pos.File)
		if file == ast.BuiltinFile {
			continue
		}
		meta := files[file]
		switch n := n.(type) {
		case *ast.Meta:
			errors0 := comp.errors
			comp.checkTypeImpl(checkCtx{}, n.Value, metaTypes[n.Value.Ident], 0)
			if errors0 != comp.errors {
				break
			}
			switch n.Value.Ident {
			case metaNoExtract.Names[0]:
				meta.NoExtract = true
			case metaArches.Names[0]:
				meta.Arches = make(map[string]bool)
				for _, arg := range n.Value.Args {
					meta.Arches[arg.String] = true
				}
			}
		}
		files[file] = meta
	}
	if comp.errors != 0 {
		return nil
	}
	return files
}

var metaTypes = map[string]*typeDesc{
	metaNoExtract.Names[0]: metaNoExtract,
	metaArches.Names[0]:    metaArches,
}

var metaNoExtract = &typeDesc{
	Names:     []string{"noextract"},
	CantBeOpt: true,
}

var metaArches = &typeDesc{
	Names:     []string{"arches"},
	CantBeOpt: true,
	OptArgs:   8,
	Args:      []namedArg{metaArch, metaArch, metaArch, metaArch, metaArch, metaArch, metaArch, metaArch},
}

var metaArch = namedArg{Name: "arch", Type: &typeArg{
	Kind: kindString,
	Check: func(comp *compiler, t *ast.Type) {
		if targets.List[comp.target.OS][t.String] == nil {
			comp.error(t.Pos, "unknown arch %v", t.String)
		}
	},
}}
