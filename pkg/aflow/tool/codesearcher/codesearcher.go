// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package codesearcher

import (
	"fmt"
	"path/filepath"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/clangtool"
	"github.com/google/syzkaller/pkg/codesearch"
	"github.com/google/syzkaller/pkg/hash"
)

var Tools = []aflow.Tool{
	aflow.NewFuncTool("codesearch-file-index", fileIndex, `
Tool provides list of entities defined in the given source file.
Entity can be function, struct, or global variable.
Use it to understand what other things of interest exist in a file.
For example, to locate some initialization function that sets up invariants,
or to find a group of similar functions to later assess similarities/differences
in their implementations.
`),
	aflow.NewFuncTool("codesearch-definition-comment", definitionComment, `
Tool provides source code comment for an entity with the given name.
Entity can be function, struct, or global variable.
Use it to understand how an entity is supposed to be used.
For example, what a function does, or if it may be invoked with NULL pointer argument or not.
But an entity may not have a comment, in which case an empty comment is returned.
In such case, you may consider using codesearch-definition-source tool to look
at the full source code of the entity.
`),
	aflow.NewFuncTool("codesearch-definition-source", definitionSource, `
Tool provides full source code for an entity with the given name.
Entity can be function, struct, or global variable.
Use it to understand implementation details of an entity.
For example, how a function works, what precondition error checks it has, etc.
`),
}

// This action needs to run before any agents that use codesearch tools.
var PrepareIndex = aflow.NewFuncAction("codesearch-prepare", prepare)

type prepareArgs struct {
	KernelCommit      string
	KernelConfig      string
	KernelSrc         string
	KernelObj         string
	CodesearchToolBin string
}

type prepareResult struct {
	Index index
}

type fileIndexArgs struct {
	SourceFile string `jsonschema:"Source file path."`
}

type fileIndexResult struct {
	Missing  bool          `jsonschema:"Set to true if the file with the given name does not exist."`
	Entities []indexEntity `jsonschema:"List of entites defined in the file."`
}

type indexEntity struct {
	Kind string `jsonschema:"Kind of the entity: function, struct, variable."`
	Name string `jsonschema:"Name of the entity."`
}

// nolint: lll
type defCommentArgs struct {
	SourceFile string `jsonschema:"Source file path that references the entity. It helps to restrict scope of the search, if there are different definitions with the same name in different source files."`
	Name       string `jsonschema:"Name of the entity of interest."`
}

type defCommentResult struct {
	Missing bool   `jsonschema:"Set to true if the entity with the given name does not exist."`
	Kind    string `jsonschema:"Kind of the entity: function, struct, variable."`
	Comment string `jsonschema:"Source comment for the entity."`
}

// nolint: lll
type defSourceArgs struct {
	SourceFile   string `jsonschema:"Source file path that references the entity. It helps to restrict scope of the search, if there are different definitions with the same name in different source files."`
	Name         string `jsonschema:"Name of the entity of interest."`
	IncludeLines bool   `jsonschema:"Whether to include line numbers in the output or not. Line numbers may distract you, so ask for them only if you need to match lines elsewhere with the source code."`
}

// nolint: lll
type defSourceResult struct {
	Missing    bool   `jsonschema:"Set to true if the entity with the given name does not exist."`
	SourceFile string `jsonschema:"Source file path where the entity is defined."`
	SourceCode string `jsonschema:"Source code of the entity definition. It is prefixed with line numbers, so that they can be referenced in other tool invocations."`
}

// index prevents full JSON marshalling of the index contexts,
// so that they do not appear in logs/journal, and also ensures
// that the index does not pass JSON marshalling round-trip.
type index struct {
	*codesearch.Index
}

func (index) MarshalJSON() ([]byte, error) {
	return []byte(`"codesearch-index"`), nil
}

func (index) UnmarshalJSON([]byte) error {
	return fmt.Errorf("codesearch-index cannot be unmarshalled")
}

func prepare(ctx *aflow.Context, args prepareArgs) (prepareResult, error) {
	desc := fmt.Sprintf("kernel commit %v, config hash %v",
		args.KernelCommit, hash.String(args.KernelConfig))
	dir, err := ctx.Cache("codesearch", desc, func(dir string) error {
		cfg := &clangtool.Config{
			ToolBin:   args.CodesearchToolBin,
			KernelSrc: args.KernelSrc,
			KernelObj: args.KernelObj,
			CacheFile: filepath.Join(dir, "index.json"),
		}
		_, err := clangtool.Run[codesearch.Database](cfg)
		return err
	})
	if err != nil {
		return prepareResult{}, err
	}
	srcDirs := []string{args.KernelSrc, args.KernelObj}
	csIndex, err := codesearch.NewIndex(filepath.Join(dir, "index.json"), srcDirs)
	return prepareResult{index{csIndex}}, err
}

func fileIndex(ctx *aflow.Context, state prepareResult, args fileIndexArgs) (fileIndexResult, error) {
	ok, entities, err := state.Index.FileIndex(args.SourceFile)
	res := fileIndexResult{
		Missing: !ok,
	}
	for _, ent := range entities {
		res.Entities = append(res.Entities, indexEntity{
			Kind: ent.Kind,
			Name: ent.Name,
		})
	}
	return res, err
}

func definitionComment(ctx *aflow.Context, state prepareResult, args defCommentArgs) (defCommentResult, error) {
	info, err := state.Index.DefinitionComment(args.SourceFile, args.Name)
	if err != nil || info == nil {
		return defCommentResult{
			Missing: info == nil,
		}, err
	}
	return defCommentResult{
		Kind:    info.Kind,
		Comment: info.Body,
	}, nil
}

func definitionSource(ctx *aflow.Context, state prepareResult, args defSourceArgs) (defSourceResult, error) {
	info, err := state.Index.DefinitionSource(args.SourceFile, args.Name, args.IncludeLines)
	if err != nil || info == nil {
		return defSourceResult{
			Missing: info == nil,
		}, err
	}
	return defSourceResult{
		SourceFile: info.File,
		SourceCode: info.Body,
	}, nil
}
