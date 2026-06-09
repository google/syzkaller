// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package codesearcher provides tools for indexing and searching source code.
package codesearcher

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/clangtool"
	"github.com/google/syzkaller/pkg/codesearch"
	"github.com/google/syzkaller/pkg/hash"
	clangtoolimpl "github.com/google/syzkaller/tools/clang/codesearch"
)

var (
	ToolFileIndex = aflow.NewFuncTool("codesearch-file-index", fileIndex, `
Tool provides list of entities defined in the given source file.
Entity can be function, struct, or global variable.
Use it to understand what other things of interest exist in a file.
For example, to locate some initialization function that sets up invariants,
or to find a group of similar functions to later assess similarities/differences
in their implementations.
`)

	ToolDefinitionComment = aflow.NewFuncTool("codesearch-definition-comment", definitionComment, `
Tool provides source code comment for an entity with the given name.
Entity can be function, struct, or global variable.
Use it to understand how an entity is supposed to be used.
For example, what a function does, or if it may be invoked with NULL pointer argument or not.
But an entity may not have a comment, in which case an empty comment is returned.
In such case, you may consider using codesearch-definition-source tool to look
at the full source code of the entity.
`)

	ToolDefinitionSource = aflow.NewFuncTool("codesearch-definition-source", definitionSource, `
Tool provides full source code for an entity with the given name.
Entity can be function, struct, or global variable.
Use it to understand implementation details of an entity.
For example, how a function works, what precondition error checks it has, etc.
`)

	ToolFindReferences = aflow.NewFuncTool("codesearch-find-references", findReferences, `
Tool finds and lists all references to (uses of) the given entity.
Entity can be function, struct, or global variable.
If can be used to find all calls or other uses of the given function,
definition of the given struct/union/enum,
or all reads/writes of the given struct/union field.
To find field references use 'struct_name::field_name' syntax.
`)

	ToolStructLayout = aflow.NewFuncTool("codesearch-struct-layout", structLayout, `
Tool provides layout of a struct/union (fields, offsets, sizes).
It can be used to understand the full memory layout of a struct,
or to find which field is located at a specific offset.
The response contains ALL fields of the struct. If you don't see
a field in the output, it is NOT present in the struct definition
(e.g. due to #ifdefs).
You can strictly trust the response to be complete and accurate.
`)

	ToolIndirectTargets = aflow.NewFuncTool("codesearch-indirect-targets", indirectTargets, `
Tool finds all functions that could be called by an indirect call matching a specific signature.
You can provide either a raw signature (e.g. "void (int)") or a struct field (e.g. "struct ops::do_work").
`)

	ToolIndirectCallers = aflow.NewFuncTool("codesearch-indirect-callers", indirectCallers, `
Tool finds all locations where an indirect call matching a specific signature is made.
You can provide either a raw signature (e.g. "void (int)") or a function name.
`)

	Tools = []aflow.Tool{ToolDirIndex, ToolReadFile, ToolFileIndex, ToolDefinitionComment,
		ToolDefinitionSource, ToolFindReferences, ToolStructLayout, ToolIndirectTargets, ToolIndirectCallers}
)

// PrepareIndex is an action that needs to run before any agents that use codesearch tools.
var PrepareIndex = aflow.NewFuncAction("codesearch-prepare", prepare)

type prepareArgs struct {
	KernelCommit string
	KernelConfig string
	KernelSrc    string
	KernelObj    string
}

type prepareResult struct {
	Index index
}

type fileIndexArgs struct {
	SourceFile string `jsonschema:"Source file path."`
}

type fileIndexResult struct {
	Entities []indexEntity `jsonschema:"List of entites defined in the file."`
}

type indexEntity struct {
	Kind string `jsonschema:"Kind of the entity: function, struct, variable."`
	Name string `jsonschema:"Name of the entity."`
}

// nolint: lll
type defCommentArgs struct {
	ContextFile string `jsonschema:"Source file path that references the entity. It helps to restrict scope of the search, if there are different definitions with the same name in different source files."`
	Name        string `jsonschema:"Name of the entity of interest."`
}

type defCommentResult struct {
	Kind    string `jsonschema:"Kind of the entity: function, struct, variable."`
	Comment string `jsonschema:"Source comment for the entity."`
}

// nolint: lll
type defSourceArgs struct {
	ContextFile string `jsonschema:"Source file path that references the entity. It helps to restrict scope of the search, if there are different definitions with the same name in different source files."`
	Name        string `jsonschema:"Name of the entity of interest."`
}

// nolint: lll
type defSourceResult struct {
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
	desc := fmt.Sprintf("kernel commit %v, config hash %v, databash hash %v",
		args.KernelCommit, hash.String(args.KernelConfig), codesearch.DatabaseFormatHash)
	dir, err := ctx.Cache("codesearch", desc, func(dir string) error {
		cfg := &clangtool.Config{
			Tool:      clangtoolimpl.Tool,
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
	entities, err := state.Index.FileIndex(args.SourceFile)
	res := fileIndexResult{}
	for _, ent := range entities {
		res.Entities = append(res.Entities, indexEntity{
			Kind: ent.Kind,
			Name: ent.Name,
		})
	}
	return res, err
}

// nolint:dupl
func definitionComment(ctx *aflow.Context, state prepareResult, args defCommentArgs) (defCommentResult, error) {
	info, err := state.Index.DefinitionComment(args.ContextFile, args.Name)
	if err != nil {
		return defCommentResult{}, err
	}
	return defCommentResult{
		Kind:    info.Kind,
		Comment: info.Body,
	}, nil
}

// nolint:dupl
func definitionSource(ctx *aflow.Context, state prepareResult, args defSourceArgs) (defSourceResult, error) {
	info, err := state.Index.DefinitionSource(args.ContextFile, args.Name)
	if err != nil {
		return defSourceResult{}, err
	}
	return defSourceResult{
		SourceFile: info.File,
		SourceCode: info.Body,
	}, nil
}

// nolint: lll
type findReferencesArgs struct {
	ContextFile         string `jsonschema:"Source file path that references the entity. It helps to restrict scope of the search, if there are different definitions with the same name in different source files." json:",omitempty"`
	Name                string `jsonschema:"Name of the entity of interest."`
	SourceTreePrefix    string `jsonschema:"Prefix of the source tree where to search for references. Can be used to restrict search to e.g. net/ipv4/. Pass an empty string to find all references." json:",omitempty"`
	IncludeSnippetLines uint   `jsonschema:"If set to non-0, output will include source code snippets with that many lines of context. If set to 0, no source snippets will be included. Snippets only show the referencing entity, so to see e.g. whole referencing functions pass a large value, e.g. 10000" json:",omitempty"`
}

// nolint: lll
type findReferencesResult struct {
	TruncatedOutput bool                       `jsonschema:"Set if there were too many references, and the output is truncated. If you get truncated output, you may try to either request w/o source code snippets by passing IncludeSnippetLines=0 (which has higher limit on the number of output references), or restrict search to some prefix of the source tree with SourceTreePrefix argument."`
	References      []codesearch.ReferenceInfo `jsonschema:"List of requested references."`
}

func findReferences(ctx *aflow.Context, state prepareResult, args findReferencesArgs) (findReferencesResult, error) {
	// TODO: consider limiting output based on the total number of lines in code snippets.
	// In the end we care about total number of consumed tokens.
	outputLimit := 20
	if args.IncludeSnippetLines == 0 {
		outputLimit = 1000
	} else if args.IncludeSnippetLines < 10 {
		outputLimit = 100
	}
	refs, totalCount, err := state.Index.FindReferences(
		args.ContextFile, args.Name, args.SourceTreePrefix,
		int(args.IncludeSnippetLines), outputLimit)
	if err != nil {
		return findReferencesResult{}, err
	}
	return findReferencesResult{
		TruncatedOutput: totalCount > len(refs),
		References:      refs,
	}, nil
}

// nolint: lll
type structLayoutArgs struct {
	ContextFile string `jsonschema:"Source file path that references the entity. It helps to restrict scope of the search, if there are different definitions with the same name in different source files." json:",omitempty"`
	Name        string `jsonschema:"Name of the struct/union."`
	FieldOffset *uint  `jsonschema:"Byte offset to query. If set to null (or missing), the tool returns the whole struct layout. Otherwise, it returns only the field(s) overlapping with this byte." json:",omitempty"`
}

type structLayoutResult struct {
	Fields []structLayoutField `jsonschema:"List of fields."`
}

type structLayoutField struct {
	Name       string `jsonschema:"Name of the field."`
	OffsetBits uint64 `jsonschema:"Offset of the field in bits."`
	SizeBits   uint64 `jsonschema:"Size of the field in bits."`
	Type       string `jsonschema:"Type of the field." json:",omitempty"`
	Signature  string `jsonschema:"If the field is a function pointer, its canonical signature." json:",omitempty"`
}

func structLayout(ctx *aflow.Context, state prepareResult, args structLayoutArgs) (structLayoutResult, error) {
	fields, err := state.Index.GetStructLayout(args.ContextFile, args.Name, args.FieldOffset)
	if err != nil {
		return structLayoutResult{}, err
	}
	res := structLayoutResult{}
	for _, f := range fields {
		res.Fields = append(res.Fields, structLayoutField{
			Name:       f.Name,
			OffsetBits: f.OffsetBits,
			SizeBits:   f.SizeBits,
			Type:       f.Type,
			Signature:  f.Signature,
		})
	}
	return res, nil
}

type extractFunctionArgs struct {
	Index index
	File  string `jsonschema:"Source file path."`
	Line  int    `jsonschema:"Line number in the file."`
}

type extractFunctionResult struct {
	FunctionName   string `jsonschema:"Name of the function."`
	FunctionSource string `jsonschema:"Source code of the function."`
}

func extractFunction(ctx *aflow.Context, args extractFunctionArgs) (extractFunctionResult, error) {
	info, err := args.Index.FindFunctionAtLine(args.File, args.Line)
	if err != nil {
		return extractFunctionResult{}, err
	}
	return extractFunctionResult{FunctionName: info.Name, FunctionSource: info.Body}, nil
}

type extractIndirectCallersArgs struct {
	Index        index
	FunctionName string
}

type extractIndirectCallersResult struct {
	IndirectCallers string
}

func extractIndirectCallers(ctx *aflow.Context, args extractIndirectCallersArgs) (extractIndirectCallersResult, error) {
	if args.FunctionName == "" {
		return extractIndirectCallersResult{}, nil
	}

	refs, totalCount, err := getIndirectCallSites(args.Index, "", args.FunctionName, "", 2, 10)
	if err != nil || totalCount == 0 {
		return extractIndirectCallersResult{}, nil
	}

	b := new(strings.Builder)
	fmt.Fprintf(b, "Function %v is called indirectly at %v locations", args.FunctionName, totalCount)
	if totalCount > len(refs) {
		fmt.Fprintf(b, " (showing %v)", len(refs))
	}
	fmt.Fprintf(b, ":\n\n")
	for _, ref := range refs {
		fmt.Fprintf(b, "%v %v it at %v:%v\n%v\n\n",
			ref.ReferencingEntityKind, ref.ReferencingEntityName,
			ref.SourceFile, ref.SourceLine, ref.SourceSnippet)
	}
	return extractIndirectCallersResult{IndirectCallers: strings.TrimSpace(b.String())}, nil
}

var ActionExtractFunction = aflow.NewFuncAction("codesearch-extract-function", extractFunction)
var ActionExtractIndirectCallers = aflow.NewFuncAction("codesearch-extract-indirect-callers", extractIndirectCallers)

type indirectTargetsArgs struct {
	ContextFile string `jsonschema:"Source file path that references the entity." json:",omitempty"`
	Name        string `jsonschema:"Name of the entity of interest. e.g. 'ops::do_work' or 'void (int)'."`
}

type indirectTargetsResult struct {
	Targets []string `jsonschema:"List of functions that match the signature and have their address taken."`
}

func indirectTargets(ctx *aflow.Context, state prepareResult, args indirectTargetsArgs) (
	indirectTargetsResult, error) {
	signature := args.Name
	if strings.Contains(args.Name, "::") {
		parts := strings.Split(args.Name, "::")
		if len(parts) == 2 {
			fields, err := state.Index.GetStructLayout(args.ContextFile, parts[0], nil)
			if err == nil {
				for _, f := range fields {
					if f.Name == parts[1] && f.Signature != "" {
						signature = f.Signature
						break
					}
				}
			}
		}
	}
	targets, err := state.Index.FindIndirectTargets(signature)
	if err != nil {
		return indirectTargetsResult{}, err
	}
	return indirectTargetsResult{Targets: targets}, nil
}

type indirectCallersArgs struct {
	ContextFile         string `jsonschema:"Source file path that references the entity." json:",omitempty"`
	Name                string `jsonschema:"Name of the entity of interest. Function name or 'void (int)'."`
	SourceTreePrefix    string `jsonschema:"Prefix to restrict search. Empty finds all." json:",omitempty"`
	IncludeSnippetLines uint   `jsonschema:"Number of lines of context for source code snippets." json:",omitempty"`
}

type indirectCallersResult struct {
	TruncatedOutput bool                       `jsonschema:"Set if output was truncated."`
	References      []codesearch.ReferenceInfo `jsonschema:"List of requested references."`
}

// getIndirectCallSites is a shared helper for retrieving indirect call sites.
// If the provided name is a function name rather than a signature, it will
// first query the definition source to resolve it into its function signature
// before querying the index for indirect callers.
func getIndirectCallSites(
	index index, contextFile, name, srcPrefix string, contextLines, outputLimit int,
) ([]codesearch.ReferenceInfo, int, error) {
	signature := name
	if !strings.Contains(name, "(") {
		info, err := index.DefinitionSource(contextFile, name)
		if err == nil && info != nil && info.Signature != "" {
			signature = info.Signature
		}
	}
	return index.FindIndirectCallSites(signature, srcPrefix, contextLines, outputLimit)
}

func indirectCallers(ctx *aflow.Context, state prepareResult, args indirectCallersArgs) (
	indirectCallersResult, error) {
	outputLimit := 20
	if args.IncludeSnippetLines == 0 {
		outputLimit = 1000
	} else if args.IncludeSnippetLines < 10 {
		outputLimit = 100
	}
	refs, totalCount, err := getIndirectCallSites(state.Index, args.ContextFile, args.Name,
		args.SourceTreePrefix, int(args.IncludeSnippetLines), outputLimit)
	if err != nil {
		return indirectCallersResult{}, err
	}
	return indirectCallersResult{
		TruncatedOutput: totalCount > len(refs),
		References:      refs,
	}, nil
}
