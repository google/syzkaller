// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package codesearcher

import (
	"fmt"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/codesearch"
)

var (
	ToolDirIndex = aflow.NewFuncTool("codesearch-dir-index", dirIndex, `
Tool provides list of source files and subdirectories in the given directory in the source tree.
`)

	ToolReadFile = aflow.NewFuncTool("read-file", readFile, `
Tool provides full contents of a single source file as is. Avoid using this tool if there are better
and more specialized tools for the job. The tool returns at most 100 lines at a time.
If you need more, you need to call the tool several times. But avoid fetching large files
with lots of repetitive calls if possible.
`)

	FilesystemTools = []aflow.Tool{ToolDirIndex, ToolReadFile}
)

type fsState struct {
	KernelSrc string
}

func getSrcDir(ctx *aflow.Context, state fsState) (string, error) {
	if state.KernelSrc != "" {
		return state.KernelSrc, nil
	}
	return "", fmt.Errorf("KernelSrc is empty")
}

// nolint: lll
type dirIndexArgs struct {
	Dir string `jsonschema:"Relative directory in the source tree. Use an empty string for the root of the tree, or paths like 'net/ipv4/' for subdirs."`
}

type dirIndexResult struct {
	Subdirs []string `jsonschema:"List of direct subdirectories."`
	Files   []string `jsonschema:"List of source files."`
}

func dirIndex(ctx *aflow.Context, state fsState, args dirIndexArgs) (dirIndexResult, error) {
	root, err := getSrcDir(ctx, state)
	if err != nil {
		return dirIndexResult{}, err
	}
	subdirs, files, err := codesearch.DirIndex([]string{root}, args.Dir)
	return dirIndexResult{
		Subdirs: subdirs,
		Files:   files,
	}, err
}

type readFileArgs struct {
	File      string `jsonschema:"Source file path."`
	FirstLine int    `jsonschema:"First source line to return, 1-based."`
	LineCount int    `jsonschema:"Number of lines to return, capped at 100."`
}

type readFileResult struct {
	Contents string `jsonschema:"File contents."`
}

func readFile(ctx *aflow.Context, state fsState, args readFileArgs) (readFileResult, error) {
	root, err := getSrcDir(ctx, state)
	if err != nil {
		return readFileResult{}, err
	}
	contents, err := codesearch.ReadFile([]string{root}, args.File, args.FirstLine, args.LineCount)
	return readFileResult{
		Contents: contents,
	}, err
}
