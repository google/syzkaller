// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package codeeditor

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/codesearch"
	"github.com/google/syzkaller/pkg/osutil"
)

var Tool = aflow.NewFuncTool("codeeditor", codeeditor, `
The tool does one source code edit to form the final patch by replacing full lines
with new provided lines. If new code is empty, current lines will be deleted.
Provide full lines of code including new line characters.
The tool should be called mutiple times to do all required changes one-by-one,
but avoid changing the same lines multiple times.
Note: You will not see your edits via the codesearch tool.
Note: The current code snippet should reflect the previous changes.
`)

type state struct {
	KernelScratchSrc string
}

type args struct {
	SourceFile  string `jsonschema:"Full source file path to edit."`
	CurrentCode string `jsonschema:"The current code lines to be replaced."`
	NewCode     string `jsonschema:"New code lines to replace the current code lines."`
}

func codeeditor(ctx *aflow.Context, state state, args args) (struct{}, error) {
	if strings.Contains(filepath.Clean(args.SourceFile), "..") {
		return struct{}{}, aflow.BadCallError("SourceFile %q is outside of the source tree", args.SourceFile)
	}
	file := filepath.Join(state.KernelScratchSrc, args.SourceFile)
	// Filter out not source files too (e.g. .git, etc),
	// LLM have not seen them and should not be messing with them.
	if !osutil.IsExist(file) || !codesearch.IsSourceFile(file) {
		return struct{}{}, aflow.BadCallError("SourceFile %q does not exist", args.SourceFile)
	}
	if strings.TrimSpace(args.CurrentCode) == "" {
		return struct{}{}, aflow.BadCallError("CurrentCode snippet is empty")
	}
	fileData, err := os.ReadFile(file)
	if err != nil {
		return struct{}{}, err
	}
	if len(fileData) == 0 || fileData[len(fileData)-1] != '\n' {
		// Generally shouldn't happen, but just in case.
		fileData = append(fileData, '\n')
	}
	if args.CurrentCode[len(args.CurrentCode)-1] != '\n' {
		args.CurrentCode += "\n"
	}
	if args.NewCode != "" && args.NewCode[len(args.NewCode)-1] != '\n' {
		args.NewCode += "\n"
	}
	lines := slices.Collect(bytes.Lines(fileData))
	src := slices.Collect(bytes.Lines([]byte(args.CurrentCode)))
	dst := slices.Collect(bytes.Lines([]byte(args.NewCode)))
	// First, try to match as is. If that fails, try a more permissive matching
	// that ignores whitespaces, empty lines, etc.
	newLines, matches := replace(lines, src, dst, false)
	if matches == 0 {
		newLines, matches = replace(lines, src, dst, true)
	}
	if matches == 0 {
		return struct{}{}, aflow.BadCallError("CurrentCode snippet does not match anything in the source file," +
			" provide more precise CurrentCode snippet")
	}
	if matches > 1 {
		return struct{}{}, aflow.BadCallError("CurrentCode snippet matched %v places,"+
			" increase context in CurrentCode to avoid ambiguity", matches)
	}
	newFileData := slices.Concat(newLines...)
	if bytes.Equal(fileData, newFileData) {
		return struct{}{}, aflow.BadCallError("The edit does not change the code.")
	}
	err = osutil.WriteFile(file, newFileData)
	return struct{}{}, err
}

func replace(lines, src, dst [][]byte, fuzzy bool) (newLines [][]byte, matches int) {
	for i := 0; i < len(lines); i++ {
		li, si := i, 0
		for li < len(lines) && si < len(src) {
			l, s := lines[li], src[si]
			if fuzzy {
				// Ignore whitespaces and empty lines.
				l, s = bytes.TrimSpace(l), bytes.TrimSpace(s)
				// Potentially we can remove line numbers from s here if they are present,
				// or use them to disambiguate in the case of multiple matches.
				if len(s) == 0 {
					si++
					continue
				}
				if len(l) == 0 && li != i {
					li++
					continue
				}
			}
			if !bytes.Equal(l, s) {
				break
			}
			li++
			si++
		}
		if si != len(src) {
			newLines = append(newLines, lines[i])
			continue
		}
		matches++
		newLines = append(newLines, dst...)
		i = li - 1
	}
	return
}
