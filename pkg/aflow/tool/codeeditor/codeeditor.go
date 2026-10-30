// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package codeeditor provides tools for viewing and editing code files.
package codeeditor

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/codesearch"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/vcs"
)

var Tool = aflow.NewFuncTool("codeeditor", codeeditor, `
The tool does one source code edit to form the final patch by replacing full lines
with new provided lines. If new code is empty, current lines will be deleted.
Provide full lines of code including new line characters.
To create a new source file in an existing directory, leave CurrentCode empty
and provide the complete file contents in NewCode. Existing files cannot be
overwritten this way.
The tool should be called mutiple times to do all required changes one-by-one,
but avoid changing the same lines multiple times.
Note: You will not see your edits via the codesearch tool.
Note: The current code snippet should reflect the previous changes.
`)

type state struct {
	KernelScratchSrc string
}

type args struct {
	SourceFile  string `jsonschema:"Source file path relative to the source tree."`
	CurrentCode string `jsonschema:"The current code lines to be replaced. Empty when creating a new file."`
	NewCode     string `jsonschema:"New code lines to replace the current code lines."`
}

func codeeditor(ctx *aflow.Context, state state, args args) (struct{}, error) {
	if strings.Contains(filepath.Clean(args.SourceFile), "..") {
		return struct{}{}, aflow.BadCallError("SourceFile %q is outside of the source tree", args.SourceFile)
	}
	file := filepath.Join(state.KernelScratchSrc, args.SourceFile)
	// Filter out not source files too (e.g. .git, etc),
	// LLM have not seen them and should not be messing with them.
	if !codesearch.IsSourceFile(file) {
		return struct{}{}, aflow.BadCallError("SourceFile %q does not exist", args.SourceFile)
	}
	root, err := os.OpenRoot(state.KernelScratchSrc)
	if err != nil {
		return struct{}{}, err
	}
	defer root.Close()
	if args.NewCode != "" && args.NewCode[len(args.NewCode)-1] != '\n' {
		args.NewCode += "\n"
	}
	fileData, err := root.ReadFile(args.SourceFile)
	if errors.Is(err, os.ErrNotExist) && args.CurrentCode == "" {
		return struct{}{}, createFile(root, state.KernelScratchSrc, args)
	}
	if err != nil {
		return struct{}{}, aflow.BadCallError("SourceFile %q does not exist", args.SourceFile)
	}
	if strings.TrimSpace(args.CurrentCode) == "" {
		return struct{}{}, aflow.BadCallError("CurrentCode snippet is empty")
	}
	if len(fileData) == 0 || fileData[len(fileData)-1] != '\n' {
		// Generally shouldn't happen, but just in case.
		fileData = append(fileData, '\n')
	}
	if args.CurrentCode[len(args.CurrentCode)-1] != '\n' {
		args.CurrentCode += "\n"
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
	return struct{}{}, root.WriteFile(args.SourceFile, newFileData, osutil.DefaultFilePerm)
}

func createFile(root *os.Root, repo string, args args) (err error) {
	if strings.TrimSpace(args.NewCode) == "" {
		return aflow.BadCallError("NewCode is empty")
	}
	// Exclusive creation prevents overwriting a file or following a dangling symlink.
	file, err := root.OpenFile(args.SourceFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, osutil.DefaultFilePerm)
	if err != nil {
		return aflow.BadCallError("failed to create SourceFile %q: %v", args.SourceFile, err)
	}
	defer func() {
		err = errors.Join(err, file.Close())
		if err != nil {
			err = errors.Join(err, root.Remove(args.SourceFile))
		}
	}()
	if _, err := file.WriteString(args.NewCode); err != nil {
		return err
	}
	// Chown the open file, not a path through the sandbox-owned source tree.
	if err := osutil.SandboxChownFile(file); err != nil {
		return err
	}
	// Include the new file in patch-diff and checkpatch without staging its contents.
	_, err = vcs.SandboxedGit(repo).RunTimeout(time.Minute,
		"--literal-pathspecs", "add", "--intent-to-add", "--", args.SourceFile)
	return err
}

func replace(lines, src, dst [][]byte, fuzzy bool) (newLines [][]byte, matches int) {
	for i := 0; i < len(lines); {
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
			i++
			continue
		}
		matches++
		newLines = append(newLines, dst...)
		i = li
	}
	return
}
