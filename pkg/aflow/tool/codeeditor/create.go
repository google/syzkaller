// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package codeeditor

import (
	"errors"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/codesearch"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/vcs"
)

var CreateTool = aflow.NewFuncTool("create-source-file", createFile, `
Create a new source file in an existing directory of the scratch checkout.
Provide the complete contents. This tool cannot overwrite existing files.
Use codeeditor to edit a file after creating it.
`)

type createArgs struct {
	SourceFile string `jsonschema:"New source file path relative to the source tree."`
	Contents   string `jsonschema:"Complete contents of the new source file."`
}

// Require a clean relative path with no hidden components or shell metacharacters.
var sourcePath = regexp.MustCompile(`^(?:[a-zA-Z0-9_-][a-zA-Z0-9_.-]*/)*[a-zA-Z0-9_-][a-zA-Z0-9_.-]*$`)

func createFile(ctx *aflow.Context, state state, args createArgs) (struct{}, error) {
	name := args.SourceFile
	if path.Clean(name) != name || !sourcePath.MatchString(name) || !codesearch.IsSourceFile(name) {
		return struct{}{}, aflow.BadCallError("invalid source file path %q", name)
	}
	if strings.TrimSpace(args.Contents) == "" {
		return struct{}{}, aflow.BadCallError("Contents is empty")
	}
	contents := strings.TrimSuffix(args.Contents, "\n") + "\n"
	root, err := osutil.OpenSandboxRoot(state.KernelScratchSrc)
	if err != nil {
		return struct{}{}, err
	}
	defer root.Close()
	if err := root.CreateFile(name, []byte(contents)); err != nil {
		return struct{}{}, aflow.BadCallError("failed to create source file %q: %v", name, err)
	}
	// CreateFile closes the descriptor before Git runs. Pass the filename as a
	// literal pathspec after --, without invoking a shell.
	_, err = vcs.SandboxedGit(state.KernelScratchSrc).RunTimeout(time.Minute,
		"--literal-pathspecs", "add", "--intent-to-add", "--", name)
	if err != nil {
		return struct{}{}, errors.Join(err, root.Remove(name))
	}
	return struct{}{}, nil
}
