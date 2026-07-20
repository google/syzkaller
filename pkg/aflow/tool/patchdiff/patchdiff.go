// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package patchdiff provides tools for computing diffs and applying patches.
package patchdiff

import (
	"bytes"
	"errors"
	"time"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/osutil"
)

var Tool = aflow.NewFuncTool("patch-diff", patchDiff, `
The tool executes 'git diff' to show the changes you have made so far.
Because other source code viewing tools only show the original code,
you can use this tool to review the modifications you applied using code
editing tools.
`)

type state struct {
	KernelScratchSrc string
}

type args struct {
	// Let's add an optional File parameter to restrict the diff output.
	File string `jsonschema:"Optional: restrict diff to a specific file. If empty, shows all changes."`
}

type result struct {
	Output string `jsonschema:"Output of the git diff command."`
}

// Diff runs a sandboxed git diff command in the specified repository.
func Diff(repo string, args ...string) (string, error) {
	gitDiffArgs := append([]string{"diff"}, args...)
	cmd := osutil.Command("git", gitDiffArgs...)
	cmd.Dir = repo
	if err := osutil.Sandbox(cmd, true, false); err != nil {
		return "", err
	}
	output, err := osutil.Run(1*time.Minute, cmd)
	if err != nil {
		return "", err
	}
	return string(output), nil
}

func patchDiff(ctx *aflow.Context, state state, args args) (result, error) {
	if state.KernelScratchSrc == "" {
		return result{}, aflow.BadCallError("KernelScratchSrc is not set")
	}

	// Compare working tree to HEAD with expanded context.
	gitArgs := []string{"HEAD", "--function-context", "-U10"}
	if args.File != "" {
		gitArgs = append(gitArgs, "--", args.File)
	}

	output, err := Diff(state.KernelScratchSrc, gitArgs...)
	if err != nil {
		if verr, ok := errors.AsType[*osutil.VerboseError](err); ok {
			if bytes.Contains(verr.Output, []byte("outside repository")) {
				return result{}, aflow.BadCallError("git diff failed: the file is outside the repository")
			}
		}
		if errors.Is(err, osutil.ErrTimeout) {
			return result{}, aflow.BadCallError("git diff timed out")
		}
		return result{}, err
	}

	return result{Output: output}, nil
}
