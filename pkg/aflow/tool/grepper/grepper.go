// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package grepper

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"slices"
	"time"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/osutil"
)

var Tool = aflow.NewFuncTool("grepper", grepper, `
The tool executes git grep on the kernel sources and returns the output.
The codesearch set of tools provide more precise results,
use them instead of this tool if they can answer your question.

The following git grep flags are used:
--extended-regexp: you need to provide expression in extended regexp syntax
--line-number: line numbers are shown in the output
--show-function: name of the function/struct/etc containing the match is shown in the output
-C1: one line of before/after context is shown

Lines with matches have ':' after the line number.
Content lines have '-'  after the line number.
Containing function/struct lines have '=' after the line number.
`)

type state struct {
	KernelSrc string
}

type args struct {
	Expression string `jsonschema:"Git grep expression in extended regexp syntax."`
}

type results struct {
	Output string `jsonschema:"Output of the grep command."`
}

func grepper(ctx *aflow.Context, state state, args args) (results, error) {
	output, err := osutil.RunCmd(time.Hour, state.KernelSrc, "git", "grep", "--extended-regexp",
		"--line-number", "--show-function", "-C1", "--no-color", "--", args.Expression)
	if err != nil {
		if exitErr := new(exec.ExitError); errors.As(err, &exitErr) {
			if exitErr.ExitCode() == 1 && len(output) == 0 {
				return results{}, aflow.BadCallError("no matches")
			}
			// This should mean an invalid expression.
			if exitErr.ExitCode() == 128 && bytes.Contains(output, []byte("fatal:")) {
				return results{}, aflow.BadCallError("bad expression: %s", bytes.TrimSpace(output))
			}
		}
		return results{}, fmt.Errorf("%w\n%s", err, output)
	}
	// There is a potential DoS by LLM is it searches for ".*",
	// "kmalloc" would be pretty bad (and useless) too.
	// We can't show whole output in these cases, and need to truncate it.
	// Output of ".*" for kernel is 3.2GB (40MLOC), so we don't bother
	// handling it with more efficient streaming. That's lots of memory,
	// but should be bearable for syz-agent.
	// Each match takes 3-6 lines (counting context, function lines, and -- delimiters).
	const maxLines = 500
	lines := slices.Collect(bytes.Lines(output))
	if len(lines) <= maxLines {
		return results{string(output)}, nil
	}
	res := fmt.Sprintf(`
Full output is too long, showing %v out of %v lines.
Use more precise expression if possible.

%s
`, maxLines, len(lines), slices.Concat(lines[:maxLines]))
	return results{res}, nil
}
