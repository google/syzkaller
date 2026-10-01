// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package grepper provides tools for regex searching across repository files.
package grepper

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"slices"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/osutil"
)

var Tool = aflow.NewFuncTool("grepper", grepper, `
The tool executes git grep on the kernel sources and returns the output.
The codesearch set of tools provide more precise results,
use them instead of this tool if they can answer your question.
CRITICAL INSTRUCTION: this tool CANNOT be used to search syzkaller syzlang descriptions
(e.g. 'dev_*.txt', 'socket_*.txt', etc.)
or expressions containing 'long syz_'. Those pseudo-syscalls are not present in the Linux kernel.
Use the read-syz-spec and syz-grepper tools instead.
Conversely, any Linux kernel files, POSIX headers (e.g. sys/socket.h, sys/ioctl.h),
or sysfs/procfs paths (e.g. sys/class, sys/devices) MUST be searched using this tool
(or codesearch-* tools), NOT syz-grepper or read-syz-spec.

The following git grep flags are used:
--extended-regexp: you need to provide expression in extended regexp syntax
--line-number: line numbers are shown in the output
--show-function: name of the function/struct/etc containing the match is shown in the output
-C1: one line of before/after context is shown

Lines with matches have ':' after the line number.
Content lines have '-'  after the line number.
Containing function/struct lines have '=' after the line number.

Batch your searches instead of doing many similar calls one at a time:
- Use regexp alternation to search for several identifiers at once
  (e.g. 'phy_connect|phy_attach').
- Pass several directories/files in PathPrefixes to search them at once
  (e.g. ["drivers/net/usb/", "drivers/net/dummy.c"]).
- Search a whole directory rather than each file in it separately.
If the output is too long, it is truncated, and the number of matches per file is shown,
use it to narrow down the next search.
`)

type state struct {
	KernelSrc string
}

type args struct {
	Expression   string   `jsonschema:"Git grep expression in extended regexp syntax."`
	PathPrefixes []string `jsonschema:"Optional path prefixes or files to restrict the grep scope." json:",omitempty"`
}

type results struct {
	Output string `jsonschema:"Output of the grep command."`
}

func grepper(ctx *aflow.Context, state state, args args) (results, error) {
	args.PathPrefixes = slices.DeleteFunc(args.PathPrefixes, func(p string) bool {
		return p == ""
	})
	cmdArgs := []string{
		"grep", "--extended-regexp", "--line-number",
		"--show-function", "-C1", "-e", args.Expression, "--",
	}
	cmdArgs = append(cmdArgs, args.PathPrefixes...)
	output, err := osutil.RunCmd(time.Hour, state.KernelSrc, "git", cmdArgs...)
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
		return results{}, err
	}
	// There is a potential DoS by LLM is it searches for ".*",
	// "kmalloc" would be pretty bad (and useless) too.
	// We can't show whole output in these cases, and need to truncate it.
	// Output of ".*" for kernel is 3.2GB (40MLOC), so we don't bother
	// handling it with more efficient streaming. That's lots of memory,
	// but should be bearable for syz-agent.
	// Each match takes 3-6 lines (counting context, function lines, and -- delimiters).
	const maxLines = 200
	// Grep can match some effectively binary files, e.g. svg.
	// They can contain lines >100K. We mainly intend to match source/docs files
	// which should not contain long lines, so cap at 200 chars.
	const maxLineLen = 200
	lines := slices.Collect(bytes.Lines(output))
	var truncated bool
	for i, line := range lines {
		hasNewline := len(line) > 0 && line[len(line)-1] == '\n'
		contentLen := len(line)
		if hasNewline {
			contentLen--
		}
		if contentLen > maxLineLen {
			newLine := slices.Clone(line[:maxLineLen])
			newLine = append(newLine, []byte("...")...)
			if hasNewline {
				newLine = append(newLine, '\n')
			}
			lines[i] = newLine
			truncated = true
		}
	}

	if len(lines) <= maxLines {
		if truncated {
			return results{string(slices.Concat(lines...))}, nil
		}
		return results{string(output)}, nil
	}
	perFile, err := matchesPerFile(state.KernelSrc, args)
	if err != nil {
		return results{}, err
	}
	res := fmt.Sprintf(`
Full output is too long, showing %v out of %v lines.
Use more precise expression or PathPrefixes if possible.

%s
%s
`, maxLines, len(lines), perFile, slices.Concat(lines[:maxLines]...))
	return results{res}, nil
}

// matchesPerFile returns a summary of the number of matching lines in each file.
func matchesPerFile(kernelSrc string, args args) (string, error) {
	cmdArgs := []string{
		"grep", "--extended-regexp", "--count", "-e", args.Expression, "--",
	}
	cmdArgs = append(cmdArgs, args.PathPrefixes...)
	output, err := osutil.RunCmd(time.Hour, kernelSrc, "git", cmdArgs...)
	if err != nil {
		return "", err
	}
	// Each line is "path:count\n".
	files := slices.Collect(bytes.Lines(output))
	const maxFiles = 50
	var sb strings.Builder
	fmt.Fprintf(&sb, "Number of matching lines per file (%v files in total):\n", len(files))
	for _, line := range files[:min(len(files), maxFiles)] {
		sb.Write(line)
	}
	if len(files) > maxFiles {
		fmt.Fprintf(&sb, "... and %v more files\n", len(files)-maxFiles)
	}
	return sb.String(), nil
}
