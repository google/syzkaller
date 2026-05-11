// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package gitlog

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/kernel"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/vcs"
)

var (
	ToolLog = aflow.NewFuncTool("git-log", gitLog, `
The tool executes git log on the kernel sources and returns the output.
Use it to find commits that introduced or modified specific code, symbols, or matched a message.

Supported search modes (you must provide at least one):
 - Code search (-G): use 'CodeRegexp' to find commits that introduced or removed code matching the regexp.
 - Symbol search (-L): use 'SymbolName' and 'SourcePath' to trace the history of a specific function or struct.
   Example: SymbolName="tcp_v4_rcv", SourcePath="net/ipv4/tcp_ipv4.c".
 - Message search: use 'MessageRegexps' (array of regexps) to find commits with matching titles or descriptions.
   If multiple regexps are provided, only commits matching ALL of them are returned.
   The search is case-insensitive.
 - File history: use 'PathPrefix' to explore the history of a single file or directory.
   Example: PathPrefix="mm/slub.c".
`)
	ToolShow = aflow.NewFuncTool("git-show", gitShow, `
Tool provides full information about a specific git commit, including its title,
full description, and the diff.
`)
	ToolBlame = aflow.NewFuncTool("git-blame", gitBlame, `
Tool provides git blame for a given file and line range.
It helps to identify which commit last modified specific lines of code.
`)

	Tools = []aflow.Tool{ToolLog, ToolShow, ToolBlame}
)

const maxOutputLines = 1000

type state struct {
	KernelCommit string
}

type logArgs struct {
	CodeRegexp string `jsonschema:"Regexp to search in the code diffs (-G)." json:",omitempty"`
	SymbolName string `jsonschema:"Name of the function or struct to trace (-L)." json:",omitempty"`
	// nolint: lll
	SourcePath string `jsonschema:"Source path for the symbol search (-L). Required if SymbolName is set." json:",omitempty"`
	// nolint: lll
	MessageRegexps []string `jsonschema:"Regexps to search in the commit messages. All regexps must match." json:",omitempty"`
	PathPrefix     string   `jsonschema:"Restrict search to this directory or file path." json:",omitempty"`
	Count          int      `jsonschema:"Max number of commits to return." json:",omitempty"`
}

type logResult struct {
	Output string `jsonschema:"Output of the git log command."`
}

func gitLog(ctx *aflow.Context, state state, args logArgs) (logResult, error) {
	if args.CodeRegexp == "" && args.SymbolName == "" && len(args.MessageRegexps) == 0 &&
		args.PathPrefix == "" {
		return logResult{}, aflow.BadCallError("at least one of CodeRegexp, SymbolName, " +
			"MessageRegexps, or PathPrefix must be set")
	}
	if args.SymbolName != "" && args.PathPrefix != "" {
		return logResult{}, aflow.BadCallError("SymbolName and PathPrefix cannot be used together")
	}
	if args.Count <= 0 {
		args.Count = 10
	}
	args.Count = min(args.Count, 100)

	gitArgs := []string{"log", "--format=%h %s", "--abbrev=12", "--no-patch", "-n", fmt.Sprint(args.Count)}

	if args.CodeRegexp != "" {
		gitArgs = append(gitArgs, "-G", args.CodeRegexp)
	}
	if args.SymbolName != "" {
		if args.SourcePath == "" {
			return logResult{}, aflow.BadCallError("SourcePath is required when SymbolName is set")
		}
		gitArgs = append(gitArgs, fmt.Sprintf("-L:%s:%s", args.SymbolName, args.SourcePath))
	}
	if len(args.MessageRegexps) != 0 {
		gitArgs = append(gitArgs, "--regexp-ignore-case", "--all-match")
		for _, re := range args.MessageRegexps {
			gitArgs = append(gitArgs, "--grep", re)
		}
	}

	if args.CodeRegexp == "" && args.SymbolName == "" {
		gitArgs = append(gitArgs, "--no-merges")
	}

	gitArgs = append(gitArgs, state.KernelCommit)

	if args.PathPrefix != "" {
		gitArgs = append(gitArgs, "--", args.PathPrefix)
	}

	var output []byte
	err := kernel.UseLinuxRepo(ctx, func(kernelRepoDir string, _ vcs.Repo) error {
		var err error
		cmd := osutil.Command("git", gitArgs...)
		cmd.Dir = kernelRepoDir
		if err := osutil.Sandbox(cmd, true, true); err != nil {
			return err
		}
		output, err = osutil.Run(10*time.Minute, cmd)
		return err
	})
	if err != nil {
		return logResult{}, gitBadCallError(err, "git log",
			"Please specify a tighter search scope (e.g. by providing a PathPrefix).")
	}
	return logResult{Output: string(output)}, nil
}

type showArgs struct {
	Commit string `jsonschema:"Commit hash or reference."`
}

type showResult struct {
	Output string `jsonschema:"Full commit information including diff."`
}

func gitShow(ctx *aflow.Context, state state, args showArgs) (showResult, error) {
	if args.Commit == "" {
		return showResult{}, aflow.BadCallError("commit hash is required")
	}
	var output []byte
	err := kernel.UseLinuxRepo(ctx, func(kernelRepoDir string, _ vcs.Repo) error {
		var err error
		cmd := osutil.Command("git", "show", "--no-color", args.Commit)
		cmd.Dir = kernelRepoDir
		if err := osutil.Sandbox(cmd, true, true); err != nil {
			return err
		}
		output, err = osutil.Run(5*time.Minute, cmd)
		return err
	})
	if err != nil {
		return showResult{}, gitBadCallError(err, "git show", "Consider specifying a different commit.")
	}
	return showResult{Output: truncate(output, maxOutputLines)}, nil
}

type blameArgs struct {
	File  string `jsonschema:"Source file path."`
	Start int    `jsonschema:"Start line number (1-based)."`
	End   int    `jsonschema:"End line number (inclusive)."`
}

type blameResult struct {
	Output string `jsonschema:"Output of the git blame command."`
}

func gitBlame(ctx *aflow.Context, state state, args blameArgs) (blameResult, error) {
	args.Start = max(args.Start, 1)
	args.End = max(args.End, args.Start)
	args.End = min(args.End, args.Start+maxOutputLines)
	lineRange := fmt.Sprintf("%d,%d", args.Start, args.End)
	var output []byte
	err := kernel.UseLinuxRepo(ctx, func(kernelRepoDir string, _ vcs.Repo) error {
		var err error
		cmd := osutil.Command("git", "blame", "-s", "-L", lineRange, "--abbrev=12", state.KernelCommit, "--", args.File)
		cmd.Dir = kernelRepoDir
		if err := osutil.Sandbox(cmd, true, true); err != nil {
			return err
		}
		output, err = osutil.Run(5*time.Minute, cmd)
		return err
	})
	if err != nil {
		return blameResult{}, gitBadCallError(err, "git blame", "Consider specifying a smaller line range.")
	}
	return blameResult{Output: truncate(output, maxOutputLines)}, nil
}

func gitBadCallError(err error, name, advice string) error {
	var verr *osutil.VerboseError
	if !errors.As(err, &verr) {
		return err
	}
	if errors.Is(err, osutil.ErrTimeout) {
		return aflow.BadCallError("%s timed out. %s", name, advice)
	}
	if verr.ExitCode == 128 && (bytes.Contains(verr.Output, []byte("bad object")) ||
		bytes.Contains(verr.Output, []byte("bad revision")) ||
		bytes.Contains(verr.Output, []byte("unknown revision")) ||
		bytes.Contains(verr.Output, []byte("ambiguous argument")) ||
		bytes.Contains(verr.Output, []byte("no match")) ||
		bytes.Contains(verr.Output, []byte("no such path"))) {
		return aflow.BadCallError("%s failed: %s", name, bytes.TrimSpace(verr.Output))
	}
	if verr.ExitCode == 1 && len(verr.Output) == 0 {
		return nil // No matches is a valid result.
	}
	return err
}

func truncate(output []byte, maxLines int) string {
	lines := slices.Collect(bytes.Lines(output))
	if len(lines) <= maxLines {
		return string(output)
	}
	return fmt.Sprintf(`
Full output is too long, showing %v out of %v lines.

%s
`, maxLines, len(lines), slices.Concat(lines[:maxLines]))
}
