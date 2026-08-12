// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzlang

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/syzspec"
	"github.com/google/syzkaller/pkg/osutil"
)

type CorpusCodeSearchArgs struct {
	FunctionName string `json:",omitempty" jsonschema:"Kernel function to find corpus programs for (optional)."`
	SyscallName  string `json:",omitempty" jsonschema:"Syzlang syscall name/substring (optional)."`
}

type CorpusCodeSearchResult struct {
	Output string `jsonschema:"The output containing corpus programs."`
}

type CorpusCodeSearchState struct {
	CorpusDir string
}

var CorpusCodeSearch = aflow.NewFuncTool("get-corpus-programs", corpusCodeSearch,
	"Provides examples of existing corpus programs reaching a function or using a syscall.")

func corpusCodeSearch(ctx *aflow.Context, state CorpusCodeSearchState,
	args CorpusCodeSearchArgs) (CorpusCodeSearchResult, error) {
	if state.CorpusDir == "" {
		msg := "No corpus directory provided. Corpus programs are unavailable."
		return CorpusCodeSearchResult{Output: msg}, nil
	}

	if (args.FunctionName == "") == (args.SyscallName == "") {
		return CorpusCodeSearchResult{}, aflow.BadCallError("exactly one of FunctionName or SyscallName must be provided")
	}

	indexFile := filepath.Join(state.CorpusDir, "index.json")
	data, err := osutil.ReadJSON[syzspec.CorpusData](indexFile)
	if err != nil {
		return CorpusCodeSearchResult{}, aflow.BadCallError("failed to read corpus execution data: %v", err)
	}

	var hashes []string
	var queryMsg string
	if args.FunctionName != "" {
		hashes = data.ProgramsForFunction(args.FunctionName)
		queryMsg = fmt.Sprintf("reaching function %q", args.FunctionName)
	} else if args.SyscallName != "" {
		hashes = data.ProgramsForSyscall(args.SyscallName)
		queryMsg = fmt.Sprintf("containing syscall matching %q", args.SyscallName)
	}

	if len(hashes) == 0 {
		msg := fmt.Sprintf("No corpus programs found %s.", queryMsg)
		return CorpusCodeSearchResult{Output: msg}, nil
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Found %d corpus programs %s.\n\n", len(hashes), queryMsg)

	// Limit the output to 5 programs to prevent context bloat.
	limit := 5
	if len(hashes) > limit {
		fmt.Fprintf(&b, "Showing the first %d programs:\n\n", limit)
		hashes = hashes[:limit]
	}

	programs, err := data.ReadPrograms(state.CorpusDir, hashes)
	if err != nil {
		return CorpusCodeSearchResult{}, aflow.BadCallError("failed to read program buckets: %v", err)
	}

	for i, h := range hashes {
		progStr, ok := programs[h]
		if !ok {
			continue
		}
		fmt.Fprintf(&b, "=== Program %d ===\n%s\n", i+1, strings.TrimSpace(ctx.ReplaceBlobs(progStr)))
	}

	return CorpusCodeSearchResult{Output: b.String()}, nil
}
