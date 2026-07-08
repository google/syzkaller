// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzlang

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/syzspec"
)

type CorpusCodeSearchArgs struct {
	FunctionName string `json:",omitempty" jsonschema:"Kernel function to find corpus programs for (optional)."`
	SyscallName  string `json:",omitempty" jsonschema:"Syzlang syscall name/substring (optional)."`
}

type CorpusCodeSearchResult struct {
	Output string `jsonschema:"The output containing corpus programs."`
}

type CorpusCodeSearchState struct {
	CorpusExecutionCachedID string
}

var (
	ToolCorpusCodeSearch = aflow.NewFuncTool("get-corpus-programs", corpusCodeSearch,
		"Provides examples of existing corpus programs reaching a function or using a syscall.")
	CorpusCodeSearch = ToolCorpusCodeSearch
)

func corpusCodeSearch(ctx *aflow.Context, state CorpusCodeSearchState,
	args CorpusCodeSearchArgs) (CorpusCodeSearchResult, error) {
	if state.CorpusExecutionCachedID == "" {
		msg := "No corpus execution cached ID provided. Corpus programs are unavailable."
		return CorpusCodeSearchResult{Output: msg}, nil
	}

	if (args.FunctionName == "") == (args.SyscallName == "") {
		return CorpusCodeSearchResult{}, aflow.BadCallError("exactly one of FunctionName or SyscallName must be provided")
	}

	data, err := aflow.RetrieveObject[syzspec.CorpusData](ctx, state.CorpusExecutionCachedID)
	if err != nil {
		return CorpusCodeSearchResult{}, aflow.BadCallError("failed to retrieve corpus execution data: %v", err)
	}

	var hashes []string
	var queryMsg string
	if args.FunctionName != "" {
		hashes = data.FunctionMap[args.FunctionName]
		queryMsg = fmt.Sprintf("reaching function %q", args.FunctionName)
	} else if args.SyscallName != "" {
		// Keys in SyscallMap are fully qualified syzlang names (e.g. "ioctl$KVM_CREATE_VM").
		// We use case-insensitive substring matching to allow users to search using partial
		// names (like "KVM" or "ioctl").
		matchedHashes := make(map[string]bool)
		queryLower := strings.ToLower(args.SyscallName)
		for name, hList := range data.SyscallMap {
			if strings.Contains(strings.ToLower(name), queryLower) {
				for _, h := range hList {
					matchedHashes[h] = true
				}
			}
		}
		hashes = slices.Collect(maps.Keys(matchedHashes))
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

	for i, h := range hashes {
		progStr, ok := data.Programs[h]
		if !ok {
			continue
		}
		fmt.Fprintf(&b, "=== Program %d ===\n%s\n", i+1, strings.TrimSpace(progStr))
	}

	return CorpusCodeSearchResult{Output: b.String()}, nil
}
