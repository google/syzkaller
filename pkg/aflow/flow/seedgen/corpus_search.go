// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package seedgen

import (
	"fmt"
	"strings"

	"github.com/google/syzkaller/pkg/aflow"
)

type CorpusCodeSearchArgs struct {
	FunctionName string `jsonschema:"The name of the kernel function to find corpus programs for."`
}

type CorpusCodeSearchResult struct {
	Output string `jsonschema:"The output containing corpus programs."`
}

type CorpusCodeSearchState struct {
	CorpusExecutionCachedID string
}

var ToolCorpusCodeSearch = aflow.NewFuncTool("get-corpus-programs",
	func(ctx *aflow.Context, state CorpusCodeSearchState, args CorpusCodeSearchArgs) (CorpusCodeSearchResult, error) {
		if state.CorpusExecutionCachedID == "" {
			msg := "No corpus execution cached ID provided. Corpus programs are unavailable."
			return CorpusCodeSearchResult{Output: msg}, nil
		}

		data, err := aflow.RetrieveObject[corpusData](ctx, state.CorpusExecutionCachedID)
		if err != nil {
			return CorpusCodeSearchResult{}, aflow.BadCallError("failed to retrieve corpus execution data: %v", err)
		}

		hashes := data.FunctionMap[args.FunctionName]
		if len(hashes) == 0 {
			msg := fmt.Sprintf("No corpus programs found that reach function %q.", args.FunctionName)
			return CorpusCodeSearchResult{Output: msg}, nil
		}

		var b strings.Builder
		fmt.Fprintf(&b, "Found %d corpus programs reaching function %q.\n\n", len(hashes), args.FunctionName)

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
	}, "Provides examples of existing corpus programs that reached the specified kernel function.")
