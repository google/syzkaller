// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package kernel

import (
	"fmt"
	"strings"

	"github.com/google/syzkaller/pkg/aflow"
)

type ConfigGrepArgs struct {
	Query string `jsonschema:"Case-insensitive substring to search for in .config (e.g. 'CONFIG_USB'). Must be non-empty."`
}

type ConfigGrepResult struct {
	Output string `jsonschema:"Matching kernel config entries."`
}

type configState struct {
	KernelConfig string
}

const maxConfigMatches = 100

var ToolConfigGrep = aflow.NewFuncTool("kernel-config-grep", grepConfigAction, `
Searches the kernel build configuration (.config) for lines containing the query substring (case-insensitive).
Use this tool to check if specific kernel configuration options, debug configs, or drivers are
enabled (e.g., 'CONFIG_USB', 'CONFIG_KASAN').
`)

func grepConfigAction(ctx *aflow.Context, state configState, args ConfigGrepArgs) (ConfigGrepResult, error) {
	query := strings.TrimSpace(args.Query)
	if query == "" {
		return ConfigGrepResult{}, aflow.BadCallError("Query parameter must not be empty")
	}

	if state.KernelConfig == "" {
		return ConfigGrepResult{Output: "Kernel config is not available.\n"}, nil
	}

	var b strings.Builder
	lowerQuery := strings.ToLower(query)

	matchedCount := 0
	for line := range strings.SplitSeq(state.KernelConfig, "\n") {
		if strings.Contains(strings.ToLower(line), lowerQuery) {
			fmt.Fprintf(&b, "%s\n", line)
			matchedCount++
			if matchedCount >= maxConfigMatches {
				fmt.Fprintf(&b, "... (truncated remaining matches, please refine your query)\n")
				break
			}
		}
	}
	if matchedCount == 0 {
		fmt.Fprintf(&b, "No kernel config options found matching query %q.\n", query)
	}

	return ConfigGrepResult{Output: b.String()}, nil
}
