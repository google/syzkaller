// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package crash

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/syzkaller/pkg/aflow"
)

type EnvironmentArgs struct {
	Query string `jsonschema:"grep search pattern in .config (e.g. 'CONFIG_USB'). Must be non-empty."`
}

type EnvironmentResult struct {
	Output string `jsonschema:"The environment metadata and matching kernel config entries."`
}

type EnvironmentState struct {
	TargetOS     string
	TargetArch   string
	KernelConfig string
	Type         string
	VM           json.RawMessage
}

const maxKconfigMatches = 100

var GetEnvironment = aflow.NewFuncTool("get-environment", getEnvironmentAction,
	"Inspects the target VM environment, architecture, and kernel build configuration (.config).")

func getEnvironmentAction(ctx *aflow.Context, state EnvironmentState, args EnvironmentArgs) (EnvironmentResult, error) {
	query := strings.TrimSpace(args.Query)
	if query == "" {
		return EnvironmentResult{}, aflow.BadCallError("Query parameter must not be empty")
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Target OS: %s\n", state.TargetOS)
	fmt.Fprintf(&b, "Target Arch: %s\n", state.TargetArch)
	if state.Type != "" {
		fmt.Fprintf(&b, "VM Type: %s\n", state.Type)
	}
	if len(state.VM) > 0 {
		var vmConfig struct {
			Cmdline  string `json:"cmdline"`
			QemuArgs string `json:"qemu_args"`
		}
		if err := json.Unmarshal(state.VM, &vmConfig); err == nil {
			if vmConfig.Cmdline != "" {
				fmt.Fprintf(&b, "VM Cmdline: %s\n", vmConfig.Cmdline)
			}
			if vmConfig.QemuArgs != "" {
				fmt.Fprintf(&b, "VM Qemu Args: %s\n", vmConfig.QemuArgs)
			}
		}
	}

	if state.KernelConfig == "" {
		b.WriteString("\nKernel config is not available.\n")
		return EnvironmentResult{Output: b.String()}, nil
	}

	b.WriteString("\nKernel Config (.config):\n")
	lowerQuery := strings.ToLower(query)

	matchedCount := 0
	for line := range strings.SplitSeq(state.KernelConfig, "\n") {
		if strings.Contains(strings.ToLower(line), lowerQuery) {
			fmt.Fprintf(&b, "%s\n", line)
			matchedCount++
			if matchedCount >= maxKconfigMatches {
				fmt.Fprintf(&b, "... (truncated remaining matches, please refine your query)\n")
				break
			}
		}
	}
	if matchedCount == 0 {
		fmt.Fprintf(&b, "No Kconfig options found matching query %q.\n", query)
	}

	return EnvironmentResult{Output: b.String()}, nil
}
