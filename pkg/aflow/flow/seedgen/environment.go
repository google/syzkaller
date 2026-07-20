// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package seedgen

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/google/syzkaller/pkg/aflow"
)

type EnvironmentArgs struct {
	Query string `jsonschema:"Optional search pattern to grep in the kernel .config (e.g. 'CONFIG_USB' or 'CONFIG_NET')."`
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

var ToolGetEnvironment = aflow.NewFuncTool("get-environment", getEnvironmentAction,
	"Inspects the target VM environment, architecture, and kernel build configuration (.config).")

func getEnvironmentAction(ctx *aflow.Context, state EnvironmentState, args EnvironmentArgs) (EnvironmentResult, error) {
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

	configContent := state.KernelConfig
	if _, err := os.Stat(state.KernelConfig); err == nil {
		data, err := os.ReadFile(state.KernelConfig)
		if err == nil {
			configContent = string(data)
		}
	}

	b.WriteString("\nKernel Config (.config):\n")
	lines := strings.Split(configContent, "\n")
	query := strings.TrimSpace(args.Query)

	if query == "" {
		matchedCount := 0
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			fmt.Fprintf(&b, "%s\n", line)
			matchedCount++
			if matchedCount >= 100 {
				fmt.Fprintf(&b, "... (truncated remaining lines; specify query parameter to filter)\n")
				break
			}
		}
	} else {
		matchedCount := 0
		for _, line := range lines {
			if strings.Contains(strings.ToLower(line), strings.ToLower(query)) {
				fmt.Fprintf(&b, "%s\n", line)
				matchedCount++
				if matchedCount >= 100 {
					fmt.Fprintf(&b, "... (truncated remaining matches)\n")
					break
				}
			}
		}
		if matchedCount == 0 {
			fmt.Fprintf(&b, "No Kconfig options found matching query %q.\n", query)
		}
	}

	return EnvironmentResult{Output: b.String()}, nil
}
