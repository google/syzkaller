// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package crash

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/log"
)

var ActionConfigureRunner = aflow.NewFuncAction("configure-runner", configureRunnerAction)

type ConfigureRunnerArgs struct {
	TargetOS   string
	TargetArch string
	Syzkaller  string
	Image      string
	Type       string
	VM         json.RawMessage
	KernelSrc  string
	KernelObj  string
	Snapshot   bool
}

type ConfigureRunnerResult struct {
	EnvironmentPrompt string
}

func configureRunnerAction(ctx *aflow.Context, args ConfigureRunnerArgs) (ConfigureRunnerResult, error) {
	workdir, err := ctx.TempDir()
	if err != nil {
		return ConfigureRunnerResult{}, fmt.Errorf("failed to create workdir for configure-runner: %w", err)
	}

	targetCfg := TargetConfig{
		TargetArch: args.TargetArch,
		Syzkaller:  args.Syzkaller,
		Image:      args.Image,
		Type:       args.Type,
		VM:         args.VM,
		KernelSrc:  args.KernelSrc,
		KernelObj:  args.KernelObj,
		Snapshot:   args.Snapshot,
	}

	if err := targetCfg.Validate(); err != nil {
		return ConfigureRunnerResult{}, aflow.FlowError(err)
	}

	cfg, err := BuildConfig(targetCfg, workdir)
	if err != nil {
		return ConfigureRunnerResult{}, fmt.Errorf("failed to build config for runner: %w", err)
	}

	// Initializes the VM pool and triggers background VM boot. Returns instantly.
	// If it fails here, it's a hard error (e.g., vm.Create failed).
	_, err = ctx.InitRunnerManager(cfg)
	if err != nil {
		return ConfigureRunnerResult{}, aflow.FlowError(fmt.Errorf("RunnerManager init failed: %w", err))
	}

	log.Logf(1, "aflow: RunnerManager configured and background VM boot started successfully")
	return ConfigureRunnerResult{
		EnvironmentPrompt: formatEnvironment(args),
	}, nil
}

func formatEnvironment(args ConfigureRunnerArgs) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Target OS: %s\n", args.TargetOS)
	fmt.Fprintf(&b, "Target Arch: %s\n", args.TargetArch)
	if args.Type != "" {
		fmt.Fprintf(&b, "VM Type: %s\n", args.Type)
	}
	if len(args.VM) > 0 {
		var vmConfig struct {
			Cmdline  string `json:"cmdline"`
			QemuArgs string `json:"qemu_args"`
		}
		if err := json.Unmarshal(args.VM, &vmConfig); err == nil {
			if vmConfig.Cmdline != "" {
				fmt.Fprintf(&b, "VM Cmdline: %s\n", vmConfig.Cmdline)
			}
			if vmConfig.QemuArgs != "" {
				fmt.Fprintf(&b, "VM Qemu Args: %s\n", vmConfig.QemuArgs)
			}
		}
	}
	return b.String()
}
