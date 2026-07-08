// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package crash

import (
	"encoding/json"
	"fmt"

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

func configureRunnerAction(ctx *aflow.Context, args ConfigureRunnerArgs) (struct{}, error) {
	workdir, err := ctx.TempDir()
	if err != nil {
		return struct{}{}, fmt.Errorf("failed to create workdir for configure-runner: %w", err)
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
		return struct{}{}, aflow.FlowError(err)
	}

	cfg, err := BuildConfig(targetCfg, workdir)
	if err != nil {
		return struct{}{}, fmt.Errorf("failed to build config for runner: %w", err)
	}

	// Initializes the VM pool and triggers background VM boot. Returns instantly.
	// If it fails here, it's a hard error (e.g., vm.Create failed).
	_, err = ctx.InitRunnerManager(cfg)
	if err != nil {
		return struct{}{}, aflow.FlowError(fmt.Errorf("RunnerManager init failed: %w", err))
	}

	log.Logf(1, "aflow: RunnerManager configured and background VM boot started successfully")
	return struct{}{}, nil
}
