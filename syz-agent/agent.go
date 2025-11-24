// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/flow/patching"
	"github.com/google/syzkaller/pkg/aflow/journal"
	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/pkg/updater"
)

type Config struct {
	DashboardAddr     string          `json:"dashboard_addr"`
	DashboardClient   string          `json:"dashboard_client"` // Global non-namespace client.
	DashboardKey      string          `json:"dashboard_key"`
	SyzkallerRepo     string          `json:"syzkaller_repo"`
	SyzkallerBranch   string          `json:"syzkaller_branch"`
	CodesearchToolBin string          `json:"codesearch_tool_bin"`
	KernelConfig      string          `json:"kernel_config"`
	Target            string          `json:"target"`
	Image             string          `json:"image"`
	Type              string          `json:"type"`
	VM                json.RawMessage `json:"vm"`
}

func main() {
	var (
		flagConfig        = flag.String("config", "", "config file")
		flagExitOnUpgrade = flag.Bool("exit-on-upgrade", false,
			"exit after a syz-ci upgrade is applied; otherwise syz-ci restarts")
		flagAutoUpdate = flag.Bool("autoupdate", true, "auto-update the binary (for testing)")
	)
	defer tool.Init()()
	log.SetName("syz-agent")
	if err := run(*flagConfig, *flagExitOnUpgrade, *flagAutoUpdate); err != nil {
		log.Fatal(err)
	}
}

func run(configFile string, exitOnUpgrade, autoUpdate bool) error {
	cfg := &Config{
		SyzkallerRepo:   "https://github.com/google/syzkaller.git",
		SyzkallerBranch: "master",
	}
	if err := config.LoadFile(configFile, cfg); err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	os, vmarch, arch, _, _, err := mgrconfig.SplitTarget(cfg.Target)
	if err != nil {
		return err
	}
	dash, err := dashapi.New(cfg.DashboardClient, cfg.DashboardAddr, cfg.DashboardKey)
	if err != nil {
		return err
	}
	buildSem := osutil.NewSemaphore(1)
	updater, err := updater.New(&updater.Config{
		ExitOnUpdate:    exitOnUpgrade,
		BuildSem:        buildSem,
		SyzkallerRepo:   cfg.SyzkallerRepo,
		SyzkallerBranch: cfg.SyzkallerBranch,
		Targets: map[updater.Target]bool{
			updater.Target{
				OS:     os,
				VMArch: vmarch,
				Arch:   arch,
			}: true,
		},
	})
	if err != nil {
		return err
	}
	updatePending := make(chan struct{})
	shutdownPending := make(chan struct{})
	osutil.HandleInterrupts(shutdownPending)
	updater.UpdateOnStart(autoUpdate, updatePending, shutdownPending)

	ctx, stop := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			ok, err := poll(ctx, cfg, dash)
			if err != nil {
				log.Error(err)
				dash.LogError("syz-agent", "%v", err)
			}
			var delay time.Duration
			if !ok {
				// Don't poll dashboard too often, if there are no jobs,
				// or errors are happenning.
				delay = 10 * time.Second
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
		}
	}()

	select {
	case <-shutdownPending:
	case <-updatePending:
	}
	stop()
	wg.Wait()

	select {
	case <-shutdownPending:
	default:
		updater.UpdateAndRestart()
	}
	return nil
}

func poll(ctx context.Context, cfg *Config, dash *dashapi.Dashboard) (bool, error) {
	req := &dashapi.AIJobPollReq{
		Workflows: slices.Collect(maps.Keys(aflow.Flows)),
	}
	resp, err := dash.AIJobPoll(req)
	if err != nil {
		return false, err
	}
	if resp.ID == "" {
		return false, nil
	}
	flow := aflow.Flows[resp.Workflow]
	if flow == nil {
		return false, fmt.Errorf("unsupported flow %q", resp.Workflow)
	}
	doneReq := &dashapi.AIJobDoneReq{
		ID: resp.ID,
	}
	switch flow.Type {
	case patching.Type:
		doneReq.Patching, err = patchingJob(ctx, cfg, dash, flow, resp)
	default:
		err = fmt.Errorf("unsupported flow type %q", flow.Type)
	}
	if err != nil {
		doneReq.Error = err.Error()
	}
	if err := dash.AIJobDone(doneReq); err != nil {
		return false, err
	}
	return true, nil
}

func patchingJob(ctx context.Context, cfg *Config, dash *dashapi.Dashboard, flow *aflow.Flow,
	req *dashapi.AIJobPollResp) (*dashapi.AIPatchingResult, error) {
	inputs := patching.Inputs{
		ReproOpts:         req.Patching.ReproOpts,
		ReproSyz:          req.Patching.ReproSyz,
		ReproC:            req.Patching.ReproC,
		KernelConfig:      req.Patching.KernelConfig,
		SyzkallerCommit:   req.Patching.SyzkallerCommit,
		CodesearchToolBin: cfg.CodesearchToolBin,
		Syzkaller:         osutil.Abs(filepath.FromSlash("syzkaller/current")),
		Image:             cfg.Image,
		Type:              cfg.Type,
		VM:                cfg.VM,
	}
	onEvent := func(ev *journal.Event) error {
		log.Logf(0, "%v%v", strings.Repeat("  ", ev.Nesting), ev.Description())
		dump, err := json.MarshalIndent(ev, "", "\t")
		if err != nil {
			panic(err)
		}
		fmt.Printf("%s\n\n", dump)
		return dash.AIJournal(&dashapi.AIJournalReq{
			JobID: req.ID,
			Event: ev,
		})
	}
	res, err := flow.Execute(ctx, false, osutil.Abs("workdir"), inputs, nil, onEvent)
	if err != nil {
		return nil, err
	}
	outputs := res.(patching.Outputs)
	return &dashapi.AIPatchingResult{
		PatchDescription: outputs.PatchDescription,
		PatchDiff:        outputs.PatchDiff,
	}, nil
}
