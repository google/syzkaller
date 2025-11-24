// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"maps"
	_ "net/http/pprof"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/aflow"
	_ "github.com/google/syzkaller/pkg/aflow/flow"
	"github.com/google/syzkaller/pkg/aflow/trajectory"
	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/pkg/updater"
	"github.com/google/syzkaller/prog"
)

type Config struct {
	// Currently serves only net/http/pprof handlers.
	HTTP              string          `json:"http"`
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
	// Use fixed base commit for patching jobs (for testing).
	FixedBaseCommit string `json:"fixed_base_commit"`
	// Use large production LLM model (enabled by default, set to false for testing).
	LargeModel bool `json:"large_model"`
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
		LargeModel:      true,
	}
	if err := config.LoadFile(configFile, cfg); err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	tool.ServeHTTP(cfg.HTTP)
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
		LLMModel:     aflow.ModelName(cfg.LargeModel),
		CodeRevision: prog.GitRevision,
	}
	for _, flow := range aflow.Flows {
		req.Workflows = append(req.Workflows, dashapi.AIWorkflow{
			Type: flow.Type,
			Name: flow.Name,
		})
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
	results, jobErr := executeJob(ctx, cfg, dash, flow, resp)
	doneReq.Results = results
	if jobErr != nil {
		doneReq.Error = jobErr.Error()
	}
	if err := dash.AIJobDone(doneReq); err != nil {
		return false, err
	}
	if jobErr != nil {
		return false, jobErr
	}
	return true, nil
}

func executeJob(ctx context.Context, cfg *Config, dash *dashapi.Dashboard, flow *aflow.Flow,
	req *dashapi.AIJobPollResp) (map[string]any, error) {
	inputs := map[string]any{
		"CodesearchToolBin": cfg.CodesearchToolBin,
		"Syzkaller":         osutil.Abs(filepath.FromSlash("syzkaller/current")),
		"Image":             cfg.Image,
		"Type":              cfg.Type,
		"VM":                cfg.VM,
		"FixedBaseCommit":   cfg.FixedBaseCommit,
	}
	maps.Insert(inputs, maps.All(req.Args))
	onEvent := func(span *trajectory.Span) error {
		log.Logf(0, "%v", span)
		return dash.AITrajectoryLog(&dashapi.AITrajectoryReq{
			JobID: req.ID,
			Span:  span,
		})
	}
	return flow.Execute(ctx, cfg.LargeModel, osutil.Abs("workdir"), inputs, onEvent)
}
