// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"maps"
	_ "net/http/pprof"
	"path/filepath"
	"slices"
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
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/prog"
)

type Config struct {
	// Currently serves only net/http/pprof handlers.
	HTTP            string          `json:"http"`
	DashboardAddr   string          `json:"dashboard_addr"`
	DashboardClient string          `json:"dashboard_client"` // Global non-namespace client.
	DashboardKey    string          `json:"dashboard_key"`
	SyzkallerRepo   string          `json:"syzkaller_repo"`
	SyzkallerBranch string          `json:"syzkaller_branch"`
	KernelConfig    string          `json:"kernel_config"`
	Target          string          `json:"target"`
	Image           string          `json:"image"`
	Type            string          `json:"type"`
	VM              json.RawMessage `json:"vm"`
	// Max workdir cache size (defaults to 1TB).
	// The whole workdir may be slightly larger, since e.g. kernel checkout is not accounted here.
	CacheSize uint64 `json:"cache_size"`
	// Use fixed base commit for patching jobs (for testing).
	FixedBaseCommit string `json:"fixed_base_commit"`
	// Use a different repo than torvalds's mainline.
	FixedRepository string `json:"repo"`
	// Use this LLM model (for testing, if empty use workflow-default model).
	Model string `json:"model"`
	// Names of workflows to serve (all if not set, mainly for testing/local experimentation).
	Workflows []string `json:"workflows"`
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
		CacheSize:       1 << 40, // 1TB should be enough for everyone!
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
		ReportBuildError: func(commit *vcs.Commit, _ string, buildErr error) {
			reportBuildError(commit, buildErr)
		},
		ExitOnUpdate:    exitOnUpgrade,
		BuildSem:        buildSem,
		SyzkallerRepo:   cfg.SyzkallerRepo,
		SyzkallerBranch: cfg.SyzkallerBranch,
		Targets: map[updater.Target]bool{
			{
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

	const workdir = "workdir"
	cache, err := aflow.NewCache(filepath.Join(workdir, "cache"), cfg.CacheSize)
	if err != nil {
		return err
	}

	s := &Server{
		cfg:             cfg,
		dash:            dash,
		cache:           cache,
		workdir:         workdir,
		overQuotaModels: make(map[string]time.Time),
	}

	ctx, stop := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			ok, err := s.poll(ctx)
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

func reportBuildError(commit *vcs.Commit, buildErr error) {
	var output []byte
	var verbose *osutil.VerboseError
	title := buildErr.Error()
	if errors.As(buildErr, &verbose) {
		output = verbose.Output
	}
	path, err := osutil.WriteTempFile(output)
	if err != nil {
		log.Logf(0, "failed to record syzkaller build error: %v", err)
		return
	}
	log.Logf(0, "syzkaller (rev. %v) failed to build: %v, see more details in %v",
		commit.Hash, title, path)
}

type Server struct {
	cfg             *Config
	dash            *dashapi.Dashboard
	cache           *aflow.Cache
	workdir         string
	overQuotaModels map[string]time.Time
}

func (s *Server) poll(ctx context.Context) (bool, error) {
	s.resetModelQuota()
	req := &dashapi.AIJobPollReq{
		CodeRevision: prog.GitRevision,
	}
	for _, flow := range aflow.Flows {
		if len(s.cfg.Workflows) != 0 && !slices.Contains(s.cfg.Workflows, flow.Name) ||
			s.modelOverQuota(flow) {
			continue
		}
		req.Workflows = append(req.Workflows, dashapi.AIWorkflow{
			Type: flow.Type,
			Name: flow.Name,
		})
	}
	if len(req.Workflows) == 0 {
		log.Logf(0, "no workflows to query")
		return false, nil
	}
	log.Logf(0, "querying jobs for %v", req.Workflows)
	resp, err := s.dash.AIJobPoll(req)
	if err != nil {
		return false, err
	}
	if resp.ID == "" {
		return false, nil
	}
	log.Logf(0, "starting job %v %v", resp.Workflow, resp.ID)
	defer log.Logf(0, "finished job %v %v", resp.Workflow, resp.ID)
	doneReq := &dashapi.AIJobDoneReq{
		ID: resp.ID,
	}
	results, jobErr := s.executeJob(ctx, resp)
	doneReq.Results = results
	if jobErr != nil {
		doneReq.Error = jobErr.Error()
		if model := aflow.IsModelQuotaError(jobErr); model != "" {
			// If a model is over quota, we will avoid requesting more jobs
			// for workflows that use the model.
			// There is no easy way to handle the current job, though.
			// We would either need to tell dashboard to have a special status,
			// and retry the job the next day. Or, somehow stack the job locally,
			// and resume it the next day. This looks rather complex, so instead
			// we just drop it on the floor and don't report anything to
			// the dashboard at all. For the dashboard it will look like
			// the server has crashed while executing the job, and it should
			// eventually retry it on common grounds.
			now := time.Now()
			s.overQuotaModels[model] = now
			log.Logf(0, "model %v is over daily quota until %v",
				model, aflow.QuotaResetTime(now))
			return true, nil
		}
	}
	log.Logf(0, "done executing job %v %v", resp.Workflow, resp.ID)
	if err := s.dash.AIJobDone(doneReq); err != nil {
		return false, err
	}
	if jobErr != nil && !aflow.IsFlowError(jobErr) {
		return false, jobErr
	}
	return true, nil
}

func (s *Server) executeJob(ctx context.Context, req *dashapi.AIJobPollResp) (map[string]any, error) {
	flow := aflow.Flows[req.Workflow]
	if flow == nil {
		return nil, fmt.Errorf("unsupported flow %q", req.Workflow)
	}
	inputs := map[string]any{
		"Syzkaller":       osutil.Abs(filepath.FromSlash("syzkaller/current")),
		"Image":           s.cfg.Image,
		"Type":            s.cfg.Type,
		"VM":              s.cfg.VM,
		"FixedBaseCommit": s.cfg.FixedBaseCommit,
		"FixedRepository": s.cfg.FixedRepository,
	}
	maps.Insert(inputs, maps.All(req.Args))
	onEvent := func(span *trajectory.Span) error {
		log.Logf(0, "%v", span)
		return s.dash.AITrajectoryLog(&dashapi.AITrajectoryReq{
			JobID: req.ID,
			Span:  span,
		})
	}
	return flow.Execute(ctx, s.cfg.Model, s.workdir, inputs, s.cache, onEvent)
}

func (s *Server) modelOverQuota(flow *aflow.Flow) bool {
	if s.cfg.Model != "" {
		return !s.overQuotaModels[s.cfg.Model].IsZero()
	}
	for _, model := range flow.Models {
		if !s.overQuotaModels[model].IsZero() {
			return true
		}
	}
	return false
}

func (s *Server) resetModelQuota() {
	for model, when := range s.overQuotaModels {
		if aflow.QuotaResetTime(when).After(time.Now()) {
			log.Logf(0, "model %v daily quota is replenished", model)
			delete(s.overQuotaModels, model)
		}
	}
}
