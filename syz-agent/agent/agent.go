// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"maps"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/aflow"
	_ "github.com/google/syzkaller/pkg/aflow/flow"
	"github.com/google/syzkaller/pkg/aflow/trajectory"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/pkg/updater"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/prog"
)

func main() {
	var (
		flagConfig        = flag.String("config", "", "config file")
		flagExitOnUpgrade = flag.Bool("exit-on-upgrade", false,
			"exit after a syz-ci upgrade is applied; otherwise syz-ci restarts")
		flagAutoUpdate = flag.Bool("autoupdate", false, "auto-update the binary")
		flagSyzkaller  = flag.String("syzkaller", "", "path to syzkaller checkout (bypasses updater)")
		flagName       = flag.String("name", "", "agent name (must be unique!)")
	)
	defer tool.Init()()
	log.SetName("syz-agent")
	if err := run(*flagConfig, *flagExitOnUpgrade, *flagAutoUpdate,
		*flagSyzkaller, *flagName); err != nil {
		log.Fatal(err)
	}
}

const workdir = "workdir"

func run(configFile string, exitOnUpgrade, autoUpdate bool, syzkallerDir, name string) error {
	cfg, err := loadConfig(configFile)
	if err != nil {
		return err
	}
	if name == "" {
		return fmt.Errorf("agent name must be specified")
	}
	kernelConfig, err := os.ReadFile(cfg.KernelConfig)
	if err != nil {
		return err
	}
	cfg.kernelConfigData = string(kernelConfig)

	if cfg.HTTP != "" {
		tool.ServeHTTP(cfg.HTTP)
	}

	var updatePending, shutdownPending chan struct{}
	var upd *updater.Updater

	if syzkallerDir == "" {
		upd, err = setupUpdater(cfg, cfg.Target, exitOnUpgrade)
		if err != nil {
			return err
		}
		syzkallerDir = filepath.FromSlash("syzkaller/current")
	}

	cache, err := aflow.NewCache(filepath.Join(workdir, "cache"), cfg.CacheSize)
	if err != nil {
		return err
	}

	dash, err := dashapi.New(cfg.DashboardClient, cfg.DashboardAddr, cfg.DashboardKey)
	if err != nil {
		return err
	}

	s := &Server{
		name:            name,
		cfg:             cfg,
		dash:            dash,
		cache:           cache,
		workdir:         workdir,
		syzkallerDir:    syzkallerDir,
		overQuotaModels: make(map[string]time.Time),
	}

	if cfg.MCP {
		http.Handle("/", mcpHandler(initState(cfg, syzkallerDir), workdir, cache))
		select {}
	}

	shutdownPending = make(chan struct{})
	osutil.HandleInterrupts(shutdownPending)
	if upd != nil {
		updatePending = make(chan struct{})
		upd.UpdateOnStart(autoUpdate, updatePending, shutdownPending)
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
		if upd != nil {
			upd.UpdateAndRestart()
		}
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

func setupUpdater(cfg *Config, target string, exitOnUpgrade bool) (*updater.Updater, error) {
	osVal, vmarch, arch, _, _, err := mgrconfig.SplitTarget(target)
	if err != nil {
		return nil, err
	}
	buildSem := osutil.NewSemaphore(1)
	return updater.New(&updater.Config{
		ReportBuildError: func(commit *vcs.Commit, _ string, buildErr error) {
			reportBuildError(commit, buildErr)
		},
		ExitOnUpdate:    exitOnUpgrade,
		BuildSem:        buildSem,
		SyzkallerRepo:   cfg.SyzkallerRepo,
		SyzkallerBranch: cfg.SyzkallerBranch,
		Targets: map[updater.Target]bool{
			{
				OS:     osVal,
				VMArch: vmarch,
				Arch:   arch,
			}: true,
		},
		MakeTargets: []string{"agent"},
	})
}

type Server struct {
	name            string
	cfg             *Config
	dash            *dashapi.Dashboard
	cache           *aflow.Cache
	workdir         string
	syzkallerDir    string
	overQuotaModels map[string]time.Time
}

func (s *Server) poll(ctx context.Context) (bool, error) {
	s.resetModelQuota()
	req := &dashapi.AIJobPollReq{
		AgentName:    s.name,
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
		// Errors may include verbose errors from running git/make/grep/etc binaries.
		// By default the verbose stdout/stderr output is not included in errors,
		// but we want to include it here (otherwise it will be lost, and the error
		// will just say "command X failed with exit status Y").
		doneReq.Error = osutil.VerboseMessage(jobErr)
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
		if errors.Is(jobErr, context.Canceled) && s.name != "" {
			// Not reporting job as failed allows the agent to pick it again immediately after restart.
			log.Logf(0, "job %v %v cancelled due to shutdown, skipping reporting to dashboard", resp.Workflow, resp.ID)
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

func (s *Server) executeJob(ctx context.Context, req *dashapi.AIJobPollResp) (out map[string]any, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic during job execution: %v", r)
		}
	}()
	flow := aflow.Flows[req.Workflow]
	if flow == nil {
		return nil, fmt.Errorf("unsupported flow %q", req.Workflow)
	}
	inputs := initState(s.cfg, s.syzkallerDir)
	maps.Insert(inputs, maps.All(req.Args))
	onEvent := func(span *trajectory.Span) error {
		log.Logf(0, "%v", span)
		return s.dash.AITrajectoryLog(&dashapi.AITrajectoryReq{
			AgentName: s.cfg.DashboardClient,
			JobID:     req.ID,
			Span:      span,
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

func initState(cfg *Config, syzkallerDir string) map[string]any {
	return map[string]any{
		"Syzkaller":       osutil.Abs(syzkallerDir),
		"Image":           cfg.Image,
		"Type":            cfg.Type,
		"VM":              cfg.VM,
		"KernelConfig":    cfg.kernelConfigData,
		"FixedBaseCommit": cfg.FixedBaseCommit,
		"FixedRepository": cfg.FixedRepository,
	}
}
