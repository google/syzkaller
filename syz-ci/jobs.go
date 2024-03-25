// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/bisect"
	"github.com/google/syzkaller/pkg/build"
	"github.com/google/syzkaller/pkg/debugtracer"
	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/vm"
)

type JobManager struct {
	cfg               *Config
	dash              *dashapi.Dashboard
	managers          []*Manager
	parallelJobFilter *ManagerJobs
	shutdownPending   <-chan struct{}
}

type JobProcessor struct {
	*JobManager
	name           string
	instanceSuffix string
	knownCommits   map[string]bool
	baseDir        string
	jobFilter      *ManagerJobs
	jobTicker      <-chan time.Time
	commitTicker   <-chan time.Time
}

func newJobManager(cfg *Config, managers []*Manager, shutdownPending chan struct{}) (*JobManager, error) {
	dash, err := dashapi.New(cfg.DashboardClient, cfg.DashboardAddr, cfg.DashboardKey)
	if err != nil {
		return nil, err
	}
	return &JobManager{
		cfg:             cfg,
		dash:            dash,
		managers:        managers,
		shutdownPending: shutdownPending,
		// For now let's only parallelize patch testing requests.
		parallelJobFilter: &ManagerJobs{TestPatches: true},
	}, nil
}

// startLoop starts a job loop in parallel and returns a blocking function
// to gracefully stop job processing.
func (jm *JobManager) startLoop(wg *sync.WaitGroup) func() {
	stop := make(chan struct{})
	done := make(chan struct{}, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		jm.loop(stop)
		done <- struct{}{}
	}()
	return func() {
		close(stop)
		<-done
	}
}

func (jm *JobManager) loop(stop chan struct{}) {
	if err := jm.resetJobs(); err != nil {
		if jm.dash != nil {
			jm.dash.LogError("syz-ci", "reset jobs failed: %v", err)
		}
		return
	}
	commitTicker := time.NewTicker(time.Duration(jm.cfg.CommitPollPeriod) * time.Second)
	defer commitTicker.Stop()
	jobTicker := time.NewTicker(time.Duration(jm.cfg.JobPollPeriod) * time.Second)
	defer jobTicker.Stop()
	var wg sync.WaitGroup
	for main := true; ; main = false {
		jp := &JobProcessor{
			JobManager: jm,
			jobTicker:  jobTicker.C,
		}
		if main {
			jp.instanceSuffix = "-job"
			jp.baseDir = osutil.Abs("jobs")
			jp.commitTicker = commitTicker.C
			jp.knownCommits = make(map[string]bool)
		} else {
			jp.instanceSuffix = "-job-parallel"
			jp.baseDir = osutil.Abs("jobs-2")
			jp.jobFilter = jm.parallelJobFilter
		}
		jp.name = fmt.Sprintf("%v%v", jm.cfg.Name, jp.instanceSuffix)
		wg.Add(1)
		go func() {
			defer wg.Done()
			jp.loop(stop)
		}()
		if !main || !jm.needParallelProcessor() {
			break
		}
	}
	wg.Wait()
}

func (jm *JobManager) needParallelProcessor() bool {
	if !jm.cfg.ParallelJobs {
		return false
	}
	for _, mgr := range jm.managers {
		if mgr.mgrcfg.Jobs.Filter(jm.parallelJobFilter).AnyEnabled() {
			return true
		}
	}
	return false
}

func (jm *JobManager) resetJobs() error {
	managerNames := []string{}
	for _, mgr := range jm.managers {
		if mgr.mgrcfg.Jobs.AnyEnabled() {
			managerNames = append(managerNames, mgr.name)
		}
	}
	if len(managerNames) > 0 {
		return jm.dash.JobReset(&dashapi.JobResetReq{Managers: managerNames})
	}
	return nil
}

func (jp *JobProcessor) loop(stop chan struct{}) {
	jp.Logf(0, "job loop started")
loop:
	for {
		// Check jp.stop separately first, otherwise if stop signal arrives during a job execution,
		// we can still grab the next job with 50% probability.
		select {
		case <-stop:
			break loop
		default:
		}
		// Similar for commit polling: if we grab 2-3 bisect jobs in a row,
		// it can delay commit polling by days.
		select {
		case <-jp.commitTicker:
			jp.pollCommits()
		default:
		}
		select {
		case <-jp.jobTicker:
			jp.pollJobs()
		case <-jp.commitTicker:
			jp.pollCommits()
		case <-stop:
			break loop
		}
	}
	jp.Logf(0, "job loop stopped")
}

func (jp *JobProcessor) pollCommits() {
	for _, mgr := range jp.managers {
		if !mgr.mgrcfg.Jobs.PollCommits {
			continue
		}
		if err := jp.pollManagerCommits(mgr); err != nil {
			jp.Errorf("failed to poll commits on %v: %v", mgr.name, err)
		}
	}
}

func brokenRepo(url string) bool {
	// TODO(dvyukov): mmots contains weird squashed commits titled "linux-next" or "origin",
	// which contain hundreds of other commits. This makes fix attribution totally broken.
	return strings.Contains(url, "git.cmpxchg.org/linux-mmots")
}

func (jp *JobProcessor) pollManagerCommits(mgr *Manager) error {
	resp, err := mgr.dash.CommitPoll()
	if err != nil {
		return err
	}
	jp.Logf(0, "polling commits for %v: repos %v, commits %v", mgr.name, len(resp.Repos), len(resp.Commits))
	if len(resp.Repos) == 0 {
		return fmt.Errorf("no repos")
	}
	commits := make(map[string]*vcs.Commit)
	for i, repo := range resp.Repos {
		if brokenRepo(repo.URL) {
			continue
		}
		if resp.ReportEmail != "" {
			commits1, err := jp.pollRepo(mgr, repo.URL, repo.Branch, resp.ReportEmail)
			if err != nil {
				jp.Errorf("failed to poll %v %v: %v", repo.URL, repo.Branch, err)
				continue
			}
			jp.Logf(1, "got %v commits from %v/%v repo", len(commits1), repo.URL, repo.Branch)
			for _, com := range commits1 {
				// Only the "main" repo is the source of true hashes.
				if i != 0 {
					com.Hash = ""
				}
				// Not overwrite existing commits, in particular commit from the main repo with hash.
				if _, ok := commits[com.Title]; !ok && !jp.knownCommits[com.Title] && len(commits) < 100 {
					commits[com.Title] = com
					jp.knownCommits[com.Title] = true
				}
			}
		}
		if i == 0 && len(resp.Commits) != 0 {
			commits1, err := jp.getCommitInfo(mgr, repo.URL, repo.Branch, resp.Commits)
			if err != nil {
				jp.Errorf("failed to poll %v %v: %v", repo.URL, repo.Branch, err)
				continue
			}
			jp.Logf(1, "got %v commit infos from %v/%v repo", len(commits1), repo.URL, repo.Branch)
			for _, com := range commits1 {
				// GetCommitByTitle does not accept ReportEmail and does not return tags,
				// so don't replace the existing commit.
				if _, ok := commits[com.Title]; !ok {
					commits[com.Title] = com
				}
			}
		}
	}
	results := make([]dashapi.Commit, 0, len(commits))
	for _, com := range commits {
		results = append(results, dashapi.Commit{
			Hash:   com.Hash,
			Title:  com.Title,
			Author: com.Author,
			BugIDs: com.Tags,
			Date:   com.Date,
		})
	}
	return mgr.dash.UploadCommits(results)
}

func (jp *JobProcessor) pollRepo(mgr *Manager, URL, branch, reportEmail string) ([]*vcs.Commit, error) {
	dir := filepath.Join(jp.baseDir, mgr.managercfg.TargetOS, "kernel")
	repo, err := vcs.NewRepo(mgr.managercfg.TargetOS, mgr.managercfg.Type, dir)
	if err != nil {
		return nil, fmt.Errorf("failed to create kernel repo: %w", err)
	}
	if _, err = repo.CheckoutBranch(URL, branch); err != nil {
		return nil, fmt.Errorf("failed to checkout kernel repo %v/%v: %w", URL, branch, err)
	}
	return repo.ExtractFixTagsFromCommits("HEAD", reportEmail)
}

func (jp *JobProcessor) getCommitInfo(mgr *Manager, URL, branch string, commits []string) ([]*vcs.Commit, error) {
	dir := filepath.Join(jp.baseDir, mgr.managercfg.TargetOS, "kernel")
	repo, err := vcs.NewRepo(mgr.managercfg.TargetOS, mgr.managercfg.Type, dir)
	if err != nil {
		return nil, fmt.Errorf("failed to create kernel repo: %w", err)
	}
	if _, err = repo.CheckoutBranch(URL, branch); err != nil {
		return nil, fmt.Errorf("failed to checkout kernel repo %v/%v: %w", URL, branch, err)
	}
	results, missing, err := repo.GetCommitsByTitles(commits)
	if err != nil {
		return nil, err
	}
	for _, title := range missing {
		jp.Logf(0, "did not find commit %q in kernel repo %v/%v", title, URL, branch)
	}
	return results, nil
}

func (jp *JobProcessor) pollJobs() {
	poll := &dashapi.JobPollReq{
		Managers: make(map[string]dashapi.ManagerJobs),
	}
	for _, mgr := range jp.managers {
		jobs := &mgr.mgrcfg.Jobs
		if jp.jobFilter != nil {
			jobs = jobs.Filter(jp.jobFilter)
		}
		apiJobs := dashapi.ManagerJobs{
			TestPatches: jobs.TestPatches,
			BisectCause: jobs.BisectCause,
			BisectFix:   jobs.BisectFix,
		}
		if apiJobs.Any() {
			poll.Managers[mgr.name] = apiJobs
		}
	}
	if len(poll.Managers) == 0 {
		return
	}
	req, err := jp.dash.JobPoll(poll)
	if err != nil {
		jp.Errorf("failed to poll jobs: %v", err)
		return
	}
	if req.ID == "" {
		return
	}
	var mgr *Manager
	for _, m := range jp.managers {
		if m.name == req.Manager {
			mgr = m
			break
		}
	}
	if mgr == nil {
		jp.Errorf("got job for unknown manager: %v", req.Manager)
		return
	}
	job := &Job{
		req: req,
		mgr: mgr,
	}
	jp.processJob(job)
}

func (jp *JobProcessor) processJob(job *Job) {
	req := job.req
	jp.Logf(0, "starting job %v type %v for manager %v on %v/%v",
		req.ID, req.Type, req.Manager, req.KernelRepo, req.KernelBranch)
	resp := jp.process(job)
	jp.Logf(0, "done job %v: commit %v, crash %q, error: %s",
		resp.ID, resp.Build.KernelCommit, resp.CrashTitle, resp.Error)
	select {
	case <-jp.shutdownPending:
		if len(resp.Error) != 0 {
			// Ctrl+C can kill a child process which will cause an error.
			jp.Logf(0, "ignoring error: shutdown pending")
			return
		}
	default:
	}
	if err := jp.dash.JobDone(resp); err != nil {
		jp.Errorf("failed to mark job as done: %v", err)
		return
	}
}

type Job struct {
	req  *dashapi.JobPollResp
	resp *dashapi.JobDoneReq
	mgr  *Manager
}

func (jp *JobProcessor) process(job *Job) *dashapi.JobDoneReq {
	req, mgr := job.req, job.mgr

	dir := filepath.Join(jp.baseDir, mgr.managercfg.TargetOS)
	mgrcfg := new(mgrconfig.Config)
	*mgrcfg = *mgr.managercfg
	mgrcfg.Workdir = filepath.Join(dir, "workdir")
	mgrcfg.KernelSrc = filepath.Join(dir, "kernel", mgr.mgrcfg.KernelSrcSuffix)
	mgrcfg.Syzkaller = filepath.Join(dir, "gopath", "src", "github.com", "google", "syzkaller")
	os.RemoveAll(mgrcfg.Workdir)
	defer os.RemoveAll(mgrcfg.Workdir)

	resp := &dashapi.JobDoneReq{
		ID: req.ID,
		Build: dashapi.Build{
			Manager:         mgr.name,
			ID:              req.ID,
			OS:              mgr.managercfg.TargetOS,
			Arch:            mgr.managercfg.TargetArch,
			VMArch:          mgr.managercfg.TargetVMArch,
			SyzkallerCommit: req.SyzkallerCommit,
		},
	}
	job.resp = resp
	resp.Build.KernelRepo = req.KernelRepo
	resp.Build.KernelBranch = req.KernelBranch
	resp.Build.KernelConfig = req.KernelConfig
	switch req.Type {
	case dashapi.JobTestPatch:
		resp.Build.KernelCommit = "[unknown]"
		mgrcfg.Name += "-test" + jp.instanceSuffix
	case dashapi.JobBisectCause, dashapi.JobBisectFix:
		resp.Build.KernelCommit = req.KernelCommit
		resp.Build.KernelCommitTitle = req.KernelCommitTitle
		mgrcfg.Name += "-bisect" + jp.instanceSuffix
	default:
		err := fmt.Errorf("bad job type %v", req.Type)
		job.resp.Error = []byte(err.Error())
		jp.Errorf("%s", err)
		return job.resp
	}
	if req.KernelRepo == "" {
		req.KernelRepo = mgr.mgrcfg.Repo
		req.KernelBranch = mgr.mgrcfg.Branch
	}
	required := []struct {
		name string
		ok   bool
	}{
		{"kernel repository", req.KernelRepo != "" || req.Type != dashapi.JobTestPatch},
		{"kernel branch", req.KernelBranch != "" || req.Type != dashapi.JobTestPatch},
		{"kernel config", len(req.KernelConfig) != 0},
		{"syzkaller commit", req.SyzkallerCommit != ""},
		// We either want a normal repro (with options and syz repro text)
		// or it's a boot time bug, in which case both are empty.
		{"reproducer consistency", (len(req.ReproOpts) != 0 && len(req.ReproSyz) != 0) ||
			(len(req.ReproOpts) == 0 && len(req.ReproSyz) == 0)},
	}
	for _, req := range required {
		if !req.ok {
			job.resp.Error = []byte(req.name + " is empty")
			jp.Errorf("%s", job.resp.Error)
			return job.resp
		}
	}
	if typ := mgr.managercfg.Type; !vm.AllowsOvercommit(typ) {
		job.resp.Error = []byte(fmt.Sprintf("testing is not yet supported for %v machine type.", typ))
		jp.Errorf("%s", job.resp.Error)
		return job.resp
	}

	var err error
	switch req.Type {
	case dashapi.JobTestPatch:
		err = jp.testPatch(job, mgrcfg)
	case dashapi.JobBisectCause, dashapi.JobBisectFix:
		err = jp.bisect(job, mgrcfg)
	}
	if err != nil {
		job.resp.Error = []byte(err.Error())
	}
	return job.resp
}

func (jp *JobProcessor) bisect(job *Job, mgrcfg *mgrconfig.Config) error {
	req, resp, mgr := job.req, job.resp, job.mgr

	// Hack: if the manager has only, say, 5 VMs, but bisect wants 10, try to override number of VMs to 10.
	// OverrideVMCount is opportunistic and should do it only if it's safe.
	if err := instance.OverrideVMCount(mgrcfg, bisect.MaxNumTests); err != nil {
		return err
	}

	var baseline []byte
	// Read possible baseline for config minimization.
	if mgr.mgrcfg.KernelBaselineConfig != "" {
		var err error
		baseline, err = os.ReadFile(mgr.mgrcfg.KernelBaselineConfig)
		if err != nil {
			return fmt.Errorf("failed to read baseline config: %w", err)
		}
	}
	err := jp.prepareBisectionRepo(mgrcfg, req)
	if err != nil {
		return err
	}
	trace := new(bytes.Buffer)
	cfg := &bisect.Config{
		Trace: &debugtracer.GenericTracer{
			TraceWriter: io.MultiWriter(trace, log.VerboseWriter(3)),
			OutDir:      osutil.Abs(filepath.Join("jobs", "debug", strings.Replace(req.ID, "|", "_", -1))),
		},
		// Out of 1049 cause bisections that we have now:
		// -  891 finished under  6h (84.9%)
		// -  957 finished under  8h (91.2%)
		// -  980 finished under 10h (93.4%)
		// -  989 finished under 12h (94.3%)
		// - 1011 finished under 18h (96.3%)
		// - 1025 finished under 24h (97.7%)
		// There is also a significant increase in errors/inconclusive bisections after ~8h.
		// Out of 4075 fix bisections:
		// - 4015 finished under  6h (98.5%)
		// - 4020 finished under  8h (98.7%)
		// - 4026 finished under 10h (98.8%)
		// - 4032 finished under 12h (98.9%)
		// Significant increase in errors starts after ~12h.
		// Bisection jobs are now executed in parallel to patch testing, so it doesn't destroy user experience.
		// Let's set the timeout to 12h.
		Timeout:         12 * time.Hour,
		Fix:             req.Type == dashapi.JobBisectFix,
		DefaultCompiler: mgr.mgrcfg.Compiler,
		CompilerType:    mgr.mgrcfg.CompilerType,
		BinDir:          jp.cfg.BisectBinDir,
		Linker:          mgr.mgrcfg.Linker,
		Ccache:          jp.cfg.Ccache,
		Kernel: bisect.KernelConfig{
			Repo:           req.KernelRepo,
			Branch:         req.KernelBranch,
			Commit:         req.KernelCommit,
			CommitTitle:    req.KernelCommitTitle,
			Cmdline:        mgr.mgrcfg.KernelCmdline,
			Sysctl:         mgr.mgrcfg.KernelSysctl,
			Config:         req.KernelConfig,
			BaselineConfig: baseline,
			Userspace:      mgr.mgrcfg.Userspace,
			Backports:      mgr.backportCommits(),
		},
		Syzkaller: bisect.SyzkallerConfig{
			Repo:   jp.cfg.SyzkallerRepo,
			Commit: req.SyzkallerCommit,
		},
		Repro: bisect.ReproConfig{
			Opts: req.ReproOpts,
			Syz:  req.ReproSyz,
			C:    req.ReproC,
		},
		CrossTree:      req.MergeBaseRepo != "",
		Manager:        mgrcfg,
		BuildSemaphore: buildSem,
		TestSemaphore:  testSem,
	}

	res, err := bisect.Run(cfg)
	resp.Log = trace.Bytes()
	if err != nil {
		var infraErr *bisect.InfraError
		if errors.As(err, &infraErr) {
			resp.Flags |= dashapi.BisectResultInfraError
		}
		return err
	}
	for _, com := range res.Commits {
		resp.Commits = append(resp.Commits, dashapi.Commit{
			Hash:       com.Hash,
			Title:      com.Title,
			Author:     com.Author,
			AuthorName: com.AuthorName,
			Recipients: com.Recipients.ToDash(),
			Date:       com.Date,
		})
	}
	if len(res.Commits) == 1 {
		if len(res.Commits[0].Parents) > 1 {
			resp.Flags |= dashapi.BisectResultMerge
		}
		if res.NoopChange {
			resp.Flags |= dashapi.BisectResultNoop
		}
		if res.IsRelease {
			resp.Flags |= dashapi.BisectResultRelease
		}
		const confidenceCutOff = 0.66
		if res.Confidence < confidenceCutOff {
			resp.Flags |= dashapi.BisectResultIgnore
		}
		if jp.ignoreBisectCommit(res.Commits[0]) {
			resp.Flags |= dashapi.BisectResultIgnore
		}
	}
	if res.Report != nil {
		resp.CrashTitle = res.Report.Title
		resp.CrashAltTitles = res.Report.AltTitles
		resp.CrashReport = res.Report.Report
		resp.CrashLog = res.Report.Output
		if len(resp.Commits) != 0 {
			resp.Commits[0].Recipients = append(resp.Commits[0].Recipients, res.Report.Recipients.ToDash()...)
		} else {
			// If there is a report and there is no commit, it means a crash
			// occurred on HEAD(for BisectFix) and oldest tested release(for BisectCause).
			resp.Build.KernelCommit = res.Commit.Hash
			resp.Build.KernelCommitDate = res.Commit.CommitDate
			resp.Build.KernelCommitTitle = res.Commit.Title
		}
	}
	return nil
}

var ignoredCommits = []string{
	// Commit "usb: gadget: add raw-gadget interface" adds a kernel interface for
	// triggering USB bugs, which ends up being the guilty commit during bisection
	// for USB bugs introduced before it.
	"f2c2e717642c66f7fe7e5dd69b2e8ff5849f4d10",
	// Commit "devlink: bump the instance index directly when iterating" has likely
	// fixed some frequent task hung, which skews fix bisection results.
	// TODO: consider backporting it during bisection itself.
	"d772781964415c63759572b917e21c4f7ec08d9f",
}

func (jp *JobProcessor) ignoreBisectCommit(commit *vcs.Commit) bool {
	// First look at the always ignored values.
	for _, hash := range ignoredCommits {
		if commit.Hash == hash {
			return true
		}
	}
	_, ok := jp.cfg.BisectIgnore[commit.Hash]
	return ok
}

func (jp *JobProcessor) testPatch(job *Job, mgrcfg *mgrconfig.Config) error {
	req, resp, mgr := job.req, job.resp, job.mgr
	env, err := instance.NewEnv(mgrcfg, buildSem, testSem)
	if err != nil {
		return err
	}
	jp.Logf(0, "building syzkaller on %v...", req.SyzkallerCommit)
	syzBuildLog, syzBuildErr := env.BuildSyzkaller(jp.cfg.SyzkallerRepo, req.SyzkallerCommit)
	if syzBuildErr != nil {
		return syzBuildErr
	}
	jp.Logf(0, "fetching kernel...")
	repo, err := vcs.NewRepo(mgrcfg.TargetOS, mgrcfg.Type, mgrcfg.KernelSrc)
	if err != nil {
		return fmt.Errorf("failed to create kernel repo: %w", err)
	}
	kernelCommit, err := jp.checkoutJobCommit(job, repo)
	if err != nil {
		return err
	}
	resp.Build.KernelCommit = kernelCommit.Hash
	resp.Build.KernelCommitTitle = kernelCommit.Title
	resp.Build.KernelCommitDate = kernelCommit.CommitDate

	if err := build.Clean(mgrcfg.TargetOS, mgrcfg.TargetVMArch, mgrcfg.Type, mgrcfg.KernelSrc); err != nil {
		return fmt.Errorf("kernel clean failed: %w", err)
	}
	if len(req.Patch) != 0 {
		if err := vcs.Patch(mgrcfg.KernelSrc, req.Patch); err != nil {
			return err
		}
	}

	// Disable CONFIG_DEBUG_INFO_BTF in the config.
	// DEBUG_INFO_BTF requires a very new pahole binary, which we don't have on syzbot instances.
	// Currently we don't enable DEBUG_INFO_BTF, but we have some old bugs with DEBUG_INFO_BTF enabled
	// (at the time requirements for pahole binary were lower, or maybe the config silently disabled itself).
	// Testing of patches for these bugs fail now because of the config, so we disable it as a work-around.
	// Ideally we have a new pahole and then we can remove this hack. That's issue #2096.
	// pkg/vcs/linux.go also disables it for the bisection process.
	req.KernelConfig = bytes.Replace(req.KernelConfig,
		[]byte("CONFIG_DEBUG_INFO_BTF=y"),
		[]byte("# CONFIG_DEBUG_INFO_BTF is not set"), -1)

	log.Logf(0, "job: building kernel...")
	kernelConfig, details, err := env.BuildKernel(&instance.BuildKernelConfig{
		CompilerBin:  mgr.mgrcfg.Compiler,
		LinkerBin:    mgr.mgrcfg.Linker,
		CcacheBin:    mgr.mgrcfg.Ccache,
		UserspaceDir: mgr.mgrcfg.Userspace,
		CmdlineFile:  mgr.mgrcfg.KernelCmdline,
		SysctlFile:   mgr.mgrcfg.KernelSysctl,
		KernelConfig: req.KernelConfig,
	})
	resp.Build.CompilerID = details.CompilerID
	if err != nil {
		return err
	}
	if kernelConfig != "" {
		resp.Build.KernelConfig, err = os.ReadFile(kernelConfig)
		if err != nil {
			return fmt.Errorf("failed to read config file: %w", err)
		}
	}
	jp.Logf(0, "job: testing...")
	results, err := env.Test(3, req.ReproSyz, req.ReproOpts, req.ReproC)
	if err != nil {
		return fmt.Errorf("%w\n\nsyzkaller build log:\n%s", err, syzBuildLog)
	}
	ret, err := aggregateTestResults(results)
	if err != nil {
		return fmt.Errorf("%w\n\nsyzkaller build log:\n%s", err, syzBuildLog)
	}
	rep := ret.report
	if rep != nil {
		resp.CrashTitle = rep.Title
		resp.CrashAltTitles = rep.AltTitles
		resp.CrashReport = rep.Report
	}
	resp.CrashLog = ret.rawOutput
	return nil
}

func (jp *JobProcessor) prepareBisectionRepo(mgrcfg *mgrconfig.Config, req *dashapi.JobPollResp) error {
	if req.MergeBaseRepo == "" {
		// No need to.
		return nil
	}
	repo, err := vcs.NewRepo(mgrcfg.TargetOS, mgrcfg.Type, mgrcfg.KernelSrc)
	if err != nil {
		return fmt.Errorf("failed to create kernel repo: %w", err)
	}
	_, err = checkoutKernelOrCommit(repo, req.MergeBaseRepo, req.MergeBaseBranch)
	if err != nil {
		return fmt.Errorf("failed to checkout the merge base repo %v on %v: %w",
			req.MergeBaseRepo, req.MergeBaseBranch, err)
	}
	return nil
}

func (jp *JobProcessor) checkoutJobCommit(job *Job, repo vcs.Repo) (*vcs.Commit, error) {
	req, resp := job.req, job.resp
	var kernelCommit *vcs.Commit
	if req.MergeBaseRepo != "" {
		jp.Logf(1, "checking out the base kernel...")
		firstCommit, err := checkoutKernelOrCommit(repo, req.KernelRepo, req.KernelBranch)
		if err != nil {
			return nil, fmt.Errorf("failed to checkout first kernel repo %v on %v: %w",
				req.KernelRepo, req.KernelBranch, err)
		}
		secondCommit, err := checkoutKernelOrCommit(repo, req.MergeBaseRepo, req.MergeBaseBranch)
		if err != nil {
			return nil, fmt.Errorf("failed to checkout second kernel repo %v on %v: %w",
				req.MergeBaseRepo, req.MergeBaseBranch, err)
		}
		bases, err := repo.MergeBases(firstCommit.Hash, secondCommit.Hash)
		if err != nil {
			return nil, fmt.Errorf("failed to calculate merge bases between %v and %v: %w",
				firstCommit.Hash, secondCommit.Hash, err)
		}
		if len(bases) != 1 {
			return nil, fmt.Errorf("expected one merge base between %v and %v, got %d",
				firstCommit.Hash, secondCommit.Hash, len(bases))
		}
		kernelCommit, err = repo.CheckoutCommit(req.KernelRepo, bases[0].Hash)
		if err != nil {
			return nil, fmt.Errorf("failed to checkout kernel repo %v on merge base %v: %w",
				req.KernelRepo, bases[0].Hash, err)
		}
		resp.Build.KernelBranch = ""
	} else if vcs.CheckCommitHash(req.KernelBranch) {
		var err error
		kernelCommit, err = repo.CheckoutCommit(req.KernelRepo, req.KernelBranch)
		if err != nil {
			return nil, fmt.Errorf("failed to checkout kernel repo %v on commit %v: %w",
				req.KernelRepo, req.KernelBranch, err)
		}
		resp.Build.KernelBranch = ""
	} else {
		var err error
		kernelCommit, err = repo.CheckoutBranch(req.KernelRepo, req.KernelBranch)
		if err != nil {
			return nil, fmt.Errorf("failed to checkout kernel repo %v/%v: %w",
				req.KernelRepo, req.KernelBranch, err)
		}
	}
	return kernelCommit, nil
}

func checkoutKernelOrCommit(repo vcs.Repo, url, branch string) (*vcs.Commit, error) {
	if vcs.CheckCommitHash(branch) {
		return repo.CheckoutCommit(url, branch)
	}
	return repo.CheckoutBranch(url, branch)
}

type patchTestResult struct {
	report    *report.Report
	rawOutput []byte
}

func aggregateTestResults(results []instance.EnvTestResult) (*patchTestResult, error) {
	// We can have transient errors and other errors of different types.
	// We need to avoid reporting transient "failed to boot" or "failed to copy binary" errors.
	// If any of the instances crash during testing, we report this with the highest priority.
	// Then if any of the runs succeed, we report that (to avoid transient errors).
	// If all instances failed to boot, then we report one of these errors.
	var anyErr, testErr error
	var resReport, resSuccess *patchTestResult
	anyErr = fmt.Errorf("no env test runs")
	for _, res := range results {
		if res.Error == nil {
			resSuccess = &patchTestResult{rawOutput: res.RawOutput}
			continue
		}
		anyErr = res.Error
		var testError *instance.TestError
		var crashError *instance.CrashError
		switch {
		case errors.As(res.Error, &testError):
			// We should not put rep into resp.CrashTitle/CrashReport,
			// because that will be treated as patch not fixing the bug.
			if rep := testError.Report; rep != nil {
				testErr = fmt.Errorf("%v\n\n%s\n\n%s", rep.Title, rep.Report, rep.Output)
			} else {
				testErr = fmt.Errorf("%v\n\n%s", testError.Title, testError.Output)
			}
		case errors.As(res.Error, &crashError):
			if resReport == nil || (len(resReport.report.Report) == 0 && len(crashError.Report.Report) != 0) {
				resReport = &patchTestResult{report: crashError.Report, rawOutput: res.RawOutput}
			}
		}
	}
	if resReport != nil {
		return resReport, nil
	}
	if resSuccess != nil {
		return resSuccess, nil
	}
	if testErr != nil {
		return nil, testErr
	}
	return nil, anyErr
}

func (jp *JobProcessor) Logf(level int, msg string, args ...interface{}) {
	log.Logf(level, "%s: "+msg, append([]interface{}{jp.name}, args...)...)
}

// Errorf logs non-fatal error and sends it to dashboard.
func (jp *JobProcessor) Errorf(msg string, args ...interface{}) {
	log.Errorf("job: "+msg, args...)
	if jp.dash != nil {
		jp.dash.LogError(jp.name, msg, args...)
	}
}
