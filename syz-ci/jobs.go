// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
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
		// The parallel job processor only handles patch testing requests.
		parallelJobFilter: &ManagerJobs{TestPatches: true},
	}, nil
}

// startLoop starts a job loop in parallel.
func (jm *JobManager) startLoop(ctx context.Context, wg *sync.WaitGroup) {
	wg.Go(func() {
		jm.loop(ctx)
	})
}

func (jm *JobManager) loop(ctx context.Context) {
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
		wg.Go(func() {
			jp.loop(ctx)
		})
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

func (jp *JobProcessor) loop(ctx context.Context) {
	jp.Logf(0, "job loop started")
loop:
	for {
		// Check jp.stop separately first, otherwise if stop signal arrives during a job execution,
		// we can still grab the next job with 50% probability.
		select {
		case <-ctx.Done():
			break loop
		default:
		}
		// Similar for commit polling: if we grab several jobs in a row,
		// it can delay commit polling for hours.
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
		case <-ctx.Done():
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
			Hash:       com.Hash,
			Title:      com.Title,
			Author:     com.Author,
			AuthorName: com.AuthorName,
			BugIDs:     com.Tags,
			Date:       com.Date,
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
	results, missing, err := repo.GetCommitsByTitles(commits, time.Time{})
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
	mgrcfg := mgr.jobConfig()
	mgrcfg.Workdir = filepath.Join(dir, "workdir")
	repoDir := filepath.Join(dir, "kernel")
	mgrcfg.KernelSrc = filepath.Join(repoDir, mgr.mgrcfg.KernelSrcSuffix)
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
			BuildEnv:        extractBuildEnv(mgr.managercfg),
		},
	}
	job.resp = resp
	if err := jp.initJobRepo(mgr, repoDir); err != nil {
		jp.Errorf("failed to init job repo: %v", osutil.VerboseMessage(err))
		job.resp.Error = []byte(err.Error())
		return job.resp
	}
	resp.Build.KernelRepo = req.KernelRepo
	resp.Build.KernelBranch = req.KernelBranch
	resp.Build.KernelConfig = req.KernelConfig
	switch req.Type {
	case dashapi.JobTestPatch:
		resp.Build.KernelCommit = "[unknown]"
		mgrcfg.Name += "-test" + jp.instanceSuffix
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
		{"kernel repository", req.KernelRepo != ""},
		{"kernel branch", req.KernelBranch != ""},
		{"kernel config", len(req.KernelConfig) != 0},
		{"syzkaller commit", req.SyzkallerCommit != ""},
		// We either want a normal repro (with options and syz repro text)
		// or it's a boot time bug, in which case both are empty.
		{
			name: "reproducer consistency",
			ok: (len(req.ReproOpts) != 0 && len(req.ReproSyz) != 0) ||
				(len(req.ReproOpts) == 0 && len(req.ReproSyz) == 0),
		},
	}
	for _, req := range required {
		if !req.ok {
			job.resp.Error = []byte(req.name + " is invalid")
			jp.Errorf("%s (job id=%q, type=%v)", job.resp.Error, job.req.ID, job.req.Type)
			return job.resp
		}
	}
	if typ := mgr.managercfg.Type; !vm.AllowsOvercommit(typ) {
		job.resp.Error = []byte(fmt.Sprintf("testing is not yet supported for %v machine type.", typ))
		jp.Errorf("%s", job.resp.Error)
		return job.resp
	}

	if err := jp.testPatch(job, mgrcfg); err != nil {
		job.resp.Error = []byte(err.Error())
	}
	return job.resp
}

func (jp *JobProcessor) testPatch(job *Job, mgrcfg *mgrconfig.Config) error {
	req, resp, mgr := job.req, job.resp, job.mgr
	trace := new(bytes.Buffer)
	dt := &debugtracer.GenericTracer{
		TraceWriter: io.MultiWriter(trace, log.VerboseWriter(1)),
		WithTime:    true,
	}
	defer func() {
		resp.Log = trace.Bytes()
	}()

	env, err := instance.NewEnv(mgrcfg, buildSem, testSem)
	if err != nil {
		dt.Logf("failed to create environment: %v", osutil.VerboseMessage(err))
		return err
	}
	dt.Logf("building syzkaller on %v...", req.SyzkallerCommit)
	syzBuildLog, syzBuildErr := env.BuildSyzkaller(jp.cfg.SyzkallerRepo, req.SyzkallerCommit)
	if syzBuildErr != nil {
		dt.Logf("building syzkaller failed: %v", osutil.VerboseMessage(syzBuildErr))
		if syzBuildLog != "" {
			dt.Logf("syzkaller build log:\n%s", syzBuildLog)
		}
		return syzBuildErr
	}
	dt.Logf("fetching kernel...")
	repo, err := vcs.NewRepo(mgrcfg.TargetOS, mgrcfg.Type, mgrcfg.KernelSrc)
	if err != nil {
		dt.Logf("failed to create kernel repo: %v", osutil.VerboseMessage(err))
		return fmt.Errorf("failed to create kernel repo: %w", err)
	}
	kernelCommit, err := jp.checkoutJobCommit(job, repo)
	if err != nil {
		dt.Logf("failed to checkout kernel: %v", osutil.VerboseMessage(err))
		return err
	}
	dt.Logf("checked out kernel commit %v (%q, %v)", kernelCommit.Hash, kernelCommit.Title, kernelCommit.CommitDate)
	resp.Build.KernelCommit = kernelCommit.Hash
	resp.Build.KernelCommitTitle = kernelCommit.Title
	resp.Build.KernelCommitDate = kernelCommit.CommitDate

	buildCfg := &instance.BuildKernelConfig{
		CompilerBin:  mgr.mgrcfg.Compiler,
		MakeBin:      mgr.mgrcfg.Make,
		LinkerBin:    mgr.mgrcfg.Linker,
		CcacheBin:    mgr.mgrcfg.Ccache,
		UserspaceDir: mgr.mgrcfg.Userspace,
		BuilderImage: mgr.mgrcfg.KernelBuilderImage,
		CmdlineFile:  mgr.mgrcfg.KernelCmdline,
		SysctlFile:   mgr.mgrcfg.KernelSysctl,
		KernelConfig: req.KernelConfig,
		BuildCPUs:    jp.cfg.BuildCPUs,
	}
	dt.Logf("cleaning kernel...")
	if err := env.CleanKernel(buildCfg); err != nil {
		dt.Logf("kernel clean failed: %v", osutil.VerboseMessage(err))
		return fmt.Errorf("kernel clean failed: %w", err)
	}
	if len(req.Patch) != 0 {
		dt.Logf("applying patch (%d bytes)...", len(req.Patch))
		if err := vcs.Patch(mgrcfg.KernelSrc, req.Patch); err != nil {
			dt.Logf("failed to apply patch: %v", osutil.VerboseMessage(err))
			return err
		}
	}

	dt.Logf("building kernel...")
	kernelConfig, details, err := env.BuildKernel(buildCfg)
	resp.Build.CompilerID = details.CompilerID
	if err != nil {
		dt.Logf("kernel build failed: %v", osutil.VerboseMessage(err))
		return err
	}
	dt.Logf("kernel built successfully with compiler %v", details.CompilerID)
	if kernelConfig != "" {
		resp.Build.KernelConfig, err = os.ReadFile(kernelConfig)
		if err != nil {
			dt.Logf("failed to read config file: %v", osutil.VerboseMessage(err))
			return fmt.Errorf("failed to read config file: %w", err)
		}
	}
	dt.Logf("testing patch...")
	results, err := env.Test(3, req.ReproSyz, req.ReproOpts, req.ReproC, false)
	if err != nil {
		dt.Logf("testing failed: %v", osutil.VerboseMessage(err))
		return fmt.Errorf("%w\n\nsyzkaller build log:\n%s", err, syzBuildLog)
	}
	ret, err := aggregateTestResults(results)
	if err != nil {
		dt.Logf("aggregating test results failed: %v", osutil.VerboseMessage(err))
		return fmt.Errorf("%w\n\nsyzkaller build log:\n%s", err, syzBuildLog)
	}
	rep := ret.report
	if rep != nil {
		dt.Logf("reproduced crash: %v", rep.Title)
		resp.CrashTitle = rep.Title
		resp.CrashAltTitles = rep.AltTitles
		resp.CrashReport = rep.Report
	} else {
		dt.Logf("testing succeeded, no crash reproduced")
	}
	resp.CrashLog = ret.rawOutput
	return nil
}

func (jp *JobProcessor) initJobRepo(mgr *Manager, repoDir string) error {
	if err := os.RemoveAll(repoDir); err != nil {
		return fmt.Errorf("failed to remove job repo dir: %w", err)
	}
	if osutil.IsExist(mgr.kernelBuildDir) {
		if err := osutil.MkdirAll(repoDir); err != nil {
			return fmt.Errorf("failed to create job repo dir: %w", err)
		}
		if err := osutil.SandboxChown(repoDir); err != nil {
			return fmt.Errorf("failed to chown job repo dir: %w", err)
		}
		jp.Logf(0, "cloning job repo from %v using reference", mgr.kernelBuildDir)
		_, err := vcs.SandboxedGit(repoDir).RunTimeout(time.Hour,
			"clone", "--reference", mgr.kernelBuildDir, mgr.kernelBuildDir, ".")
		if err == nil {
			return nil
		}
		jp.Logf(0, "failed to clone with reference from %v: %v", mgr.kernelBuildDir, osutil.VerboseMessage(err))
		os.RemoveAll(repoDir)
	}
	jp.Logf(0, "job repo will be fetched from scratch")
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
	// We report crashes with the highest priority.
	res, err := instance.AggregateTestResults(results)
	if err != nil {
		return nil, err
	} else if res.Error == nil {
		return &patchTestResult{rawOutput: res.RawOutput}, nil
	}

	var testError *instance.TestError
	var crashError *instance.CrashError

	switch {
	case errors.As(res.Error, &testError):
		// We should not put rep into resp.CrashTitle/CrashReport,
		// because that will be treated as patch not fixing the bug.
		if rep := testError.Report; rep != nil {
			return nil, fmt.Errorf("%v\n\n%s\n\n%s", rep.Title, rep.Report, rep.Output)
		}
		return nil, fmt.Errorf("%v\n\n%s", testError.Title, testError.Output)
	case errors.As(res.Error, &crashError):
		return &patchTestResult{report: crashError.Report, rawOutput: res.RawOutput}, nil
	default:
		return nil, res.Error
	}
}

func (jp *JobProcessor) Logf(level int, msg string, args ...any) {
	log.Logf(level, "%s: "+msg, append([]any{jp.name}, args...)...)
}

// Errorf logs non-fatal error and sends it to dashboard.
func (jp *JobProcessor) Errorf(msg string, args ...any) {
	log.Errorf("job: "+msg, args...)
	if jp.dash != nil {
		jp.dash.LogError(jp.name, msg, args...)
	}
}
