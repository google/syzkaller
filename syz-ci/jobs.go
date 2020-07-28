// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/bisect"
	"github.com/google/syzkaller/pkg/build"
	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/vm"
)

const (
	commitPollPeriod = time.Hour
)

type JobProcessor struct {
	cfg             *Config
	name            string
	managers        []*Manager
	knownCommits    map[string]bool
	stop            chan struct{}
	shutdownPending chan struct{}
	dash            *dashapi.Dashboard
	syzkallerRepo   string
	syzkallerBranch string
}

func newJobProcessor(cfg *Config, managers []*Manager, stop, shutdownPending chan struct{}) *JobProcessor {
	return &JobProcessor{
		cfg:             cfg,
		name:            fmt.Sprintf("%v-job", cfg.Name),
		managers:        managers,
		knownCommits:    make(map[string]bool),
		stop:            stop,
		shutdownPending: shutdownPending,
		dash:            dashapi.New(cfg.DashboardClient, cfg.DashboardAddr, cfg.DashboardKey),
		syzkallerRepo:   cfg.SyzkallerRepo,
		syzkallerBranch: cfg.SyzkallerBranch,
	}
}

func (jp *JobProcessor) loop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	var lastCommitPoll time.Time
loop:
	for {
		// Check jp.stop separately first, otherwise if stop signal arrives during a job execution,
		// we can grab the next one with 50% probability.
		select {
		case <-jp.stop:
			break loop
		default:
		}
		select {
		case <-ticker.C:
			if len(kernelBuildSem) != 0 {
				// If normal kernel build is in progress (usually on start), don't query jobs.
				// Otherwise we claim a job, but can't start it for a while.
				continue loop
			}
			jp.pollJobs()
			if time.Since(lastCommitPoll) > commitPollPeriod {
				jp.pollCommits()
				lastCommitPoll = time.Now()
			}
		case <-jp.stop:
			break loop
		}
	}
	log.Logf(0, "job loop stopped")
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
	log.Logf(0, "polling commits for %v: repos %v, commits %v", mgr.name, len(resp.Repos), len(resp.Commits))
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
			log.Logf(1, "got %v commits from %v/%v repo", len(commits1), repo.URL, repo.Branch)
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
			log.Logf(1, "got %v commit infos from %v/%v repo", len(commits1), repo.URL, repo.Branch)
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
	dir := osutil.Abs(filepath.Join("jobs", mgr.managercfg.TargetOS, "kernel"))
	repo, err := vcs.NewRepo(mgr.managercfg.TargetOS, mgr.managercfg.Type, dir)
	if err != nil {
		return nil, fmt.Errorf("failed to create kernel repo: %v", err)
	}
	if _, err = repo.CheckoutBranch(URL, branch); err != nil {
		return nil, fmt.Errorf("failed to checkout kernel repo %v/%v: %v", URL, branch, err)
	}
	return repo.ExtractFixTagsFromCommits("HEAD", reportEmail)
}

func (jp *JobProcessor) getCommitInfo(mgr *Manager, URL, branch string, commits []string) ([]*vcs.Commit, error) {
	dir := osutil.Abs(filepath.Join("jobs", mgr.managercfg.TargetOS, "kernel"))
	repo, err := vcs.NewRepo(mgr.managercfg.TargetOS, mgr.managercfg.Type, dir)
	if err != nil {
		return nil, fmt.Errorf("failed to create kernel repo: %v", err)
	}
	if _, err = repo.CheckoutBranch(URL, branch); err != nil {
		return nil, fmt.Errorf("failed to checkout kernel repo %v/%v: %v", URL, branch, err)
	}
	results, missing, err := repo.GetCommitsByTitles(commits)
	if err != nil {
		return nil, err
	}
	for _, title := range missing {
		log.Logf(0, "did not find commit %q", title)
	}
	return results, nil
}

func (jp *JobProcessor) pollJobs() {
	poll := &dashapi.JobPollReq{
		Managers: make(map[string]dashapi.ManagerJobs),
	}
	for _, mgr := range jp.managers {
		if !mgr.mgrcfg.Jobs.TestPatches &&
			!mgr.mgrcfg.Jobs.BisectCause &&
			!mgr.mgrcfg.Jobs.BisectFix {
			continue
		}
		poll.Managers[mgr.name] = dashapi.ManagerJobs{
			TestPatches: mgr.mgrcfg.Jobs.TestPatches,
			BisectCause: mgr.mgrcfg.Jobs.BisectCause,
			BisectFix:   mgr.mgrcfg.Jobs.BisectFix,
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
	select {
	case kernelBuildSem <- struct{}{}:
	case <-jp.stop:
		return
	}
	defer func() { <-kernelBuildSem }()

	req := job.req
	log.Logf(0, "starting job %v type %v for manager %v on %v/%v",
		req.ID, req.Type, req.Manager, req.KernelRepo, req.KernelBranch)
	resp := jp.process(job)
	log.Logf(0, "done job %v: commit %v, crash %q, error: %s",
		resp.ID, resp.Build.KernelCommit, resp.CrashTitle, resp.Error)
	select {
	case <-jp.shutdownPending:
		if len(resp.Error) != 0 {
			// Ctrl+C can kill a child process which will cause an error.
			log.Logf(0, "ignoring error: shutdown pending")
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

	dir := osutil.Abs(filepath.Join("jobs", mgr.managercfg.TargetOS))
	mgrcfg := new(mgrconfig.Config)
	*mgrcfg = *mgr.managercfg
	mgrcfg.Workdir = filepath.Join(dir, "workdir")
	mgrcfg.KernelSrc = filepath.Join(dir, "kernel")
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
	switch req.Type {
	case dashapi.JobTestPatch:
		mgrcfg.Name += "-test-job"
		resp.Build.CompilerID = mgr.compilerID
		resp.Build.KernelRepo = req.KernelRepo
		resp.Build.KernelBranch = req.KernelBranch
		resp.Build.KernelCommit = "[unknown]"
	case dashapi.JobBisectCause, dashapi.JobBisectFix:
		mgrcfg.Name += "-bisect-job"
		resp.Build.KernelRepo = mgr.mgrcfg.Repo
		resp.Build.KernelBranch = mgr.mgrcfg.Branch
		resp.Build.KernelCommit = req.KernelCommit
		resp.Build.KernelCommitTitle = req.KernelCommitTitle
		resp.Build.KernelCommitDate = req.KernelCommitDate
		resp.Build.KernelConfig = req.KernelConfig
	default:
		err := fmt.Errorf("bad job type %v", req.Type)
		job.resp.Error = []byte(err.Error())
		jp.Errorf("%s", err)
		return job.resp
	}

	required := []struct {
		name string
		ok   bool
	}{
		{"kernel repository", req.KernelRepo != "" || req.Type != dashapi.JobTestPatch},
		{"kernel branch", req.KernelBranch != "" || req.Type != dashapi.JobTestPatch},
		{"kernel config", len(req.KernelConfig) != 0},
		{"syzkaller commit", req.SyzkallerCommit != ""},
		{"reproducer options", len(req.ReproOpts) != 0},
		{"reproducer program", len(req.ReproSyz) != 0},
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
		mgrcfg.Name += "-test-job"
		err = jp.testPatch(job, mgrcfg)
	case dashapi.JobBisectCause, dashapi.JobBisectFix:
		mgrcfg.Name += "-bisect-job"
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
	if err := instance.OverrideVMCount(mgrcfg, bisect.NumTests); err != nil {
		return err
	}

	var baseline []byte
	// Read possible baseline for config minimization.
	if mgr.mgrcfg.KernelBaselineConfig != "" {
		var err error
		baseline, err = ioutil.ReadFile(mgr.mgrcfg.KernelBaselineConfig)
		if err != nil {
			return fmt.Errorf("failed to read baseline config: %v", err)
		}
	}
	trace := new(bytes.Buffer)
	cfg := &bisect.Config{
		Trace:    io.MultiWriter(trace, log.VerboseWriter(3)),
		DebugDir: osutil.Abs(filepath.Join("jobs", "debug", strings.Replace(req.ID, "|", "_", -1))),
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
		// The current timeout also take into account that bisection jobs
		// compete with patch testing jobs (it's bad delaying patch testing).
		// When/if bisection jobs don't compete with patch testing,
		// it makes sense to increase this to 12-24h.
		Timeout: 8 * time.Hour,
		Fix:     req.Type == dashapi.JobBisectFix,
		BinDir:  jp.cfg.BisectBinDir,
		Kernel: bisect.KernelConfig{
			Repo:           mgr.mgrcfg.Repo,
			Branch:         mgr.mgrcfg.Branch,
			Commit:         req.KernelCommit,
			Cmdline:        mgr.mgrcfg.KernelCmdline,
			Sysctl:         mgr.mgrcfg.KernelSysctl,
			Config:         req.KernelConfig,
			BaselineConfig: baseline,
			Userspace:      mgr.mgrcfg.Userspace,
		},
		Syzkaller: bisect.SyzkallerConfig{
			Repo:   jp.syzkallerRepo,
			Commit: req.SyzkallerCommit,
		},
		Repro: bisect.ReproConfig{
			Opts: req.ReproOpts,
			Syz:  req.ReproSyz,
			C:    req.ReproC,
		},
		Manager: *mgrcfg,
	}

	res, err := bisect.Run(cfg)
	resp.Log = trace.Bytes()
	if err != nil {
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
		ignoredCommits := []string{
			// Commit "usb: gadget: add raw-gadget interface" adds a kernel interface for
			// triggering USB bugs, which ends up being the guilty commit during bisection
			// for USB bugs introduced before it.
			"f2c2e717642c66f7fe7e5dd69b2e8ff5849f4d10",
		}
		for _, commit := range ignoredCommits {
			if res.Commits[0].Hash == commit {
				resp.Flags |= dashapi.BisectResultIgnore
			}
		}
	}
	if res.Report != nil {
		resp.CrashTitle = res.Report.Title
		resp.CrashReport = res.Report.Report
		resp.CrashLog = res.Report.Output
		if len(resp.Commits) != 0 {
			resp.Commits[0].Recipients = append(resp.Commits[0].Recipients, res.Report.Recipients.ToDash()...)
		} else {
			// If there is a report and there is no commit, it means a crash
			// occurred on HEAD(for BisectFix) and oldest tested release(for BisectCause).
			resp.Build.KernelCommit = res.Commit.Hash
			resp.Build.KernelCommitDate = res.Commit.Date
			resp.Build.KernelCommitTitle = res.Commit.Title
		}
	}
	return nil
}

func (jp *JobProcessor) testPatch(job *Job, mgrcfg *mgrconfig.Config) error {
	req, resp, mgr := job.req, job.resp, job.mgr

	env, err := instance.NewEnv(mgrcfg)
	if err != nil {
		return err
	}
	log.Logf(0, "job: building syzkaller on %v...", req.SyzkallerCommit)
	if err := env.BuildSyzkaller(jp.syzkallerRepo, req.SyzkallerCommit); err != nil {
		return err
	}

	log.Logf(0, "job: fetching kernel...")
	repo, err := vcs.NewRepo(mgrcfg.TargetOS, mgrcfg.Type, mgrcfg.KernelSrc)
	if err != nil {
		return fmt.Errorf("failed to create kernel repo: %v", err)
	}
	var kernelCommit *vcs.Commit
	if vcs.CheckCommitHash(req.KernelBranch) {
		kernelCommit, err = repo.CheckoutCommit(req.KernelRepo, req.KernelBranch)
		if err != nil {
			return fmt.Errorf("failed to checkout kernel repo %v on commit %v: %v",
				req.KernelRepo, req.KernelBranch, err)
		}
		resp.Build.KernelBranch = ""
	} else {
		kernelCommit, err = repo.CheckoutBranch(req.KernelRepo, req.KernelBranch)
		if err != nil {
			return fmt.Errorf("failed to checkout kernel repo %v/%v: %v",
				req.KernelRepo, req.KernelBranch, err)
		}
	}
	resp.Build.KernelCommit = kernelCommit.Hash
	resp.Build.KernelCommitTitle = kernelCommit.Title
	resp.Build.KernelCommitDate = kernelCommit.Date

	if err := build.Clean(mgrcfg.TargetOS, mgrcfg.TargetVMArch, mgrcfg.Type, mgrcfg.KernelSrc); err != nil {
		return fmt.Errorf("kernel clean failed: %v", err)
	}
	if len(req.Patch) != 0 {
		if err := vcs.Patch(mgrcfg.KernelSrc, req.Patch); err != nil {
			return err
		}
	}

	log.Logf(0, "job: building kernel...")
	kernelConfig, _, err := env.BuildKernel(mgr.mgrcfg.Compiler, mgr.mgrcfg.Userspace, mgr.mgrcfg.KernelCmdline,
		mgr.mgrcfg.KernelSysctl, req.KernelConfig)
	if err != nil {
		return err
	}
	if kernelConfig != "" {
		resp.Build.KernelConfig, err = ioutil.ReadFile(kernelConfig)
		if err != nil {
			return fmt.Errorf("failed to read config file: %v", err)
		}
	}
	log.Logf(0, "job: testing...")
	results, err := env.Test(3, req.ReproSyz, req.ReproOpts, req.ReproC)
	if err != nil {
		return err
	}
	rep, err := aggregateTestResults(results)
	if err != nil {
		return err
	}
	if rep != nil {
		resp.CrashTitle = rep.Title
		resp.CrashReport = rep.Report
		resp.CrashLog = rep.Output
	}
	return nil
}

func aggregateTestResults(results []error) (*report.Report, error) {
	// We can have transient errors and other errors of different types.
	// We need to avoid reporting transient "failed to boot" or "failed to copy binary" errors.
	// If any of the instances crash during testing, we report this with the highest priority.
	// Then if any of the runs succeed, we report that (to avoid transient errors).
	// If all instances failed to boot, then we report one of these errors.
	anySuccess := false
	var anyErr, testErr error
	var resReport *report.Report
	for _, res := range results {
		if res == nil {
			anySuccess = true
			continue
		}
		anyErr = res
		switch err := res.(type) {
		case *instance.TestError:
			// We should not put rep into resp.CrashTitle/CrashReport,
			// because that will be treated as patch not fixing the bug.
			if rep := err.Report; rep != nil {
				testErr = fmt.Errorf("%v\n\n%s\n\n%s", rep.Title, rep.Report, rep.Output)
			} else {
				testErr = fmt.Errorf("%v\n\n%s", err.Title, err.Output)
			}
		case *instance.CrashError:
			if resReport == nil || (len(resReport.Report) == 0 && len(err.Report.Report) != 0) {
				resReport = err.Report
			}
		}
	}
	if resReport != nil {
		return resReport, nil
	}
	if anySuccess {
		return nil, nil
	}
	if testErr != nil {
		return nil, testErr
	}
	return nil, anyErr
}

// Errorf logs non-fatal error and sends it to dashboard.
func (jp *JobProcessor) Errorf(msg string, args ...interface{}) {
	log.Logf(0, "job: "+msg, args...)
	if jp.dash != nil {
		jp.dash.LogError(jp.name, msg, args...)
	}
}
