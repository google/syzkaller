// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package bisect

import (
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/google/syzkaller/pkg/build"
	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/vcs"
)

type Config struct {
	Trace     io.Writer
	Fix       bool
	BinDir    string
	DebugDir  string
	Kernel    KernelConfig
	Syzkaller SyzkallerConfig
	Repro     ReproConfig
	Manager   mgrconfig.Config
}

type KernelConfig struct {
	Repo      string
	Branch    string
	Commit    string
	Cmdline   string
	Sysctl    string
	Config    []byte
	Userspace string
}

type SyzkallerConfig struct {
	Repo         string
	Commit       string
	Descriptions string
}

type ReproConfig struct {
	Opts []byte
	Syz  []byte
	C    []byte
}

type env struct {
	cfg       *Config
	repo      vcs.Repo
	bisecter  vcs.Bisecter
	commit    *vcs.Commit
	head      *vcs.Commit
	inst      instance.Env
	numTests  int
	buildTime time.Duration
	testTime  time.Duration
}

const NumTests = 10 // number of tests we do per commit

// Result describes bisection result:
//  - if bisection is conclusive, the single cause/fix commit in Commits
//    - for cause bisection report is the crash on the cause commit
//    - for fix bisection report is nil
//    - Commit is nil
//    - NoopChange is set if the commit did not cause any change in the kernel binary
//      (bisection result it most likely wrong)
//    - Bisected to a release commit
//  - if bisection is inconclusive, range of potential cause/fix commits in Commits
//    - report is nil in such case
//    - Commit is nil
//  - if the crash still happens on the oldest release/HEAD (for cause/fix bisection correspondingly)
//    - no commits in Commits
//    - the crash report on the oldest release/HEAD;
//    - Commit points to the oldest/latest commit where crash happens.
type Result struct {
	Commits    []*vcs.Commit
	Report     *report.Report
	Commit     *vcs.Commit
	NoopChange bool
	IsRelease  bool
}

// Run does the bisection and returns either the Result,
// or, if the crash is not reproduced on the start commit, an error.
func Run(cfg *Config) (*Result, error) {
	if err := checkConfig(cfg); err != nil {
		return nil, err
	}
	cfg.Manager.Cover = false // it's not supported somewhere back in time
	repo, err := vcs.NewRepo(cfg.Manager.TargetOS, cfg.Manager.Type, cfg.Manager.KernelSrc)
	if err != nil {
		return nil, err
	}
	bisecter, ok := repo.(vcs.Bisecter)
	if !ok {
		return nil, fmt.Errorf("bisection is not implemented for %v", cfg.Manager.TargetOS)
	}
	inst, err := instance.NewEnv(&cfg.Manager)
	if err != nil {
		return nil, err
	}
	if _, err = repo.CheckoutBranch(cfg.Kernel.Repo, cfg.Kernel.Branch); err != nil {
		return nil, err
	}
	return runImpl(cfg, repo, bisecter, inst)
}

func runImpl(cfg *Config, repo vcs.Repo, bisecter vcs.Bisecter, inst instance.Env) (*Result, error) {
	env := &env{
		cfg:      cfg,
		repo:     repo,
		bisecter: bisecter,
		inst:     inst,
	}
	head, err := repo.HeadCommit()
	if err != nil {
		return nil, err
	}
	env.head = head
	if cfg.Fix {
		env.log("bisecting fixing commit since %v", cfg.Kernel.Commit)
	} else {
		env.log("bisecting cause commit starting from %v", cfg.Kernel.Commit)
	}
	start := time.Now()
	res, err := env.bisect()
	env.log("revisions tested: %v, total time: %v (build: %v, test: %v)",
		env.numTests, time.Since(start), env.buildTime, env.testTime)
	if err != nil {
		env.log("error: %v", err)
		return nil, err
	}
	if len(res.Commits) == 0 {
		if cfg.Fix {
			env.log("the crash still happens on HEAD")
		} else {
			env.log("the crash already happened on the oldest tested release")
		}
		env.log("commit msg: %v", res.Commit.Title)
		env.log("crash: %v\n%s", res.Report.Title, res.Report.Report)
		return res, nil
	}
	what := "bad"
	if cfg.Fix {
		what = "good"
	}
	if len(res.Commits) > 1 {
		env.log("bisection is inconclusive, the first %v commit could be any of:", what)
		for _, com := range res.Commits {
			env.log("%v", com.Hash)
		}
		return res, nil
	}
	com := res.Commits[0]
	env.log("first %v commit: %v %v", what, com.Hash, com.Title)
	env.log("cc: %q", com.CC)
	if res.Report != nil {
		env.log("crash: %v\n%s", res.Report.Title, res.Report.Report)
	}
	return res, nil
}

func (env *env) bisect() (*Result, error) {
	cfg := env.cfg
	var err error
	if err := build.Clean(cfg.Manager.TargetOS, cfg.Manager.TargetVMArch,
		cfg.Manager.Type, cfg.Manager.KernelSrc); err != nil {
		return nil, fmt.Errorf("kernel clean failed: %v", err)
	}
	env.log("building syzkaller on %v", cfg.Syzkaller.Commit)
	if err := env.inst.BuildSyzkaller(cfg.Syzkaller.Repo, cfg.Syzkaller.Commit); err != nil {
		return nil, err
	}
	com, err := env.repo.CheckoutCommit(cfg.Kernel.Repo, cfg.Kernel.Commit)
	if err != nil {
		return nil, err
	}
	env.commit = com
	testRes, err := env.test()
	if err != nil {
		return nil, err
	} else if testRes.verdict != vcs.BisectBad {
		return nil, fmt.Errorf("the crash wasn't reproduced on the original commit")
	}
	bad, good, rep1, results1, err := env.commitRange()
	if err != nil {
		return nil, err
	}
	if rep1 != nil {
		return &Result{Report: rep1, Commit: bad}, nil // still not fixed/happens on the oldest release
	}
	results := map[string]*testResult{cfg.Kernel.Commit: testRes}
	for _, res := range results1 {
		results[res.com.Hash] = res
	}
	pred := func() (vcs.BisectResult, error) {
		testRes1, err := env.test()
		if err != nil {
			return 0, err
		}
		if cfg.Fix {
			if testRes1.verdict == vcs.BisectBad {
				testRes1.verdict = vcs.BisectGood
			} else if testRes1.verdict == vcs.BisectGood {
				testRes1.verdict = vcs.BisectBad
			}
		}
		results[testRes1.com.Hash] = testRes1
		return testRes1.verdict, err
	}
	commits, err := env.bisecter.Bisect(bad.Hash, good.Hash, cfg.Trace, pred)
	if err != nil {
		return nil, err
	}
	res := &Result{
		Commits: commits,
	}
	if len(commits) == 1 {
		com := commits[0]
		testRes := results[com.Hash]
		if testRes == nil {
			return nil, fmt.Errorf("no result for culprit commit")
		}
		res.Report = testRes.rep
		isRelease, err := env.bisecter.IsRelease(com.Hash)
		if err != nil {
			env.log("failed to detect release: %v", err)
		}
		res.IsRelease = isRelease
		noopChange, err := env.detectNoopChange(results, com)
		if err != nil {
			env.log("failed to detect noop change: %v", err)
		}
		res.NoopChange = noopChange
	}
	return res, nil
}

func (env *env) detectNoopChange(results map[string]*testResult, com *vcs.Commit) (bool, error) {
	testRes := results[com.Hash]
	if testRes.kernelSign == "" || len(com.Parents) != 1 {
		return false, nil
	}
	parent := com.Parents[0]
	parentRes := results[parent]
	if parentRes == nil {
		env.log("parent commit %v wasn't tested", parent)
		// We could not test the parent commit if it is not based on the previous release
		// (instead based on an older release, i.e. a very old non-rebased commit
		// merged into the current release).
		// TODO: we can use a differnet compiler for this old commit
		// since effectively it's in the older release, in that case we may not
		// detect noop change anyway.
		if _, err := env.repo.SwitchCommit(parent); err != nil {
			return false, err
		}
		_, kernelSign, err := env.build()
		if err != nil {
			return false, err
		}
		parentRes = &testResult{kernelSign: kernelSign}
	}
	env.log("culprit signature: %v", testRes.kernelSign)
	env.log("parent  signature: %v", parentRes.kernelSign)
	return testRes.kernelSign == parentRes.kernelSign, nil
}

func (env *env) commitRange() (*vcs.Commit, *vcs.Commit, *report.Report, []*testResult, error) {
	if env.cfg.Fix {
		return env.commitRangeForFix()
	}
	return env.commitRangeForBug()
}

func (env *env) commitRangeForFix() (*vcs.Commit, *vcs.Commit, *report.Report, []*testResult, error) {
	env.log("testing current HEAD %v", env.head.Hash)
	if _, err := env.repo.SwitchCommit(env.head.Hash); err != nil {
		return nil, nil, nil, nil, err
	}
	res, err := env.test()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if res.verdict != vcs.BisectGood {
		return env.head, nil, res.rep, []*testResult{res}, nil
	}
	return env.head, env.commit, nil, []*testResult{res}, nil
}

func (env *env) commitRangeForBug() (*vcs.Commit, *vcs.Commit, *report.Report, []*testResult, error) {
	cfg := env.cfg
	tags, err := env.bisecter.PreviousReleaseTags(cfg.Kernel.Commit)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if len(tags) == 0 {
		return nil, nil, nil, nil, fmt.Errorf("no release tags before this commit")
	}
	lastBad := env.commit
	var lastRep *report.Report
	var results []*testResult
	for _, tag := range tags {
		env.log("testing release %v", tag)
		com, err := env.repo.SwitchCommit(tag)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		res, err := env.test()
		if err != nil {
			return nil, nil, nil, nil, err
		}
		results = append(results, res)
		if res.verdict == vcs.BisectGood {
			return lastBad, com, nil, results, nil
		}
		if res.verdict == vcs.BisectBad {
			lastBad = com
			lastRep = res.rep
		}
	}
	return lastBad, nil, lastRep, results, nil
}

type testResult struct {
	verdict    vcs.BisectResult
	com        *vcs.Commit
	rep        *report.Report
	kernelSign string
}

func (env *env) build() (*vcs.Commit, string, error) {
	current, err := env.repo.HeadCommit()
	if err != nil {
		return nil, "", err
	}
	bisectEnv, err := env.bisecter.EnvForCommit(env.cfg.BinDir, current.Hash, env.cfg.Kernel.Config)
	if err != nil {
		return nil, "", err
	}
	compilerID, err := build.CompilerIdentity(bisectEnv.Compiler)
	if err != nil {
		return nil, "", err
	}
	env.log("testing commit %v with %v", current.Hash, compilerID)
	buildStart := time.Now()
	mgr := &env.cfg.Manager
	if err := build.Clean(mgr.TargetOS, mgr.TargetVMArch, mgr.Type, mgr.KernelSrc); err != nil {
		return nil, "", fmt.Errorf("kernel clean failed: %v", err)
	}
	kern := &env.cfg.Kernel
	_, kernelSign, err := env.inst.BuildKernel(bisectEnv.Compiler, kern.Userspace,
		kern.Cmdline, kern.Sysctl, bisectEnv.KernelConfig)
	if kernelSign != "" {
		env.log("kernel signature: %v", kernelSign)
	}
	env.buildTime += time.Since(buildStart)
	return current, kernelSign, err
}

func (env *env) test() (*testResult, error) {
	cfg := env.cfg
	env.numTests++
	current, kernelSign, err := env.build()
	if err != nil {
		return nil, err
	}
	res := &testResult{
		verdict:    vcs.BisectSkip,
		com:        current,
		kernelSign: kernelSign,
	}
	if err != nil {
		if verr, ok := err.(*osutil.VerboseError); ok {
			env.log("%v", verr.Title)
			env.saveDebugFile(current.Hash, 0, verr.Output)
		} else if verr, ok := err.(build.KernelBuildError); ok {
			env.log("%v", verr.Title)
			env.saveDebugFile(current.Hash, 0, verr.Output)
		} else {
			env.log("%v", err)
		}
		return res, nil
	}
	testStart := time.Now()
	results, err := env.inst.Test(NumTests, cfg.Repro.Syz, cfg.Repro.Opts, cfg.Repro.C)
	env.testTime += time.Since(testStart)
	if err != nil {
		env.log("failed: %v", err)
		return res, nil
	}
	bad, good, rep := env.processResults(current, results)
	res.rep = rep
	res.verdict = vcs.BisectSkip
	if bad != 0 {
		res.verdict = vcs.BisectBad
	} else if NumTests-good-bad > NumTests/3*2 {
		// More than 2/3 of instances failed with infrastructure error,
		// can't reliably tell that the commit is good.
		res.verdict = vcs.BisectSkip
	} else if good != 0 {
		res.verdict = vcs.BisectGood
	}
	return res, nil
}

func (env *env) processResults(current *vcs.Commit, results []error) (bad, good int, rep *report.Report) {
	var verdicts []string
	for i, res := range results {
		if res == nil {
			good++
			verdicts = append(verdicts, "OK")
			continue
		}
		switch err := res.(type) {
		case *instance.TestError:
			if err.Boot {
				verdicts = append(verdicts, fmt.Sprintf("boot failed: %v", err))
			} else {
				verdicts = append(verdicts, fmt.Sprintf("basic kernel testing failed: %v", err))
			}
			output := err.Output
			if err.Report != nil {
				output = err.Report.Output
			}
			env.saveDebugFile(current.Hash, i, output)
		case *instance.CrashError:
			bad++
			rep = err.Report
			verdicts = append(verdicts, fmt.Sprintf("crashed: %v", err))
			output := err.Report.Report
			if len(output) == 0 {
				output = err.Report.Output
			}
			env.saveDebugFile(current.Hash, i, output)
		default:
			verdicts = append(verdicts, fmt.Sprintf("failed: %v", err))
		}
	}
	unique := make(map[string]bool)
	for _, verdict := range verdicts {
		unique[verdict] = true
	}
	if len(unique) == 1 {
		env.log("all runs: %v", verdicts[0])
	} else {
		for i, verdict := range verdicts {
			env.log("run #%v: %v", i, verdict)
		}
	}
	return
}

func (env *env) saveDebugFile(hash string, idx int, data []byte) {
	if env.cfg.DebugDir == "" || len(data) == 0 {
		return
	}
	osutil.MkdirAll(env.cfg.DebugDir)
	osutil.WriteFile(filepath.Join(env.cfg.DebugDir, fmt.Sprintf("%v.%v", hash, idx)), data)
}

func checkConfig(cfg *Config) error {
	if !osutil.IsExist(cfg.BinDir) {
		return fmt.Errorf("bin dir %v does not exist", cfg.BinDir)
	}
	if cfg.Kernel.Userspace != "" && !osutil.IsExist(cfg.Kernel.Userspace) {
		return fmt.Errorf("userspace dir %v does not exist", cfg.Kernel.Userspace)
	}
	if cfg.Kernel.Sysctl != "" && !osutil.IsExist(cfg.Kernel.Sysctl) {
		return fmt.Errorf("sysctl file %v does not exist", cfg.Kernel.Sysctl)
	}
	if cfg.Kernel.Cmdline != "" && !osutil.IsExist(cfg.Kernel.Cmdline) {
		return fmt.Errorf("cmdline file %v does not exist", cfg.Kernel.Cmdline)
	}
	return nil
}

func (env *env) log(msg string, args ...interface{}) {
	fmt.Fprintf(env.cfg.Trace, msg+"\n", args...)
}
