// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package bisect

import (
	"errors"
	"fmt"
	"math"
	"os"
	"sort"
	"time"

	"github.com/google/syzkaller/pkg/build"
	"github.com/google/syzkaller/pkg/debugtracer"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/report/crash"
	"github.com/google/syzkaller/pkg/vcs"
)

type Config struct {
	Trace           debugtracer.DebugTracer
	Fix             bool
	DefaultCompiler string
	CompilerType    string
	Linker          string
	BinDir          string
	Ccache          string
	Timeout         time.Duration
	Kernel          KernelConfig
	Syzkaller       SyzkallerConfig
	Repro           ReproConfig
	Manager         *mgrconfig.Config
	BuildSemaphore  *instance.Semaphore
	TestSemaphore   *instance.Semaphore
	// CrossTree specifies whether a cross tree bisection is to take place, i.e.
	// Kernel.Commit is not reachable from Kernel.Branch.
	// In this case, bisection starts from their merge base.
	CrossTree bool
}

type KernelConfig struct {
	Repo        string
	Branch      string
	Commit      string
	CommitTitle string
	Cmdline     string
	Sysctl      string
	Config      []byte
	// Baseline configuration is used in commit bisection. If the crash doesn't reproduce
	// with baseline configuratopm config bisection is run. When triggering configuration
	// option is found provided baseline configuration is modified according the bisection
	// results. This new configuration is tested once more with current head. If crash
	// reproduces with the generated configuration original configuation is replaced with
	// this minimized one.
	BaselineConfig []byte
	Userspace      string
	// Extra commits to cherry pick to older kernel revisions.
	Backports []vcs.BackportCommit
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
	cfg          *Config
	repo         vcs.Repo
	bisecter     vcs.Bisecter
	minimizer    vcs.ConfigMinimizer
	commit       *vcs.Commit
	head         *vcs.Commit
	kernelConfig []byte
	inst         instance.Env
	numTests     int
	startTime    time.Time
	buildTime    time.Duration
	testTime     time.Duration
	reportTypes  []crash.Type
	// The current estimate of the reproducer's kernel crashing probability.
	reproChance float64
	// The product of our confidence in every bisection step result.
	confidence float64
	// Whether we should do 2x more execution runs for every test step.
	// We could have inferred this data from reproChance, but we want to be
	// able to react faster to sudden drops of reproducibility than an estimate
	// can allows us to.
	flaky bool
	// A cache of already performed revision tests.
	results map[string]*testResult
}

const MaxNumTests = 20 // number of tests we do per commit

// Result describes bisection result:
// 1. if bisection is conclusive, the single cause/fix commit in Commits
//   - for cause bisection report is the crash on the cause commit
//   - for fix bisection report is nil
//   - Commit is nil
//   - NoopChange is set if the commit did not cause any change in the kernel binary
//     (bisection result it most likely wrong)
//
// 2. Bisected to a release commit
//   - if bisection is inconclusive, range of potential cause/fix commits in Commits
//   - report is nil in such case
//
// 3. Commit is nil
//   - if the crash still happens on the oldest release/HEAD (for cause/fix bisection correspondingly)
//   - no commits in Commits
//   - the crash report on the oldest release/HEAD;
//   - Commit points to the oldest/latest commit where crash happens.
//
// 4. Config contains kernel config used for bisection.
type Result struct {
	Commits    []*vcs.Commit
	Report     *report.Report
	Commit     *vcs.Commit
	Config     []byte
	NoopChange bool
	IsRelease  bool
	Confidence float64
}

type InfraError struct {
	Title string
}

func (e InfraError) Error() string {
	return e.Title
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
	inst, err := instance.NewEnv(cfg.Manager, cfg.BuildSemaphore, cfg.TestSemaphore)
	if err != nil {
		return nil, err
	}
	if _, err = repo.CheckoutBranch(cfg.Kernel.Repo, cfg.Kernel.Branch); err != nil {
		return nil, &InfraError{Title: fmt.Sprintf("%v", err)}
	}
	return runImpl(cfg, repo, inst)
}

func runImpl(cfg *Config, repo vcs.Repo, inst instance.Env) (*Result, error) {
	bisecter, ok := repo.(vcs.Bisecter)
	if !ok {
		return nil, fmt.Errorf("bisection is not implemented for %v", cfg.Manager.TargetOS)
	}
	minimizer, ok := repo.(vcs.ConfigMinimizer)
	if !ok && len(cfg.Kernel.BaselineConfig) != 0 {
		return nil, fmt.Errorf("config minimization is not implemented for %v", cfg.Manager.TargetOS)
	}
	env := &env{
		cfg:        cfg,
		repo:       repo,
		bisecter:   bisecter,
		minimizer:  minimizer,
		inst:       inst,
		startTime:  time.Now(),
		confidence: 1.0,
	}
	head, err := repo.HeadCommit()
	if err != nil {
		return nil, err
	}
	defer env.repo.SwitchCommit(head.Hash)
	env.head = head
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unnamed host"
	}
	env.log("%s starts bisection %s", hostname, env.startTime.String())
	if cfg.Fix {
		env.log("bisecting fixing commit since %v", cfg.Kernel.Commit)
	} else {
		env.log("bisecting cause commit starting from %v", cfg.Kernel.Commit)
	}
	start := time.Now()
	res, err := env.bisect()
	if env.flaky {
		env.log("reproducer is flaky (%.2f repro chance estimate)", env.reproChance)
	}
	env.log("revisions tested: %v, total time: %v (build: %v, test: %v)",
		env.numTests, time.Since(start), env.buildTime, env.testTime)
	if err != nil {
		env.log("error: %v", err)
		return nil, err
	}
	if len(res.Commits) == 0 {
		if cfg.Fix {
			env.log("crash still not fixed or there were kernel test errors")
		} else {
			env.log("oldest tested release already had the bug or it had kernel test errors")
		}

		env.log("commit msg: %v", res.Commit.Title)
		if res.Report != nil {
			env.log("crash: %v\n%s", res.Report.Title, res.Report.Report)
		}
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
	env.log("recipients (to): %q", com.Recipients.GetEmails(vcs.To))
	env.log("recipients (cc): %q", com.Recipients.GetEmails(vcs.Cc))
	if res.Report != nil {
		env.log("crash: %v\n%s", res.Report.Title, res.Report.Report)
	}
	return res, nil
}

func (env *env) bisect() (*Result, error) {
	err := env.bisecter.PrepareBisect()
	if err != nil {
		return nil, err
	}

	cfg := env.cfg
	if err := build.Clean(cfg.Manager.TargetOS, cfg.Manager.TargetVMArch,
		cfg.Manager.Type, cfg.Manager.KernelSrc); err != nil {
		return nil, fmt.Errorf("kernel clean failed: %w", err)
	}
	env.log("building syzkaller on %v", cfg.Syzkaller.Commit)
	if _, err := env.inst.BuildSyzkaller(cfg.Syzkaller.Repo, cfg.Syzkaller.Commit); err != nil {
		return nil, err
	}

	cfg.Kernel.Commit, err = env.identifyRewrittenCommit()
	if err != nil {
		return nil, err
	}
	com, err := env.repo.SwitchCommit(cfg.Kernel.Commit)
	if err != nil {
		return nil, err
	}

	env.log("ensuring issue is reproducible on original commit %v\n", cfg.Kernel.Commit)
	env.commit = com
	env.kernelConfig = cfg.Kernel.Config
	testRes, err := env.test()
	if err != nil {
		return nil, err
	} else if testRes.verdict != vcs.BisectBad {
		return nil, fmt.Errorf("the crash wasn't reproduced on the original commit")
	}
	env.reportTypes = testRes.types
	env.reproChance = testRes.badRatio

	testRes1, err := env.minimizeConfig()
	if err != nil {
		return nil, fmt.Errorf("config minimization failed: %w", err)
	}
	if testRes1 != nil {
		// If config minimization even partially succeeds, minimizeConfig()
		// would return a non-nil value of a new report.
		testRes = testRes1
		// Overwrite bug's reproducibility - it may be different after config minimization.
		env.reproChance = testRes.badRatio
	}

	bad, good, results1, fatalResult, err := env.commitRange()
	if fatalResult != nil || err != nil {
		return fatalResult, err
	}
	if env.cfg.Fix {
		env.commit = good
	} else {
		env.commit = bad
	}
	env.results = map[string]*testResult{cfg.Kernel.Commit: testRes}
	for _, res := range results1 {
		env.results[res.com.Hash] = res
	}
	commits, err := env.bisecter.Bisect(bad.Hash, good.Hash, cfg.Trace, env.testPredicate)
	if err != nil {
		return nil, err
	}
	env.log("accumulated error probability: %0.2f", 1.0-env.confidence)
	res := &Result{
		Commits:    commits,
		Config:     env.kernelConfig,
		Confidence: env.confidence,
	}
	if len(commits) == 1 {
		com := commits[0]
		testRes := env.results[com.Hash]
		if testRes == nil {
			return nil, fmt.Errorf("no result for culprit commit")
		}
		res.Report = testRes.rep
		isRelease, err := env.bisecter.IsRelease(com.Hash)
		if err != nil {
			env.log("failed to detect release: %v", err)
		}
		res.IsRelease = isRelease
		noopChange, err := env.detectNoopChange(com)
		if err != nil {
			env.log("failed to detect noop change: %v", err)
		}
		res.NoopChange = noopChange
	}
	return res, nil
}

func (env *env) identifyRewrittenCommit() (string, error) {
	cfg := env.cfg
	if cfg.Kernel.Commit != "" && cfg.CrossTree {
		// If the failing commit is on another tree, just take it as is.
		return cfg.Kernel.Commit, nil
	}
	_, err := env.repo.CheckoutBranch(cfg.Kernel.Repo, cfg.Kernel.Branch)
	if err != nil {
		return cfg.Kernel.Commit, err
	}
	contained, err := env.repo.Contains(cfg.Kernel.Commit)
	if err != nil || contained {
		return cfg.Kernel.Commit, err
	}

	if !cfg.Fix {
		// If we're doing a cause bisection, we don't really need the commit to be
		// reachable from cfg.Kernel.Branch.
		// So let's try to force tag fetch and check if the commit is present in the
		// repository.
		env.log("fetch other tags and check if the commit is present")
		commit, err := env.repo.CheckoutCommit(cfg.Kernel.Repo, cfg.Kernel.Commit)
		if err != nil {
			// Ignore the error because the command will fail if the commit is really not
			// present in the tree.
			env.log("fetch failed with %s", err)
		} else if commit != nil {
			return commit.Hash, nil
		}
	}

	// We record the tested kernel commit when syzkaller triggers a crash. These commits can become
	// unreachable after the crash was found, when the history of the tested kernel branch was
	// rewritten. The commit might have been completely deleted from the branch or just changed in
	// some way. Some branches like linux-next are often and heavily rewritten (aka rebased).
	// This can also happen when changing the branch you fuzz in an existing syz-manager config.
	// This makes sense when a downstream kernel fork rebased on top of a new upstream version and
	// you don't want syzkaller to report all your old bugs again.
	if cfg.Kernel.CommitTitle == "" {
		// This can happen during a manual bisection, when only a hash is given.
		return cfg.Kernel.Commit, fmt.Errorf(
			"commit %v not reachable in branch '%v' and no commit title available",
			cfg.Kernel.Commit, cfg.Kernel.Branch)
	}
	commit, err := env.repo.GetCommitByTitle(cfg.Kernel.CommitTitle)
	if err != nil {
		return cfg.Kernel.Commit, err
	}
	if commit == nil {
		return cfg.Kernel.Commit, fmt.Errorf(
			"commit %v not reachable in branch '%v'", cfg.Kernel.Commit, cfg.Kernel.Branch)
	}
	env.log("rewritten commit %v reidentified by title '%v'\n", commit.Hash, cfg.Kernel.CommitTitle)
	return commit.Hash, nil
}

func (env *env) minimizeConfig() (*testResult, error) {
	// Find minimal configuration based on baseline to reproduce the crash.
	testResults := make(map[hash.Sig]*testResult)
	predMinimize := func(test []byte) (vcs.BisectResult, error) {
		env.kernelConfig = test
		testRes, err := env.test()
		if err != nil {
			return 0, err
		}
		// We want either a > 33% repro probability or at least it should not be
		// worse than for the non-minimized config.
		const badRatioThreshold = 1.0 / 3.0
		if testRes.verdict == vcs.BisectBad &&
			testRes.badRatio < badRatioThreshold &&
			testRes.badRatio < env.reproChance {
			return vcs.BisectSkip, nil
		}
		if testRes.verdict == vcs.BisectBad {
			// Only remember crashes.
			testResults[hash.Hash(test)] = testRes
		}
		return testRes.verdict, err
	}
	minConfig, err := env.minimizer.Minimize(env.cfg.Manager.SysTarget, env.cfg.Kernel.Config,
		env.cfg.Kernel.BaselineConfig, env.reportTypes, env.cfg.Trace, predMinimize)
	if err != nil {
		if errors.Is(err, vcs.ErrBadKconfig) {
			env.log("config minimization failed due to bad Kconfig %v\nproceeding with the original config", err)
		} else {
			return nil, err
		}
	}
	env.kernelConfig = minConfig
	return testResults[hash.Hash(minConfig)], nil
}

func (env *env) detectNoopChange(com *vcs.Commit) (bool, error) {
	testRes := env.results[com.Hash]
	if testRes.kernelSign == "" || len(com.Parents) != 1 {
		return false, nil
	}
	parent := com.Parents[0]
	parentRes := env.results[parent]
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

func (env *env) commitRange() (*vcs.Commit, *vcs.Commit, []*testResult, *Result, error) {
	rangeFunc := env.commitRangeForCause
	if env.cfg.Fix {
		rangeFunc = env.commitRangeForFix
	}

	bad, good, results1, err := rangeFunc()
	if err != nil {
		return bad, good, results1, nil, err
	}

	fatalResult, err := env.validateCommitRange(bad, good, results1)
	return bad, good, results1, fatalResult, err
}

func (env *env) commitRangeForFix() (*vcs.Commit, *vcs.Commit, []*testResult, error) {
	var results []*testResult
	startCommit := env.commit
	if env.cfg.CrossTree {
		env.log("determining the merge base between %v and %v",
			env.commit.Hash, env.head.Hash)
		bases, err := env.repo.MergeBases(env.commit.Hash, env.head.Hash)
		if err != nil {
			return nil, nil, nil, err
		}
		if len(bases) != 1 {
			env.log("expected 1 merge base, got %d", len(bases))
			return nil, nil, nil, fmt.Errorf("expected 1 merge base, got %d", len(bases))
		}
		env.log("%s/%s is a merge base, check if it has the bug", bases[0].Hash, bases[0].Title)
		startCommit = bases[0]
		if _, err := env.repo.SwitchCommit(startCommit.Hash); err != nil {
			return nil, nil, nil, err
		}
		res, err := env.test()
		if err != nil {
			return nil, nil, nil, err
		}
		results = append(results, res)
		if res.verdict != vcs.BisectBad {
			return nil, startCommit, results, nil
		}
	}
	env.log("testing current HEAD %v", env.head.Hash)
	if _, err := env.repo.SwitchCommit(env.head.Hash); err != nil {
		return nil, nil, nil, err
	}
	res, err := env.test()
	if err != nil {
		return nil, nil, nil, err
	}
	results = append(results, res)
	if res.verdict != vcs.BisectGood {
		return env.head, nil, results, nil
	}
	return env.head, startCommit, results, nil
}

func (env *env) commitRangeForCause() (*vcs.Commit, *vcs.Commit, []*testResult, error) {
	cfg := env.cfg
	tags, err := env.bisecter.PreviousReleaseTags(cfg.Kernel.Commit, cfg.CompilerType)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(tags) == 0 {
		return nil, nil, nil, fmt.Errorf("no release tags before this commit")
	}
	pickedTags := pickReleaseTags(tags)
	env.log("picked %v out of %d release tags", pickedTags, len(tags))

	lastBad := env.commit
	var results []*testResult
	for _, tag := range pickedTags {
		env.log("testing release %v", tag)
		com, err := env.repo.SwitchCommit(tag)
		if err != nil {
			return nil, nil, nil, err
		}
		res, err := env.test()
		if err != nil {
			return nil, nil, nil, err
		}
		results = append(results, res)
		if res.verdict == vcs.BisectGood {
			return lastBad, com, results, nil
		}
		if res.verdict == vcs.BisectBad {
			lastBad = com
		}
	}
	// All tags were vcs.BisectBad or vcs.BisectSkip.
	return lastBad, nil, results, nil
}

func (env *env) validateCommitRange(bad, good *vcs.Commit, results []*testResult) (*Result, error) {
	if len(results) < 1 {
		return nil, fmt.Errorf("commitRange returned no results")
	}

	if env.cfg.Fix && env.cfg.CrossTree && len(results) < 2 {
		// For cross-tree bisections, it can be the case that the bug was introduced
		// after the merge base, so there's no sense to continue the fix bisection.
		env.log("reproducer does not crash the merge base, so there's no known bad commit")
		return &Result{Commit: good, Config: env.kernelConfig}, nil
	}

	finalResult := results[len(results)-1] // HEAD test for fix, oldest tested test for cause bisection
	if finalResult.verdict == vcs.BisectBad {
		// For cause bisection: Oldest tested release already had the bug. Giving up.
		// For fix bisection:   Crash still not fixed on HEAD. Leaving Result.Commits empty causes
		//                      syzbot to retry this bisection later.
		env.log("crash still not fixed/happens on the oldest tested release")
		return &Result{Report: finalResult.rep, Commit: bad, Config: env.kernelConfig}, nil
	}
	if finalResult.verdict == vcs.BisectSkip {
		if env.cfg.Fix {
			// HEAD is moving target. Sometimes changes break syzkaller fuzzing.
			// Leaving Result.Commits empty so syzbot retries this bisection again later.
			env.log("HEAD had kernel build, boot or test errors")
			return &Result{Report: finalResult.rep, Commit: bad, Config: env.kernelConfig}, nil
		}
		// The oldest tested release usually doesn't change. Retrying would give us the same result,
		// unless we change the syz-ci setup (e.g. new rootfs, new compilers).
		return nil, fmt.Errorf("oldest tested release had kernel build, boot or test errors")
	}

	return nil, nil
}

type testResult struct {
	verdict    vcs.BisectResult
	com        *vcs.Commit
	rep        *report.Report
	types      []crash.Type
	kernelSign string
	// The ratio of bad/(good+bad) results.
	badRatio float64
	// An estimate how much we can trust the result.
	confidence float64
}

func (env *env) build() (*vcs.Commit, string, error) {
	current, err := env.repo.HeadCommit()
	if err != nil {
		return nil, "", err
	}

	bisectEnv, err := env.bisecter.EnvForCommit(
		env.cfg.DefaultCompiler, env.cfg.CompilerType,
		env.cfg.BinDir, current.Hash, env.kernelConfig,
		env.cfg.Kernel.Backports,
	)
	if err != nil {
		return current, "", err
	}
	env.log("testing commit %v %v", current.Hash, env.cfg.CompilerType)
	buildStart := time.Now()
	mgr := env.cfg.Manager
	if err := build.Clean(mgr.TargetOS, mgr.TargetVMArch, mgr.Type, mgr.KernelSrc); err != nil {
		return current, "", fmt.Errorf("kernel clean failed: %w", err)
	}
	kern := &env.cfg.Kernel
	_, imageDetails, err := env.inst.BuildKernel(&instance.BuildKernelConfig{
		CompilerBin:  bisectEnv.Compiler,
		LinkerBin:    env.cfg.Linker,
		CcacheBin:    env.cfg.Ccache,
		UserspaceDir: kern.Userspace,
		CmdlineFile:  kern.Cmdline,
		SysctlFile:   kern.Sysctl,
		KernelConfig: bisectEnv.KernelConfig,
	})
	if imageDetails.CompilerID != "" {
		env.log("compiler: %v", imageDetails.CompilerID)
	}
	if imageDetails.Signature != "" {
		env.log("kernel signature: %v", imageDetails.Signature)
	}
	env.buildTime += time.Since(buildStart)
	return current, imageDetails.Signature, err
}

// Note: When this function returns an error, the bisection it was called from is aborted.
// Hence recoverable errors must be handled and the callers must treat testResult with care.
// e.g. testResult.verdict will be vcs.BisectSkip for a broken build, but err will be nil.
func (env *env) test() (*testResult, error) {
	cfg := env.cfg
	if cfg.Timeout != 0 && time.Since(env.startTime) > cfg.Timeout {
		return nil, fmt.Errorf("bisection is taking too long (>%v), aborting", cfg.Timeout)
	}
	current, kernelSign, err := env.build()
	res := &testResult{
		verdict:    vcs.BisectSkip,
		com:        current,
		kernelSign: kernelSign,
		confidence: 1.0,
	}
	if current == nil {
		// This is not recoverable, as the caller must know which commit to skip.
		return res, fmt.Errorf("couldn't get repo HEAD: %w", err)
	}
	if err != nil {
		errInfo := fmt.Sprintf("failed building %v: ", current.Hash)
		var verr *osutil.VerboseError
		var kerr *build.KernelError
		if errors.As(err, &verr) {
			errInfo += verr.Title
			env.saveDebugFile(current.Hash, 0, verr.Output)
		} else if errors.As(err, &kerr) {
			errInfo += string(kerr.Report)
			env.saveDebugFile(current.Hash, 0, kerr.Output)
		} else {
			errInfo += err.Error()
			env.log("%v", err)
		}

		env.log("%s", errInfo)
		res.rep = &report.Report{Title: errInfo}
		return res, nil
	}

	numTests := MaxNumTests / 2
	if env.flaky || env.numTests == 0 {
		// Use twice as many instances if the bug is flaky and during initial testing
		// (as we don't know yet if it's flaky or not).
		numTests *= 2
	}
	env.numTests++

	testStart := time.Now()

	results, err := env.inst.Test(numTests, cfg.Repro.Syz, cfg.Repro.Opts, cfg.Repro.C)
	env.testTime += time.Since(testStart)
	if err != nil {
		problem := fmt.Sprintf("repro testing failure: %v", err)
		env.log(problem)
		return res, &InfraError{Title: problem}
	}
	bad, good, infra, rep, types := env.processResults(current, results)
	res.verdict, err = env.bisectionDecision(len(results), bad, good, infra)
	if err != nil {
		return nil, err
	}
	if bad+good > 0 {
		res.badRatio = float64(bad) / float64(bad+good)
	}
	if res.verdict == vcs.BisectGood {
		// The result could be a false negative.
		res.confidence = 1.0 - math.Pow(1.0-env.reproChance, float64(good))
		env.log("false negative chance: %.3f", 1.0-res.confidence)
	}
	if res.verdict == vcs.BisectSkip {
		res.rep = &report.Report{
			Title: fmt.Sprintf("failed testing reproducer on %v", current.Hash),
		}
	} else {
		// Pick the most relevant as the main one.
		res.rep = rep
	}
	res.types = types
	env.updateFlaky(res)
	// TODO: when we start supporting boot/test error bisection, we need to make
	// processResults treat that verdit as "good".
	return res, nil
}

// testPredicate() is meant to be invoked by bisecter.Bisect().
func (env *env) testPredicate() (vcs.BisectResult, error) {
	var testRes1 *testResult
	if env.cfg.Fix {
		// There's a chance we might test a revision that does not yet contain the bug.
		// Perform extra checks (see #4117).
		env.log("determine whether the revision contains the guilty commit")
		hadBug, err := env.revisionHadBug()
		if err == errUnknownBugPresence {
			// Let's skip the revision just in case.
			testRes1 = &testResult{verdict: vcs.BisectSkip}
		} else if err != nil {
			return 0, err
		}
		if !hadBug {
			// For result consistency, pretend that the kernel crashed.
			env.log("the bug was not introduced yet; pretend that kernel crashed")
			testRes1 = &testResult{verdict: vcs.BisectBad}
		}
	}
	if testRes1 == nil {
		var err error
		testRes1, err = env.test()
		if err != nil {
			return 0, err
		}
		env.postTestResult(testRes1)
		env.results[testRes1.com.Hash] = testRes1
	}
	// For fix bisections, results are inverted.
	if env.cfg.Fix {
		if testRes1.verdict == vcs.BisectBad {
			testRes1.verdict = vcs.BisectGood
		} else if testRes1.verdict == vcs.BisectGood {
			testRes1.verdict = vcs.BisectBad
		}
	}
	return testRes1.verdict, nil
}

// If there's a merge from a branch that was based on a much older code revision,
// it's likely that the bug was not yet present at all.
var errUnknownBugPresence = errors.New("unable to determine whether there was a bug")

func (env *env) revisionHadBug() (bool, error) {
	// Check if any already tested revision that is reachable from HEAD crashed.
	for hash, res := range env.results {
		if res.rep == nil {
			continue
		}
		ok, err := env.repo.Contains(hash)
		if err != nil {
			return false, err
		}
		if ok {
			env.log("revision %s crashed and is reachable", hash)
			return true, nil
		}
	}

	// TODO: it's also possible to extract useful information from non-crashed runs.
	// But let's first see how many extra test() runs we get without it.

	// We'll likely change the revision below. Ensure we get back to the original one.
	curr, err := env.repo.HeadCommit()
	if err != nil {
		return false, err
	}
	defer env.repo.SwitchCommit(curr.Hash)

	// Check all merge bases between the original bad commit (*) and the current HEAD revision.
	// If at least one crashed, bug was definitely present.
	// (*) Using the same bad commit hopefully helps us reuse many of the results.
	bases, err := env.repo.MergeBases(curr.Hash, env.commit.Hash)
	if err != nil {
		return false, fmt.Errorf("failed to get the merge base between %s and %s: %w",
			curr.Hash, env.commit.Hash, err)
	}
	anyResult := false
	for _, base := range bases {
		env.log("checking the merge base %s", base.Hash)
		res := env.results[base.Hash]
		if res == nil {
			env.log("no existing result, test the revision")
			env.repo.SwitchCommit(base.Hash)
			res, err = env.test()
			if err != nil {
				return false, err
			}
			env.results[base.Hash] = res
		}
		if res.verdict == vcs.BisectSkip {
			continue
		}
		anyResult = true
		if res.rep != nil {
			// No reason to test other bases.
			return true, nil
		}
	}
	if anyResult {
		return false, nil
	}
	return false, errUnknownBugPresence
}

func (env *env) bisectionDecision(total, bad, good, infra int) (vcs.BisectResult, error) {
	// Boot errors, image test errors, skipped crashes.
	skip := total - bad - good - infra

	wantGoodRuns := total / 2
	wantTotalRuns := total / 2
	if env.flaky {
		// The reproducer works less than 50% of time, so we need really many good results.
		wantGoodRuns = total * 3 / 4
	}
	if bad == 0 && good >= wantGoodRuns {
		// We need a big enough number of good results, otherwise the chance of a false
		// positive is too high.
		return vcs.BisectGood, nil
	} else if bad > 0 && (good+bad) >= wantTotalRuns {
		// We need enough (good+bad) results to conclude that the kernel revision itself
		// is not too broken.
		return vcs.BisectBad, nil
	} else if infra > skip {
		// We have been unable to determine a verdict mostly because of infra errors.
		// Abort the bisection.
		return vcs.BisectSkip,
			&InfraError{Title: "unable to determine the verdict because of infra errors"}
	}
	env.log("unable to determine the verdict: %d good runs (wanted %d), for bad wanted %d in total, got %d",
		good, wantGoodRuns, wantTotalRuns, good+bad)
	return vcs.BisectSkip, nil
}

func (env *env) processResults(current *vcs.Commit, results []instance.EnvTestResult) (
	bad, good, infra int, rep *report.Report, types []crash.Type) {
	var verdicts []string
	var reports []*report.Report
	for i, res := range results {
		if res.Error == nil {
			good++
			verdicts = append(verdicts, "OK")
			continue
		}
		var testError *instance.TestError
		var crashError *instance.CrashError
		switch {
		case errors.As(res.Error, &testError):
			if testError.Infra {
				infra++
				verdicts = append(verdicts, fmt.Sprintf("infra problem: %v", testError))
			} else if testError.Boot {
				verdicts = append(verdicts, fmt.Sprintf("boot failed: %v", testError))
			} else {
				verdicts = append(verdicts, fmt.Sprintf("basic kernel testing failed: %v", testError))
			}
			output := testError.Output
			if testError.Report != nil {
				output = testError.Report.Output
			}
			env.saveDebugFile(current.Hash, i, output)
		case errors.As(res.Error, &crashError):
			output := crashError.Report.Report
			if len(output) == 0 {
				output = crashError.Report.Output
			}
			env.saveDebugFile(current.Hash, i, output)
			if env.isTransientError(crashError.Report) {
				verdicts = append(verdicts, fmt.Sprintf("ignore: %v", crashError))
				break
			}
			bad++
			reports = append(reports, crashError.Report)
			verdicts = append(verdicts, fmt.Sprintf("crashed: %v", crashError))
		default:
			infra++
			verdicts = append(verdicts, fmt.Sprintf("failed: %v", res.Error))
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
	var others bool
	rep, types, others = mostFrequentReports(reports)
	if rep != nil || others {
		// TODO: set flaky=true or in some other way indicate that the bug
		// triggers multiple different crashes?
		env.log("representative crash: %v, types: %v", rep.Title, types)
	}
	return
}

// postTestResult() is to be run after we have got the results of a test() call for a revision.
// It updates the estimates of reproducibility and the overall result confidence.
func (env *env) postTestResult(res *testResult) {
	env.confidence *= res.confidence
	if res.verdict == vcs.BisectBad {
		// Let's be conservative and only decrease our reproduction likelihood estimate.
		// As the estimate of each test() can also be flaky, only partially update the result.
		avg := (env.reproChance + res.badRatio) / 2.0
		if env.reproChance > avg {
			env.reproChance = avg
		}
	}
}

// updateFlaky() updates the current flakiness estimate.
func (env *env) updateFlaky(res *testResult) {
	// We require at least 5 good+bad runs for a verdict, so
	// with a 50% reproducility there's a ~3% chance of a false negative result.
	// If there are 10 "good" results, that's a ~36% accumulated error probability.
	// That's already noticeable, so let's do 2x more runs from there.
	const flakyThreshold = 0.5
	if res.verdict == vcs.BisectBad && res.badRatio < flakyThreshold {
		// Once flaky => always treat as flaky.
		env.flaky = true
	}
}

// mostFrequentReports() processes the list of run results and determines:
// 1) The most representative crash types.
// 2) The most representative crash report.
// The algorithm is described in code comments.
func mostFrequentReports(reports []*report.Report) (*report.Report, []crash.Type, bool) {
	// First find most frequent report types.
	type info struct {
		t      crash.Type
		count  int
		report *report.Report
	}
	crashes := 0
	perType := []*info{}
	perTypeMap := map[crash.Type]*info{}
	for _, rep := range reports {
		if rep.Title == "" {
			continue
		}
		crashes++
		if perTypeMap[rep.Type] == nil {
			obj := &info{
				t:      rep.Type,
				report: rep,
			}
			perType = append(perType, obj)
			perTypeMap[rep.Type] = obj
		}
		perTypeMap[rep.Type].count++
	}
	sort.Slice(perType, func(i, j int) bool {
		return perType[i].count > perType[j].count
	})
	// Then pick those that are representative enough.
	var bestTypes []crash.Type
	var bestReport *report.Report
	taken := 0
	for _, info := range perType {
		if info.t == crash.Hang && info.count*2 < crashes && len(perType) > 1 {
			// To pick a Hang as a representative one, require >= 50%
			// of all crashes to be of this type.
			// Hang crashes can appear in various parts of the kernel, so
			// we only want to take them into account only if we are actually
			// bisecting this kind of a bug.
			continue
		}
		// Take further crash types until we have considered 2/3 of all crashes, but
		// no more than 3.
		needTaken := (crashes + 2) * 2 / 3
		if taken < needTaken && len(bestTypes) < 3 {
			if bestReport == nil {
				bestReport = info.report
			}
			bestTypes = append(bestTypes, info.t)
			taken += info.count
		}
	}
	return bestReport, bestTypes, len(bestTypes) != len(perType)
}

func (env *env) isTransientError(rep *report.Report) bool {
	// If we're not chasing a SYZFATAL error, ignore them.
	// Otherwise it indicates some transient problem of the tested kernel revision.
	hadSyzFailure := false
	for _, t := range env.reportTypes {
		hadSyzFailure = hadSyzFailure || t == crash.SyzFailure
	}
	return rep.Type == crash.SyzFailure &&
		len(env.reportTypes) > 0 && !hadSyzFailure
}

func (env *env) saveDebugFile(hash string, idx int, data []byte) {
	env.cfg.Trace.SaveFile(fmt.Sprintf("%v.%v", hash, idx), data)
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
	if false {
		_ = fmt.Sprintf(msg, args...) // enable printf checker
	}
	env.cfg.Trace.Log(msg, args...)
}

// pickReleaseTags() picks a subset of revisions to test.
// `all` is an ordered list of tags (from newer to older).
func pickReleaseTags(all []string) []string {
	if len(all) == 0 {
		return nil
	}
	// First split into x.y.z, x.y.z-1, ... and x.y, x.y-1, ...
	var subReleases, releases []string
	releaseBegin := false
	for _, tag := range all {
		v1, _, rc, v3 := vcs.ParseReleaseTag(tag)
		if v1 < 0 || rc < 0 && v3 < 0 {
			releaseBegin = true
			releases = append(releases, tag)
		}
		if !releaseBegin {
			subReleases = append(subReleases, tag)
		}
	}
	var ret []string
	// Take 2 latest sub releases.
	takeSubReleases := minInts(2, len(subReleases))
	ret = append(ret, subReleases[:takeSubReleases]...)
	// If there are a lot of sub releases, also take the middle one.
	if len(subReleases) > 5 {
		ret = append(ret, subReleases[len(subReleases)/2])
	}
	for i := 0; i < len(releases); i++ {
		// Gradually increase step.
		step := 1
		if i >= 3 {
			step = 2
		}
		if i >= 11 {
			step = 3
		}
		if i%step == 0 || i == len(releases)-1 {
			ret = append(ret, releases[i])
		}
	}
	return ret
}

func minInts(vals ...int) int {
	ret := vals[0]
	for i := 1; i < len(vals); i++ {
		if vals[i] < ret {
			ret = vals[i]
		}
	}
	return ret
}
