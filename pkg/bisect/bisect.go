// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package bisect

import (
	"bytes"
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
	Timeout   time.Duration
	Kernel    KernelConfig
	Syzkaller SyzkallerConfig
	Repro     ReproConfig
	Manager   mgrconfig.Config
}

type KernelConfig struct {
	Repo    string
	Branch  string
	Commit  string
	Cmdline string
	Sysctl  string
	Config  []byte
	// Baseline configuration is used in commit bisection. If the crash doesn't reproduce
	// with baseline configuration, config bisection is run. When triggering configuration
	// option is found, the provided baseline configuration is modified according to the
	// bisection results. This new configuration is tested once more with current head.
	// If the crash reproduces with the generated configuration, original configuration is
	// replaced with this minimized one.
	BaselineConfig []byte
	Userspace      string
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
	cfg              *Config
	repo             vcs.Repo
	bisecter         vcs.Bisecter
	minimizer        vcs.ConfigMinimizer
	commit           *vcs.Commit
	head             *vcs.Commit
	kernelConfig     []byte
	inst             instance.Env
	numTests         int
	startTime        time.Time
	buildTime        time.Duration
	testTime         time.Duration
	buildTestRsltMap map[string]*fullBuildProcessingResult // by kernelSign (as e.g., in testResult)
}

const NumTests = 10 // number of tests we do per commit

// Result describes bisection result:
//  - if bisection is conclusive, the single cause/fix commit in Commits
//    - for cause bisection, report is the crash on the cause commit
//    - for fix bisection report is nil
//    - Commit is nil
//    - NoopChange is set if the bisection result commit did not cause any change in the kernel binary
//      and this could not be fixed (bisection result it most likely wrong)
//      - OrigBisectWasNoOpCmt is also set for the case above, but is kept asserted even if it was
//        possible to roll-back in the repo to a direct non-noop parent commit.
//        (NoopChange is cleaned if the latter succeeds. 'Commit' contains single noOp commit - original
//        bisection result, while 'Commits[0]' keeps either non-noOp parent [true operational change]
//        culprit/fix or the end-point commit of unsuccessful "rollback" attempt)
//    - Bisected to a release commit
//  - if bisection is inconclusive, range of potential cause/fix commits in Commits
//    - report is nil in such case
//    - Commit is nil
//  - if the crash still happens on the oldest release/HEAD (for cause/fix bisection correspondingly)
//    - no commits in Commits
//    - the crash report on the oldest release/HEAD;
//    - Commit points to the oldest/latest commit where crash happens.
//  - Config contains kernel config used for bisection
type Result struct {
	Commits              []*vcs.Commit
	Report               *report.Report
	Commit               *vcs.Commit
	Config               []byte
	IsRelease            bool
	OrigBisectWasNoOpCmt bool
	NoopChange           bool
}

type fullBuildProcessingResult struct {
	bootable         bool
	rawResults       []error
	processedResults map[string]*testResult // by commit hash key
}

const buildFailedToken = "build failed"

type testResult struct {
	verdict    vcs.BisectResult
	com        *vcs.Commit
	rep        *report.Report
	kernelSign string
}

// Run does the bisection and returns either the Result
//  or, if the crash is not reproduced on the start commit, an error.
func Run(cfg *Config) (*Result, error) {
	if err := checkConfig(cfg); err != nil {
		return nil, err
	}
	cfg.Manager.Cover = false // it's not supported somewhere back in time
	repo, err := vcs.NewRepo(cfg.Manager.TargetOS, cfg.Manager.Type, cfg.Manager.KernelSrc)
	if err != nil {
		return nil, err
	}
	inst, err := instance.NewEnv(&cfg.Manager)
	if err != nil {
		return nil, err
	}
	if _, err = repo.CheckoutBranch(cfg.Kernel.Repo, cfg.Kernel.Branch); err != nil {
		return nil, err
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
		cfg:              cfg,
		repo:             repo,
		bisecter:         bisecter,
		minimizer:        minimizer,
		inst:             inst,
		startTime:        time.Now(),
		buildTestRsltMap: make(map[string]*fullBuildProcessingResult),
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
	env.log("instances tested: %v, total time: %v (build: %v, test: %v)",
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
	if res.OrigBisectWasNoOpCmt {
		env.log("bisection originally resulted in 'noOp change' first %v commit: #%v : '%v'",
			what, res.Commit.Hash, res.Commit.Title)
		if res.NoopChange {
			env.log("the 'noOp change' couldn't be reliably rolled back to (parent) true `operational"+
				" change` 'first %v' commit. Rolling back stumbled at : #%v : '%v'",
				what, com.Hash, com.Title)
		} else {
			env.log("the 'noOp change' was rolled back to (parent) true operational change"+
				" 'first %v' commit: #%v : '%v'", what, com.Hash, com.Title)
		}
	} else {
		env.log("first %v commit: %v %v", what, com.Hash, com.Title)
	}
	// Kept for the coming merge:
	// env.log("recipients (to): %q", com.Recipients.GetEmails(vcs.To))
	// env.log("recipients (cc): %q", com.Recipients.GetEmails(vcs.Cc))
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
	env.kernelConfig = cfg.Kernel.Config
	testRes, err := env.test()
	if err != nil {
		return nil, err
	} else if testRes.verdict != vcs.BisectBad {
		return nil, fmt.Errorf("the crash wasn't reproduced on the original commit")
	}

	if len(cfg.Kernel.BaselineConfig) != 0 {
		testRes1, err := env.testMinimizeConfig()
		if err != nil {
			return nil, err
		}
		if testRes1 != nil {
			testRes = testRes1
		}
	}
	// CONFIG stays firmly fixed after this line
	bad, good, rep1, results1, err := env.commitRange()
	if err != nil {
		return nil, err
	}
	if rep1 != nil {
		return &Result{Report: rep1, Commit: bad, Config: env.kernelConfig},
			nil // still not fixed/happens on the oldest release
	}
	if good == nil {
		// Special case: all previous releases are build broken.
		// It's unclear what's the best way to report this.
		// We return 2+ commits which means "inconclusive".
		return &Result{Commits: []*vcs.Commit{com, bad}, Config: env.kernelConfig}, nil
	}
	// It can be deemed to switch to usage of the introd-ed more detailed global
	// map (referred via env-t) completely. However, the mapping is different in these:
	//  here (results[] map): 'commit_hash' <-> 'parsed test result',
	//  in global - 'build_sign' -> 'raw test results' -> map('commit_hash' <-> 'parsed test result')
	// Thus, both are kept here currently as sort of 'bidirectional list/road'
	results := map[string]*testResult{cfg.Kernel.Commit: testRes}
	for _, res := range results1 {
		results[res.com.Hash] = res
	}
	pred := func() (vcs.BisectResult, error) {
		// We can't 100% trust the bisecter.Bisect(). Confirmed by inconclusive bisection test-cases.
		current, err := env.repo.HeadCommit()
		if err != nil {
			env.log("failed to check repo.HeadCommit() in pred for Bisect: %v."+
				" Skip tied actions until it get exited on this issue later.", err)
		} else {
			if locMapRslt, fnd := results[current.Hash]; fnd {
				env.log("bisector logic failure: attempted to check same commit '%v' (#%v) again."+
					" Return the verdict saved in the test results map from 1st try.",
					current.Title, current.Hash)
				return locMapRslt.verdict, nil
			}
		}
		testRes1, err := env.test()
		if err != nil {
			// Not registering the test failure as it can only refer to timeout currently.
			// So, might have sense trying next time.
			// (Note: "failed build", etc. is not a failure.)
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
		Config:  env.kernelConfig,
	}
	if len(commits) == 1 {
		com := commits[0]
		testRes := results[com.Hash]
		if testRes == nil {
			return nil, fmt.Errorf("no result for culprit commit")
		}
		res.Report = testRes.rep

		checkedCmt, err := env.checkAndHandleNoOpRslt(res, results, com)
		if err != nil {
			env.log("failed to handle noOp change: %v", err)
		}
		isRelease, err := env.bisecter.IsRelease(checkedCmt.Hash)
		if err != nil {
			env.log("failed to detect release: %v", err)
		}
		res.IsRelease = isRelease
	}
	// If multiple commits returned by bisector, so inconclusive results,
	//  no processing here, but - in the wrapping runImpl()
	return res, nil
}

func (env *env) checkAndHandleNoOpRslt(res *Result, results map[string]*testResult,
	com *vcs.Commit) (*vcs.Commit, error) {
	noopChange, err := env.detectNoopChange(results, com)
	if err != nil {
		env.log("failed to detect noOp change: %v", err)
		return com, err
	}
	if noopChange {
		// Try to rollback to closest (direct) non-noOp parent and then
		//  re-arrange final bisection reporting correspondingly
		res.OrigBisectWasNoOpCmt = true
		opChangeCmtCand := com
		for noopChange && err == nil {
			opChangeCmtCand, err = env.repo.SwitchCommit(opChangeCmtCand.Parents[0])
			if err == nil {
				noopChange, err = env.detectNoopChange(results, opChangeCmtCand)
			}
		}
		res.NoopChange = noopChange
		if err != nil {
			env.log("failed to rollback to non-noOp: %v", err)
			env.log("rollback from noOp commit %v (#%v) stumbled at commmit: '%v' (#%v)",
				com.Title, com.Hash, opChangeCmtCand.Title, opChangeCmtCand.Hash)
		} else {
			env.log("successfully rolled back from noOp commit '%v' (#%v) to non-noOp: '%v' (#%v)",
				com.Title, com.Hash, opChangeCmtCand.Title, opChangeCmtCand.Hash)
		}
		buildId := results[opChangeCmtCand.Hash].kernelSign
		res.Commit = com
		res.Commits[0] = opChangeCmtCand
		// Re-parse test results (obtained for original noOp commit)
		if prevBuildResults, fnd := env.buildTestRsltMap[buildId]; fnd {
			testResUpd := results[opChangeCmtCand.Hash]
			env.applyResultsProcessing(testResUpd, opChangeCmtCand, prevBuildResults.rawResults)
			res.Report = testResUpd.rep
		}
		com = opChangeCmtCand
	}
	return com, nil
}

func (env *env) detectNoopChange(results map[string]*testResult, com *vcs.Commit) (bool, error) {
	cmtTestRes := results[com.Hash]
	if cmtTestRes.kernelSign == "" || len(com.Parents) != 1 { // TODO: Handle multiple parents also?
		return false, nil
	}
	parent := com.Parents[0]
	parentRes := results[parent]
	if parentRes == nil {
		env.log("parent commit %v test results were not found in fast access map", parent)
		// We could not test the parent commit if it is not based on the previous release
		// (instead based on an older release, i.e. a very old non-rebased commit
		// merged into the current release).
		// TODO: we can use a differnet compiler for this old commit
		// since effectively it's in the older release, in that case we may not
		// detect noop change anyway.
		parentComm, err := env.repo.SwitchCommit(parent)
		if err != nil {
			return false, err
		}
		// Need a new build, unfortunately (no track of the 'parent commit' found in our registers)
		_, kernelSign, err := env.build()
		if err != nil {
			return false, err
		}
		// It has not been registered into local results[] map originally. Added now (with knlSign only).
		parentRes = &testResult{
			com:        parentComm,
			kernelSign: kernelSign,
		}
		results[parent] = parentRes // We need it at least for "rollback" from noOp change.
	}
	env.log("culprit signature: %v", cmtTestRes.kernelSign)
	env.log("parent  signature: %v", parentRes.kernelSign)
	return cmtTestRes.kernelSign == parentRes.kernelSign && cmtTestRes.kernelSign != buildFailedToken, nil
}

func (env *env) testMinimizeConfig() (*testResult, error) {
	cfg := env.cfg
	// Check if crash reproduces with baseline config.
	env.kernelConfig = cfg.Kernel.BaselineConfig
	testRes, err := env.test()
	if err != nil {
		env.log("testing baseline config failed: %v", err)
		env.kernelConfig = cfg.Kernel.Config
		return nil, err
	}
	if testRes.verdict == vcs.BisectBad {
		env.log("crash reproduces with baseline config")
		return testRes, nil
	}
	if testRes.verdict == vcs.BisectSkip {
		env.log("unable to test using baseline config, keep original config")
		env.kernelConfig = cfg.Kernel.Config
		return nil, nil
	}
	predMinimize := func(test []byte) (vcs.BisectResult, error) {
		env.kernelConfig = test
		testRes, err := env.test()
		if err != nil {
			return 0, err
		}
		return testRes.verdict, err
	}
	// Find minimal configuration based on baseline to reproduce the crash.
	env.kernelConfig, err = env.minimizer.Minimize(cfg.Kernel.Config,
		cfg.Kernel.BaselineConfig, cfg.Trace, predMinimize)
	if err != nil {
		env.log("minimizing config failed: %v", err)
		return nil, err
	}
	if bytes.Equal(env.kernelConfig, cfg.Kernel.Config) {
		return nil, nil
	}
	// Check that crash is really reproduced with generated config.
	testRes, err = env.test()
	if err != nil {
		return nil, fmt.Errorf("testing generated minimized config failed: %v", err)
	}
	if testRes.verdict != vcs.BisectBad {
		env.log("testing with generated minimized config doesn't reproduce the crash")
		env.kernelConfig = cfg.Kernel.Config
		return nil, nil
	}
	return testRes, nil
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

func (env *env) build() (*vcs.Commit, string, error) {
	current, err := env.repo.HeadCommit()
	if err != nil {
		return nil, "", err
	}

	bisectEnv, err := env.bisecter.EnvForCommit(env.cfg.BinDir, current.Hash, env.kernelConfig)
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
	if cfg.Timeout != 0 && time.Since(env.startTime) > cfg.Timeout {
		return nil, fmt.Errorf("bisection is taking too long (>%v), aborting", cfg.Timeout)
	}
	env.numTests++
	// No way to predict a build outcome for a commit (unless we have registered it) ->
	// It can also happen we try playing with the same commit twice. For config optimizers at least.
	// Whether we can 100% trust the "bisecter.Bisect" is checked in wrappers (in DB mode).
	current, kernelSign, err := env.build()
	res := &testResult{
		verdict:    vcs.BisectSkip,
		com:        current,
		kernelSign: kernelSign, // Note: build() returns empty kernelSign for build fails.
	}
	if err != nil {
		if verr, ok := err.(*osutil.VerboseError); ok {
			env.log("%v", verr.Title)
			env.saveDebugFile(current.Hash, 0, verr.Output)
		} else if verr, ok := err.(*build.KernelError); ok {
			env.log("%s", verr.Report)
			env.saveDebugFile(current.Hash, 0, verr.Output)
		} else {
			env.log("%v", err)
		}
		// Make it more clear (and robust against unexpected misinterpretation and logic messup bugs)
		res.kernelSign = buildFailedToken
		return res, nil
	}

	// Check: did we test this build already (and processed results)
	needRetest := true
	if prevBuildResults, found := env.buildTestRsltMap[kernelSign]; found {
		env.log("the build with signature '%v' was identified tested before."+
			" Checking whether some old results can apply..", kernelSign)
		if len(prevBuildResults.rawResults) == 0 {
			env.log("despite the build was registered as 'tested' before," +
				" there are no testing results found in the bisection-run registers. Re-testing then..")
		} else {
			// We have some raw test results for this build kept. Let's check do we have also
			//  anything reported about those also (that would be logically expected).
			needRereport := true
			if len(prevBuildResults.processedResults) == 0 {
				env.log("no raw test results processing reports found in the registers.",
					" Re-testing then completely..")
				if prevBuildResults.processedResults == nil {
					prevBuildResults.processedResults = make(map[string]*testResult)
				}
			} else {
				needRetest = false // No full re-test needed. Only (additional - for another commit) parsing results.
				if _, fndR := prevBuildResults.processedResults[current.Hash]; !fndR {
					env.log("no processing reports of raw test results found in the bisection-run registers"+
						" for the commit '%v' (hash: '%v') in question. Re-generating reports then..",
						current.Title, current.Hash)
				} else {
					needRereport = false
				}
			}
			if needRereport {
				env.applyResultsProcessing(res, current, prevBuildResults.rawResults)
				prevBuildResults.processedResults[current.Hash] = res // add processed info (reports)
				env.log("for binary (sign-re: '%v') tested fine before, results also parsed and"+
					" reg added fine for commit '%v' (hash: '%v')", kernelSign, current.Title, current.Hash)
				return res, nil
			}
		}
		if !needRetest {
			// Extract processed results data for this build & commit hash (we confirmed the latter is there)
			res = prevBuildResults.processedResults[current.Hash]
			env.log("for binary (sign-re: '%v') tested fine before, results for commit '%v' (hash: '%v')"+
				" are EXTRACTED as: ", kernelSign, current.Title, current.Hash)
			env.log("verdict: '%v', [com.Title: '%v', com.Hash: '%v'], kernelSign: '%v'",
				res.verdict, res.com.Title, res.com.Hash, res.kernelSign)
			return res, nil
		}
	}

	// This build has never been tested before. TEST it now (and process results also for current commit).
	testStart := time.Now()
	results, err := env.inst.Test(NumTests, cfg.Repro.Syz, cfg.Repro.Opts, cfg.Repro.C)
	env.testTime += time.Since(testStart)
	newBuildProcResult := &fullBuildProcessingResult{
		bootable:         false,
		rawResults:       results,
		processedResults: map[string]*testResult{current.Hash: res},
	}
	if err != nil {
		env.log("testing binary (sign-re: '%v') failed with err: '%v'."+
			" Thus, no testing results obtained/reg-ed.", kernelSign, err)
		env.buildTestRsltMap[kernelSign] = newBuildProcResult // save some incomplete full set of results
		return res, nil
	}

	env.applyResultsProcessing(res, current, results)

	// Keep the test results for this build & their parse outcome for this commit
	// (The main map is init-ed at runImpl(), but not the inner one)
	newBuildProcResult.bootable = true
	newBuildProcResult.processedResults[current.Hash] = res // update parsing result
	env.buildTestRsltMap[kernelSign] = newBuildProcResult
	env.log(" binary (sign-re: '%v') tested, results parsed and all that reg-ed fine"+
		" for commit '%v' (hash: '%v')", kernelSign, current.Title, current.Hash)

	return res, nil
}

func (env *env) applyResultsProcessing(res *testResult, current *vcs.Commit, results []error) {
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
