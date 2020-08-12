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
	// If the crash reproduces with the generated configuration, original configuation is
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
	/// [TOV] MapPtr to be assigned when starting bisect (test)run?
	buildTestRsltMap map[string]*fullBuildProcessingResult // by Knl build Signature (kernelSign in testResult)
}

const NumTests = 10 // number of tests we do per commit

// BisectResult describes bisection result:
//  - if bisection is conclusive, the single cause/fix commit in Commits
//    - for cause bisection, report is the crash on the cause commit
//    - for fix bisection report is nil
//    - Commit is nil
//    - NoopChange is set if the bisection result commit did not cause any change in the kernel binary
//      and this could not be fixed (bisection result it most likely wrong)   <-<- [TOV]-ed ->->
//      - BisectedToNoop is also set for the case above, but is kept asserted even if it was
//        possible to roll-back in the repo to a direct non-noop parent commit.
//        (NoopChange is cleaned if the latter succeeds. TODO: 'Commit' contain single noOp commit - original
//	      bisection result (needed?), while 'Commits' keeps either non-noOp parent [true operational change] culprit/fix
//        or the end-point commit of unseccessful "roll back" attempt)
//    - Bisected to a release commit
//  - if bisection is inconclusive, range of potential cause/fix commits in Commits
//    - report is nil in such case
//    - Commit is nil
//  - if the crash still happens on the oldest release/HEAD (for cause/fix bisection correspondingly)
//    - no commits in Commits
//    - the crash report on the oldest release/HEAD;
//    - Commit points to the oldest/latest commit where crash happens. // [TOV]: impl-ed in func (env *env) bisect() Ln:286..
//  - Config contains kernel config used for bisection
type BisectResult struct { // [TOV]: name changed from 'Result'
	Commits   []*vcs.Commit
	Report    *report.Report
	Commit    *vcs.Commit
	Config    []byte
	IsRelease bool
	// [TOV]: Reports orig noop fnd. Stays, even if fixed (with rollback) while the former ^ gets cleaned.
	OrigBisectWasNoOpCmt bool // [TOV]: Is it really needed? Currently in used as a token in runImpl final analysis&reporting
	// [TOV]: So having this TRUE, signals ERROR in real-life (but that was fine target for Vyukov according to UTs
	//        despite his note above ^). After change, still having it asserted means we weren't able to rollback from it
	//        to non-noop (culprit/fix) commit
	NoopChange bool
}

/// [TOV]: For buildHash-To-FullRsltsRec mapping. Commits with failed builds are registered at 0 entry.
type fullBuildProcessingResult struct {
	// The following is one of 3 different par-s that directly affect/define the build bin (KernSign).
	// (2 others: commit and compiler). But in currnt logic, after initial config minimizing (intermediate test
	// results of which aren't saved) the config *stays* unchanged throughout whole bisection procedure?
	// configHash       string
	bootable         bool // TODO: can we have any other issues preventing us from getting rawResults below?
	rawResults       []error
	processedResults map[string]*testResult // by commit hash key ()
	// Same build signature will also be for series of builds when rolling back through all the NoOp commits, so those
	// will stack in the mao above ^ with empty test result reports, right?
}

// [TOV]: This token should be used for marking failed kernel builds where no testing can be provided respectively in testResult
const buildFailedToken = "build failed"

type testResult struct { ///    [TOV]: TODO: Rename into testResultReport?
	verdict    vcs.BisectResult
	com        *vcs.Commit ///  [TOV]: What's the policy about NoOp commits here? Any commit allowed, right?
	rep        *report.Report
	kernelSign string ///       [TOV]: Can this key be used for efficient search (as in 'map')? Originally used in map:commit<->testRslt
	// noopChange bool ///      [TOV]: Can possibly be useful here (e.g. for leaving traces during roll back), since Ptrs to corresponding commits are allowed ^
}

// Run does the bisection and returns either the BisectResult,
// or, if the crash is not reproduced on the start commit, an error.
func Run(cfg *Config) (*BisectResult, error) {
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

func runImpl(cfg *Config, repo vcs.Repo, inst instance.Env) (*BisectResult, error) {
	bisecter, ok := repo.(vcs.Bisecter)
	if !ok {
		return nil, fmt.Errorf("bisection is not implemented for %v", cfg.Manager.TargetOS)
	}
	minimizer, ok := repo.(vcs.ConfigMinimizer)
	if !ok && len(cfg.Kernel.BaselineConfig) != 0 {
		return nil, fmt.Errorf("config minimization is not implemented for %v", cfg.Manager.TargetOS)
	}

	env := &env{
		cfg:       cfg,
		repo:      repo,
		bisecter:  bisecter,
		minimizer: minimizer,
		inst:      inst,
		startTime: time.Now(),
		// [TOV]: Added: Map 'buildId' -> 'allRelevantResults' ->  commit (noOps are also there) based
		//        parsing|reporting that might go differently (wrognly). We need rolling back to true operational
		//        change non-noOp (parent) commit and go for reprocessing with overwriting the final bisection results.
		buildTestRsltMap: make(map[string]*fullBuildProcessingResult),
	}
	/*// __DB__
	// [TOV]: TODO: This way seems like it looks a bit too heavy for usage - results[] map is more convenient
	//        Add [DB-mode] entry commits with build fails (to save time on checks later)
	env.buildTestRsltMap["0"] = &fullBuildProcessingResult{
		bootable:         false,
		processedResults: make(map[string]*testResult),
	}
	*/ // ^^DB^^
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
	env.log("revisions tested: %v, total time: %v (build: %v, test: %v)", // [TOV]: FIXME: Why 'revisions'? Meant 'instances'!
		env.numTests, time.Since(start), env.buildTime, env.testTime)
	if err != nil {
		env.log("error: %v", err)
		return nil, err
	}
	if len(res.Commits) == 0 { // [TOV]: We shouldn't make this false for noOp case resolution\state, right?
		// [TOV]: "the crash still happens" (out of search focus area)
		if cfg.Fix {
			env.log("the crash still happens on HEAD")
		} else {
			env.log("the crash already happened on the oldest tested release")
		}
		// [TOV]: FIXME: Where it's checked the res.Commit really exists?
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
	// [TOV]: BisectResult is 'conclusive'
	com := res.Commits[0]
	// [TOV]: Added: Check noOp bisection result and roll-back status
	if res.OrigBisectWasNoOpCmt /*len(res.Commits) == 1 & ..*/ {
		env.log("bisection resulted in 'noOp change' first %v commit: #%v : '%v'",
			what, res.Commits[0].Hash, res.Commits[0].Title)
		// [TOV]: We add the 'noop rollback' result into main res.Commits[0]. (TODO: Even if incomplete)
		//        The sort of additional commit report -> res.Commit is assigned with orig found noOp commit.
		if res.NoopChange {
			env.log("the 'noOp change' couldn't be reliably rolled back to (parent) true `operational"+
				" change` 'first %v' commit. Rolling back stumbled at : #%v : '%v'",
				what, com.Hash, com.Title) // TODO: any err on sumbling reason?
		} else {
			env.log("the 'noOp change' was rolled back to (parent) true operational change"+
				" 'first %v' commit: #%v : '%v'", what, com.Hash, com.Title)
			env.log("cc: %q", res.Commit.CC)
		}
	} else {
		// [TOV]: Check: What was the original case here (len(res.Commits) == 1 && res.Commit == nil)?
		//        Based on 'type BisectResult struct', it's _primary expectation_ and Commit should be == nil.
		//        We had *single* commit in Commits, but do not check what we have in Commit.
		//        we just say "first bad/good" based that *single* commit[0] in Commits.
		env.log("first %v commit: %v %v", what, com.Hash, com.Title)
		env.log("cc: %q", com.CC)
	}
	if res.Report != nil {
		env.log("crash: %v\n%s", res.Report.Title, res.Report.Report)
	}
	return res, nil
}

func (env *env) bisect() (*BisectResult, error) {
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
	/// [TOV]: The 'build' phase is also included into 'test()' as used in |pred(icate?)| below
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
	// [TOV]: Can CONFIG ever change after this during the bisection ?!!!  If no,
	//        *CONFIG is firm* after this line
	bad, good, rep1, results1, err := env.commitRange()
	if err != nil {
		return nil, err
	}
	if rep1 != nil {
		return &BisectResult{Report: rep1, Commit: bad, Config: env.kernelConfig},
			nil // still not fixed/happens on the oldest release
	}
	if good == nil {
		// Special case: all previous releases are build broken.
		// It's unclear what's the best way to report this.
		// We return 2 commits which means "inconclusive".
		return &BisectResult{Commits: []*vcs.Commit{com, bad}, Config: env.kernelConfig}, nil
	}
	// [TOV]: This map is too scarce. Not very diverse (to cover all cases) either:
	//              commits can be tested on builds obtained on (dif configs [in general, but not in
	//              current impl-n, though!] and) diff compilers at least.
	//        TODO: At larger scale, it can be deemed to switch to usage of the introd-ed more detailed global
	//              map ref-ed via env, right?  However, the mapping there is different:
	//                here is 'commit_hash' <-> 'parsed test result',
	//                in global - 'build_sign' <-> 'raw test results' -> map('commit_hash' <-> 'parsed test result')
	//              So, both are kept here currently as sort of 'bidirectional list' ;)
	// [TOV] 1st entry - minimized (if needed) config testing result
	results := map[string]*testResult{cfg.Kernel.Commit: testRes}
	for _, res := range results1 {
		// [TOV]: Map all test results returned by env.commitRange(). (TODO: Add inner 'knl config' mapping?)
		results[res.com.Hash] = res
	}
	pred := func() (vcs.BisectResult, error) {
		/// __DB__
		// __[TOV]__ : __Do we 100% trust the bisecter.Bisect()?__
		//        TODO: M.b. check 1st: didn't we reg this commit as tested already? ;)
		//              Pass results[] into test() or access commit here like added below?
		current, err := env.repo.HeadCommit() // [TOV]: Does wrapping bisector play with HeadCommit()?
		if err != nil {
			env.log("[TOV] DB: failed to check repo.HeadCommit() in pred for Bisect: %v."+
				" Skip tied actions until it get exited on this issue later.", err)
		} else {
			if locMapRslt, fnd := results[current.Hash]; fnd {
				env.log("[TOV] DB: Bisector logic failure: attempted to check same commit '%v' (#%v) again."+
					"Returned verdict saved in the test result from 1st try.", current.Title, current.Hash)
				return locMapRslt.verdict, nil
			}
			/*// __DB__ __DB__
			// This is extra check -- too heavy logic compared to results[current.Hash] ^
			for _, buildRsltN := range env.buildTestRsltMap {
				if bldTstRslt, fnd := buildRsltN.processedResults[current.Hash]; fnd {
					env.log("[TOV] DB: Bisector logic failure: attempted to check same commit '%v' (#%v) again."+
						" Data obtained from global map (so, not in local). Returned test results saved from 1st try.",
						current.Title, current.Hash)
					return bldTstRslt.verdict, nil
				}
			}
			*/ // ^^DB^^ ^^DB^^
		}
		// ^^[TOV]^^ : ^^Do we 100% trust the bisecter.Bisect()?^^
		/// ^^DB^^
		testRes1, err := env.test()
		if err != nil {
			// [TOV] TODO: Not registering the test failure because the only such possible seems to be
			//             only timeout?
			//       Do we hope it will work next try? Any other cases?
			//       (Note: "failed build", etc. is not a failure.)
			return 0, err
		}
		if cfg.Fix {
			if testRes1.verdict == vcs.BisectBad {
				testRes1.verdict = vcs.BisectGood
			} else if testRes1.verdict == vcs.BisectGood {
				testRes1.verdict = vcs.BisectBad
			}
		}
		// [TOV] TODO: In general, commits can be tested on dif configs at least, but under the logic here,
		//             config is not changed (either baseline or min) after the init phase above^.
		//       So, a commit can have only one build(bin)|results, while a build - several commits|results, right?
		//       Note: 'failed builds' are aslo saved here with specific token for knlSign and BisectSkip verdict
		results[testRes1.com.Hash] = testRes1
		return testRes1.verdict, err
	}
	commits, err := env.bisecter.Bisect(bad.Hash, good.Hash, cfg.Trace, pred)
	if err != nil {
		return nil, err
	}
	res := &BisectResult{
		Commits: commits,
		Config:  env.kernelConfig,
	}
	if len(commits) == 1 {
		// [TOV]: Single commit reported ^ is a good sign of non-failed bisection
		com := commits[0]
		testRes := results[com.Hash]
		if testRes == nil {
			return nil, fmt.Errorf("no result for culprit commit")
		}
		res.Report = testRes.rep

		noopChange, err := env.detectNoopChange(results, com)
		if err != nil {
			env.log("failed to detect noOp change: %v", err)
		}
		if noopChange {
			// [TOV]: Added: Roll-back to closest (direct) non-noop parent and
			//        arrange final bisection reporting correspondignly
			res.OrigBisectWasNoOpCmt = true // noopChange
			opChangeCmtCand := com
			for noopChange && err == nil {
				// TODO: Git tree traversal instead of going via Parents[0]?
				opChangeCmtCand, err := env.repo.SwitchCommit(opChangeCmtCand.Parents[0])
				if err == nil {
					noopChange, err = env.detectNoopChange(results, opChangeCmtCand)
				}
			}
			res.NoopChange = noopChange // [TOV]: This should be fine enough?
			if err != nil {
				env.log("failed to rollback to non-noOp: %v", err)
				// [TOV]: Save as incomplete rollback?
				env.log("rollback from noOp commit %v (#%v) stumbled at commmit: '%v' (#%v)",
					com.Title, com.Hash, opChangeCmtCand.Title, opChangeCmtCand.Hash)
			} else {
				// [TOV]: Successful rollback? \o/?
				env.log("successfully rolled back from noOp commit '%v' (#%v) to non-noOp: '%v' (#%v)",
					com.Title, com.Hash, opChangeCmtCand.Title, opChangeCmtCand.Hash)
			}
			buildId := results[opChangeCmtCand.Hash].kernelSign
			//__DB__
			// Check theoretically possible tragic failure that could popup during noOp rollback
			if buildId != testRes.kernelSign {
				env.log("some strange failure in rollback to non-noOp: knlSign '%v' while"+
					" noOp knlSign: '%v'. Refrain from reporting noOp rollback result then.",
					buildId, testRes.kernelSign)
			} else {
				//^^DB^^
				// Output bisect reported commits
				res.Commit = com // Put orig found noOp here
				// The noOp fix (or even incomplete noOp fix) is made final resulting culprit commit
				// (The knlSign at least is still expected to be the same as for initial noOp found)
				res.Commits[0] = opChangeCmtCand
				// Re-parse test results (prepared for original noOp commit) now based on another commit (same as in test())
				if prevBuildResults, fnd := env.buildTestRsltMap[buildId]; fnd {
					testResUpd := results[opChangeCmtCand.Hash] // Only knlSign was put there when handled with detectNoopChange()
					testResUpd.verdict = testRes.verdict        // let's assign initially the verdict from original noOp cmt
					env.applyResultsProcessing(testResUpd, opChangeCmtCand, prevBuildResults.rawResults)
					res.Report = testResUpd.rep
				} else {
					// Impossible failure -> The build (where all the noOp-s and their non-noOp root should be)
					// accidentally now NOT FOUND :O.
					env.log("Impossible failure -> The build ([knlSign-re: %v] where all the noOp-s and their non-noOp"+
						" root (supposedly commmit: '%v' (#%v)) should be was not found",
						buildId, opChangeCmtCand.Title, opChangeCmtCand.Hash)
				}
				// Switch the current comment to be the noOp fix now (to complete filling uip other report feilds)
				com = opChangeCmtCand
			}
		}

		isRelease, err := env.bisecter.IsRelease(com.Hash)
		if err != nil {
			env.log("failed to detect release: %v", err)
		}
		res.IsRelease = isRelease
	}
	// [TOV]: NOTE: No "grooming" ^ if multiple commits returned by bisector. No logs here about that,
	//              but this to be noted in the wrapping runImpl() final bisection results analysis.
	return res, nil
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

func (env *env) detectNoopChange(results map[string]*testResult, com *vcs.Commit) (bool, error) {
	comTestRes := results[com.Hash]                           // [TOV]: We should have just checked that and put into local reg
	if comTestRes.kernelSign == "" || len(com.Parents) != 1 { // [TOV]: Commit with multiple parents can't be noOp? Really?
		return false, nil
	}
	/// [TOV]: There is no guarantee that only one noOp commit is possible and 'com.Parents[0]' is the
	///        correct reliable OpCh 'parent' choice and not just another noOp. (Understading of the fact
	///        is also reflected in current (U)test-cases state.) Although, it's enough for
	///        identifying the fact of having same binary produced for 2 neighbor commits.
	parent := com.Parents[0] // [TOV]: TODO: Handle multiple parents?
	parentRes := results[parent]
	if parentRes == nil {
		env.log("parent commit %v test results were not found in fast access map", parent)
		// We could not test the parent commit if it is not based on the previous release
		// (instead based on an older release, i.e. a very old non-rebased commit
		// merged into the current release).
		// TODO: we can use a differnet compiler for this old commit
		// since effectively it's in the older release, in that case we may not
		// detect noop change anyway.
		// [TOV]: We do not need testing binaries, we just need getting their hashes. For this reason,
		//        there is no point to change compiler, even opposite - we need ensuring the same compiler
		//        is used disregarding to release.  For close releases it might work - older releases could
		//        presumably build fine with newer compilers.
		parentComm, err := env.repo.SwitchCommit(parent)
		if err != nil {
			return false, err
		}

		// [TOV]: If the 'parent' commit results are not found in the local map, does it have sense to check
		//        in the global (env)?  Could this have happened under current conf treatment policy?
		//        E.g., as results into local map are saved only those are returned by env.test() without err-s.
		//        TODO:  Check the cases of *untestable (e.g., no boot) bin-s* in env.test()
		//        (If that's a noop case, it should be under same KernelSign.  If not, search for the
		//		  commit hash throughout whole global (env) map)
		// [TOV]: Add the register checking logic clause to avoid unnecessary double building
		//        (Due to dumb GoLang that doesn't allow (with all its "Short" one-liners) normal optimized L->R logic pred
		// 	      evaluation, those nice "helper" booleans have to be added :)
		// [TOV]:
		if bldRslt, fnd := env.buildTestRsltMap[comTestRes.kernelSign]; fnd {
			if _ /*bldTstRslt*/, fnd2 := bldRslt.processedResults[parentComm.Hash]; fnd2 {
				// This is *very improbable to get here*: the noOp cannot be something that is untestable,
				// so this analysis cannot start.  On the other hand, if it was testable, the results for
				// this 'parent' commit should be in the local map, so we couldn't have reached to here.
				// If we registered this build tested (no matter was there any failure) also with the
				// 'parent' commit hash, instead of one more (same) re-build, just report the noOp case.
				env.log("parent commit build signature was found registered the same as for"+
					" current (culprit) commit: %v. So, the found culprit commit is a noOp change one.",
					comTestRes.kernelSign)
				return true, nil
			}
		}
		// [TOV]: There is no build binary registered "the same" for the 'parent' as for the cuprit candidate
		//        checked.  But if we find another build binary registered with the parent commit (the config
		//        is unchanged), we'll save time from skipping build step (required otherwise in order to
		//        provide some conclusion).  Note also: we are looking for a build that most
		//        probably we failed to test before (as mentioned above).
		for _, buildRsltN := range env.buildTestRsltMap {
			if parentBldTstRslt, fnd := buildRsltN.processedResults[parentComm.Hash]; fnd {
				// If here (so the clause above proved to be false), this means -->
				env.log("parent commit build signature was found registered but different (%v) compared"+
					" to current (culprit) commit: %v. So, the found culprit commit is not a noOp change.",
					parentBldTstRslt.kernelSign, comTestRes.kernelSign)
				// 'Failed build' is also sort of different knlSign for 'parent', so the 'com' is not noOp.
				return false, nil
			}
		}
		// Need a new build, unfortunately (no track of the 'parent commit' found in our registers)
		_, kernelSign, err := env.build()
		if err != nil {
			/// __DB__
			// [TOV]: TODO: In general it would be good to have the corresponding entry (below) at least
			//        in commitHash->tstRslt local map, right?
			//        But can we ever make use of it?
			//        What's the usecase for this: even noOp rollback should break right after return from here!
			// [TOV]: Register *failed build* for the 'parent commit' same way as in test() (no fear to overwrite)
			failedBuildTstRslt := &testResult{
				verdict:    vcs.BisectSkip,
				com:        parentComm,
				kernelSign: buildFailedToken,
			}
			results[parentComm.Hash] = failedBuildTstRslt
			/*// __DB__ __DB__
			// [TOV]: TODO: This way seems like it looks a bit too heavy
			//        Add [DB-mode] entry commits with build fails (to save time on checks later)
			env.buildTestRsltMap["0"].processedResults[parentComm.Hash] = failedBuildTstRslt
			*/ // ^^DB^^ ^^DB^^
			/// ^^DB^^
			return false, err
		}
		// [TOV]: else : IN GENERAL, the commit could have been tested with dif configs (in addition to
		//        dif compilers as mentioned above)!  But in current logic, the config shouldn't change after init!

		/// [TOV]: It has not been registered into local map originally. Added now (with just knlSign).
		///	       TODO: In rollback steps: Would we have ref-s to test results from this build, we could
		///              have reported those correctly (parsed based on the newly relevant commit ;)
		parentRes = &testResult{
			com:        parentComm,
			kernelSign: kernelSign,
		}
		// [TOV]: We need saving at least build hash (knlSign-re), at least for "rollback"?
		results[parent] = parentRes
		// [TOV]: TODO: Do we need it in the global (env) map? (Just for reliability and DB as local should be enough)
		// ..
	}
	env.log("culprit signature: %v", comTestRes.kernelSign)
	env.log("parent  signature: %v", parentRes.kernelSign)
	// [TOV]: TODO: Added the second (logical condition) part for the case when detectNoopChange()
	//         is called for such bad noOp, it hasn't even been tested as knlBuild failed for this commit.
	//         Can this ever happen? (rollback?)
	//         Basically, at least 1 of 2 commits failing builds can be noOp, we just cannot discriminate that.
	return comTestRes.kernelSign == parentRes.kernelSign && comTestRes.kernelSign != buildFailedToken, nil
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

// [TOV]: TODO: Pass par to: Stick to ref commit compiler
func (env *env) build() (*vcs.Commit, string, error) {
	current, err := env.repo.HeadCommit() // [TOV]: Does wrapping bisector play with HeadCommit()?
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
	/// [TOV]: No way to predict a build outcome for a commit (unless we have registered it) ->
	//         It can also happen we try playing with the same commit twice. For config optimizers at least.
	//         Whether we can 100% trust the Bisecter is checked in wrappers (in DB mode).
	current, kernelSign, err := env.build()
	res := &testResult{
		verdict:    vcs.BisectSkip,
		com:        current,
		kernelSign: kernelSign, // [TOV]: build() returns empty kernelSign for build fails
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
		// [TOV]: IMHO: It seems it will looks more clear (and robust against unexpected misinterpretation and
		//        logic messup bugs) to make a CLEAR marker of sort of const("build failure")
		res.kernelSign = buildFailedToken
		/*// __DB__
		// [TOV]: TODO: This way seems like it looks a bit too heavy compared to resultsp[] map
		// 	      Save it among the failed builds
		//       (TODO: Do we need the same in the local (commitHash->tstRslt) map? )
		env.buildTestRsltMap["0"].processedResults[current.Hash] = res
		*/ // ^^DB^^
		// [TOV]: Note: 'failed build' is not an issue!
		return res, nil
	}

	///  [TOV]:  __Check: did we test this build already (and processed results)?__
	//           (Such posibility exists for reverts, noOp change commits [,etc.?])
	needRetest := true
	var resE *testResult   // = nil //DB
	var rawResults []error //DB
	if prevBuildResults, fnd := env.buildTestRsltMap[kernelSign]; fnd {
		env.log("[TOV]: the build with signature '%v' was identified tested before. Checking whether some old results apply..",
			kernelSign)
		if len(prevBuildResults.rawResults) == 0 {
			env.log("[TOV]: despite the build ^ was registered as 'tested' before," +
				" there are no testing results found in the bisection-run registers. Re-testing then..")
		} else {
			// We have some raw test results for this build kept. Let's check do we have also
			// anything reported about those also (that would be logically expected).
			needRereport := true
			if len(prevBuildResults.processedResults) == 0 {
				env.log("[TOV]: no raw test results processing reports found in the registers.",
					" Re-testing then completely..")
				if prevBuildResults.processedResults == nil {
					// TODO: It would be some strange case, if map would be found created with 0 items - expected no map created
					prevBuildResults.processedResults = make(map[string]*testResult) // create map (by commit hash string key)
				}
			} else {
				needRetest = false // No full re-test needed. Only (additional - for another commit) parsinig results.
				if _, fndR := prevBuildResults.processedResults[current.Hash]; !fndR {
					env.log("[TOV]: no processing reports of raw test results found in the bisection-run registers"+
						" for the commit '%v' (hash: '%v') in question. Re-generating reports then..",
						current.Title, current.Hash)
					// TODO: We can get the same binary for NoOp comments also and now we have a clue
					//       another differnt commit was also used for reporting test results of this build.
					// What logic should be here (to cope with this the best):
					//  - roll-back down (with builds) to OpCh commit and report with it?
					//    <| Impl-ed now |> with modified detectNoopChange() as main engine due to the fact that
					//    all noop (U)tests were made (as of 1Aug20) inconsistent presumably from desire to test
					//    noop cases handling - noop commits withing "same binary" spans were marked as generating
					//    different test results for same binaries (with 1 probability for all Vms) which is IMPOSSIBLE!
					//    Note: currently we have a clue in the global map that there are 2 or more commits which
					//    are tied to the same build binaries, but no clue what is the mutual relations between those commits
					//    (which one is (direct)'parent'/'child'? is any of those a non-noOp one? etc.?)
					//  - Or just make new report and add it to an inner map (CommHash-testResult) without
					//    checking any relations between the commits resulting in the same build binaries
					//    (easiest and consuming no additional computation time)
				} else {
					needRereport = false
				}
			}
			if needRereport {
				rawResults = prevBuildResults.rawResults // DB
				env.applyResultsProcessing(res, current, prevBuildResults.rawResults)
				prevBuildResults.processedResults[current.Hash] = res // add processed info (reports)
				env.log("[TOV]: DB: for binary (sign-re: '%v') tested fine before, results also parsed and"+
					" reg added fine for commit '%v' (hash: '%v')", kernelSign, current.Title, current.Hash)
			}
		}
		if !needRetest {
			// Extract processed results data for this build & commit hash (we confirmed the latter is there)
			resE = prevBuildResults.processedResults[current.Hash]
			env.log("[TOV]: DB: for binary (sign-re: '%v') tested fine before, results for commit '%v' (hash: '%v')"+
				" are EXTRACTED as: ", kernelSign, current.Title, current.Hash)
			env.log("[TOV]: DB: verdict: '%v', [com.Title: '%v', com.Hash: '%v'], kernelSign: '%v'",
				resE.verdict, resE.com.Title, resE.com.Hash, resE.kernelSign)
			// return resE, nil /// TODO: Uncomment when DB is removed/disabled
		}
	}
	///  [TOV]:  ^^Check: did we test this build already (and processed results)?^^

	/// ORG
	// This build has never been tested before. TEST it now (and process results also for current commit).
	testStart := time.Now()
	results, err := env.inst.Test(NumTests, cfg.Repro.Syz, cfg.Repro.Opts, cfg.Repro.C)
	env.testTime += time.Since(testStart)
	if err != nil {
		env.log("testing binary (sign-re: '%v') failed with err: '%v'. Thus, no testing results obtained/reg-ed.", kernelSign, err)
		return res, nil /// [TOV]: Any point to save failures?
	}

	// _DB_
	rslt := &testResult{
		verdict:    vcs.BisectSkip,
		com:        current,
		kernelSign: kernelSign,
	}
	// ^DB^

	env.applyResultsProcessing(rslt, current, results)

	//////// /// __DB__
	if !needRetest {
		env.log("[TOV]: DB: !Results compare possibility!")
		// env.log("[TOV]: DB: for binary (sign-re: '%v') tested fine before, results for commit '%v' (hash: '%v')"+
		// 	"were supposed to be EXTRACTED as: ", kernelSign, current.Title, current.Hash)
		// env.log("[TOV]: DB: verdict: '%v', [com.Title: '%v', com.Hash: '%v'], kernelSign: '%v'",
		// 	resE.verdict, resE.com.Title, resE.com.Hash, resE.kernelSign)
		env.log("[TOV]: DB: RECALCULATED from scratch:")
		env.log("[TOV]: DB: verdict: '%v', [com.Title: '%v', com.Hash: '%v'], kernelSign: '%v'",
			rslt.verdict, rslt.com.Title, rslt.com.Hash, rslt.kernelSign)
		if rslt.verdict != resE.verdict {
			env.log("[TOV]: DB: !!! VERDICTS ^ MISMATCH !!!")
			env.log("[TOV]: DB: ![Initial raw results CMP]!")
			env.log("[TOV]: DB: ! --<Saved raw results>-- !")
			for i, r := range rawResults {
				env.log("[TOV]: DB: -<result #%v: '%v'>-", i, r)
			}
			env.log("[TOV]: DB: ! -=| New raw results |=- !")
			for i, r := range results {
				env.log("[TOV]: DB: -=result #%v: '%v'=-", i, r)
			}
		}
		return resE, nil
	} else { /// ^^DB^^

		/// [TOV]:  __Keep the test results for this build & their parse outcome for this commit__
		// The main map is init-ed at runImpl(), but not the inner one
		env.buildTestRsltMap[kernelSign] = &fullBuildProcessingResult{
			rawResults:       results,
			processedResults: map[string]*testResult{current.Hash: rslt},
		}
		env.log("[TOV]: DB: binary (sign-re: '%v') tested, results parsed and all that reg-ed fine"+
			" for commit '%v' (hash: '%v')", kernelSign, current.Title, current.Hash)
		/// [TOV]:  ^^Keep the test results for this build & their parse outcome for this commit^^

		return rslt, nil
	}
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
