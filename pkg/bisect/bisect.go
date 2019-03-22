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
	head      *vcs.Commit
	inst      *instance.Env
	numTests  int
	buildTime time.Duration
	testTime  time.Duration
}

// Run does the bisection and returns:
//  - if bisection is conclusive, the single cause/fix commit
//    - for cause bisection report is the crash on the cause commit
//    - for fix bisection report is nil
//  - if bisection is inconclusive, range of potential cause/fix commits
//    - report is nil in such case
//  - if the crash still happens on the oldest release/HEAD (for cause/fix bisection correspondingly),
//    no commits and the crash report on the oldest release/HEAD
//  - if the crash is not reproduced on the start commit, an error
func Run(cfg *Config) ([]*vcs.Commit, *report.Report, error) {
	if err := checkConfig(cfg); err != nil {
		return nil, nil, err
	}
	cfg.Manager.Cover = false // it's not supported somewhere back in time
	repo, err := vcs.NewRepo(cfg.Manager.TargetOS, cfg.Manager.Type, cfg.Manager.KernelSrc)
	if err != nil {
		return nil, nil, err
	}
	bisecter, ok := repo.(vcs.Bisecter)
	if !ok {
		return nil, nil, fmt.Errorf("bisection is not implemented for %v", cfg.Manager.TargetOS)
	}
	env := &env{
		cfg:      cfg,
		repo:     repo,
		bisecter: bisecter,
	}
	if cfg.Fix {
		env.log("bisecting fixing commit since %v", cfg.Kernel.Commit)
	} else {
		env.log("bisecting cause commit starting from %v", cfg.Kernel.Commit)
	}
	start := time.Now()
	commits, rep, err := env.bisect()
	env.log("revisions tested: %v, total time: %v (build: %v, test: %v)",
		env.numTests, time.Since(start), env.buildTime, env.testTime)
	if err != nil {
		env.log("error: %v", err)
		return nil, nil, err
	}
	if len(commits) == 0 {
		if cfg.Fix {
			env.log("the crash still happens on HEAD")
		} else {
			env.log("the crash already happened on the oldest tested release")
		}
		env.log("crash: %v\n%s", rep.Title, rep.Report)
		return nil, rep, nil
	}
	what := "bad"
	if cfg.Fix {
		what = "good"
	}
	if len(commits) > 1 {
		env.log("bisection is inconclusive, the first %v commit could be any of:", what)
		for _, com := range commits {
			env.log("%v", com.Hash)
		}
		return commits, nil, nil
	}
	com := commits[0]
	env.log("first %v commit: %v %v", what, com.Hash, com.Title)
	env.log("cc: %q", com.CC)
	if rep != nil {
		env.log("crash: %v\n%s", rep.Title, rep.Report)
	}
	return commits, rep, nil
}

func (env *env) bisect() ([]*vcs.Commit, *report.Report, error) {
	cfg := env.cfg
	var err error
	if env.inst, err = instance.NewEnv(&cfg.Manager); err != nil {
		return nil, nil, err
	}
	if env.head, err = env.repo.CheckoutBranch(cfg.Kernel.Repo, cfg.Kernel.Branch); err != nil {
		return nil, nil, err
	}
	if err := build.Clean(cfg.Manager.TargetOS, cfg.Manager.TargetVMArch,
		cfg.Manager.Type, cfg.Manager.KernelSrc); err != nil {
		return nil, nil, fmt.Errorf("kernel clean failed: %v", err)
	}
	env.log("building syzkaller on %v", cfg.Syzkaller.Commit)
	if err := env.inst.BuildSyzkaller(cfg.Syzkaller.Repo, cfg.Syzkaller.Commit); err != nil {
		return nil, nil, err
	}
	if _, err := env.repo.CheckoutCommit(cfg.Kernel.Repo, cfg.Kernel.Commit); err != nil {
		return nil, nil, err
	}
	res, _, rep0, err := env.test()
	if err != nil {
		return nil, nil, err
	} else if res != vcs.BisectBad {
		return nil, nil, fmt.Errorf("the crash wasn't reproduced on the original commit")
	}
	bad, good, rep1, err := env.commitRange()
	if err != nil {
		return nil, nil, err
	}
	if good == "" {
		return nil, rep1, nil // still not fixed/happens on the oldest release
	}
	reports := make(map[string]*report.Report)
	reports[cfg.Kernel.Commit] = rep0
	commits, err := env.bisecter.Bisect(bad, good, cfg.Trace, func() (vcs.BisectResult, error) {
		res, com, rep, err := env.test()
		reports[com.Hash] = rep
		if cfg.Fix {
			if res == vcs.BisectBad {
				res = vcs.BisectGood
			} else if res == vcs.BisectGood {
				res = vcs.BisectBad
			}
		}
		return res, err
	})
	var rep *report.Report
	if len(commits) == 1 {
		rep = reports[commits[0].Hash]
	}
	return commits, rep, err
}

func (env *env) commitRange() (string, string, *report.Report, error) {
	if env.cfg.Fix {
		return env.commitRangeForFix()
	}
	return env.commitRangeForBug()
}

func (env *env) commitRangeForFix() (string, string, *report.Report, error) {
	env.log("testing current HEAD %v", env.head.Hash)
	if _, err := env.repo.SwitchCommit(env.head.Hash); err != nil {
		return "", "", nil, err
	}
	res, _, rep, err := env.test()
	if err != nil {
		return "", "", nil, err
	}
	if res != vcs.BisectGood {
		return "", "", rep, nil
	}
	return env.head.Hash, env.cfg.Kernel.Commit, nil, nil
}

func (env *env) commitRangeForBug() (string, string, *report.Report, error) {
	cfg := env.cfg
	tags, err := env.bisecter.PreviousReleaseTags(cfg.Kernel.Commit)
	if err != nil {
		return "", "", nil, err
	}
	if len(tags) == 0 {
		return "", "", nil, fmt.Errorf("no release tags before this commit")
	}
	lastBad := cfg.Kernel.Commit
	var lastRep *report.Report
	for _, tag := range tags {
		env.log("testing release %v", tag)
		if _, err := env.repo.SwitchCommit(tag); err != nil {
			return "", "", nil, err
		}
		res, _, rep, err := env.test()
		if err != nil {
			return "", "", nil, err
		}
		if res == vcs.BisectGood {
			return lastBad, tag, nil, nil
		}
		if res == vcs.BisectBad {
			lastBad = tag
			lastRep = rep
		}
	}
	return "", "", lastRep, nil
}

func (env *env) test() (vcs.BisectResult, *vcs.Commit, *report.Report, error) {
	cfg := env.cfg
	env.numTests++
	current, err := env.repo.HeadCommit()
	if err != nil {
		return 0, nil, nil, err
	}
	bisectEnv, err := env.bisecter.EnvForCommit(current.Hash, cfg.Kernel.Config)
	if err != nil {
		return 0, nil, nil, err
	}
	compiler := filepath.Join(cfg.BinDir, bisectEnv.Compiler, "bin", "gcc")
	compilerID, err := build.CompilerIdentity(compiler)
	if err != nil {
		return 0, nil, nil, err
	}
	env.log("testing commit %v with %v", current.Hash, compilerID)
	buildStart := time.Now()
	if err := build.Clean(cfg.Manager.TargetOS, cfg.Manager.TargetVMArch,
		cfg.Manager.Type, cfg.Manager.KernelSrc); err != nil {
		return 0, nil, nil, fmt.Errorf("kernel clean failed: %v", err)
	}
	err = env.inst.BuildKernel(compiler, cfg.Kernel.Userspace,
		cfg.Kernel.Cmdline, cfg.Kernel.Sysctl, bisectEnv.KernelConfig)
	env.buildTime += time.Since(buildStart)
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
		return vcs.BisectSkip, current, nil, nil
	}
	testStart := time.Now()
	const numTests = 10
	results, err := env.inst.Test(numTests, cfg.Repro.Syz, cfg.Repro.Opts, cfg.Repro.C)
	env.testTime += time.Since(testStart)
	if err != nil {
		env.log("failed: %v", err)
		return vcs.BisectSkip, current, nil, nil
	}
	bad, good, rep := env.processResults(current, results)
	res := vcs.BisectSkip
	if bad != 0 {
		res = vcs.BisectBad
	} else if numTests-good-bad > numTests/3*2 {
		// More than 2/3 of instances failed with infrastructure error,
		// can't reliably tell that the commit is good.
		res = vcs.BisectSkip
	} else if good != 0 {
		res = vcs.BisectGood
	}
	return res, current, rep, nil
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
