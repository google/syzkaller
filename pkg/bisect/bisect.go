// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package bisect

import (
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/google/syzkaller/pkg/git"
	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/kernel"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/syz-manager/mgrconfig"
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
	head      *git.Commit
	inst      *instance.Env
	numTests  int
	buildTime time.Duration
	testTime  time.Duration
}

type buildEnv struct {
	compiler string
}

func Run(cfg *Config) (*git.Commit, error) {
	env := &env{
		cfg: cfg,
	}
	if cfg.Fix {
		env.log("searching for fixing commit since %v", cfg.Kernel.Commit)
	} else {
		env.log("searching for guilty commit starting from %v", cfg.Kernel.Commit)
	}
	start := time.Now()
	res, err := env.bisect()
	env.log("revisions tested: %v, total time: %v (build: %v, test: %v)",
		env.numTests, time.Since(start), env.buildTime, env.testTime)
	if err != nil {
		env.log("error: %v", err)
		return nil, err
	}
	if res == nil {
		env.log("the crash is still unfixed")
		return nil, nil
	}
	what := "bad"
	if cfg.Fix {
		what = "good"
	}
	env.log("first %v commit: %v %v", what, res.Hash, res.Title)
	env.log("cc: %q", res.CC)
	return res, nil
}

func (env *env) bisect() (*git.Commit, error) {
	cfg := env.cfg
	var err error
	if env.inst, err = instance.NewEnv(&cfg.Manager); err != nil {
		return nil, err
	}
	if env.head, err = git.Poll(cfg.Manager.KernelSrc, cfg.Kernel.Repo, cfg.Kernel.Branch); err != nil {
		return nil, err
	}
	if err := kernel.Clean(cfg.Manager.KernelSrc); err != nil {
		return nil, fmt.Errorf("kernel clean failed: %v", err)
	}
	env.log("building syzkaller on %v", cfg.Syzkaller.Commit)
	if err := env.inst.BuildSyzkaller(cfg.Syzkaller.Repo, cfg.Syzkaller.Commit); err != nil {
		return nil, err
	}
	if _, err := git.SwitchCommit(cfg.Manager.KernelSrc, cfg.Kernel.Commit); err != nil {
		return nil, err
	}
	if res, err := env.test(); err != nil {
		return nil, err
	} else if res != git.BisectBad {
		return nil, fmt.Errorf("the crash wasn't reproduced on the original commit")
	}
	res, bad, good, err := env.commitRange()
	if err != nil {
		return nil, err
	}
	if res != nil {
		return res, nil // happens on the oldest release
	}
	if good == "" {
		return nil, nil // still not fixed
	}
	return git.Bisect(cfg.Manager.KernelSrc, bad, good, cfg.Trace, func() (git.BisectResult, error) {
		res, err := env.test()
		if cfg.Fix {
			if res == git.BisectBad {
				res = git.BisectGood
			} else if res == git.BisectGood {
				res = git.BisectBad
			}
		}
		return res, err
	})
}

func (env *env) commitRange() (*git.Commit, string, string, error) {
	if env.cfg.Fix {
		return env.commitRangeForFix()
	}
	return env.commitRangeForBug()
}

func (env *env) commitRangeForFix() (*git.Commit, string, string, error) {
	env.log("testing current HEAD %v", env.head.Hash)
	if _, err := git.SwitchCommit(env.cfg.Manager.KernelSrc, env.head.Hash); err != nil {
		return nil, "", "", err
	}
	res, err := env.test()
	if err != nil {
		return nil, "", "", err
	}
	if res != git.BisectGood {
		return nil, "", "", nil
	}
	return nil, env.head.Hash, env.cfg.Kernel.Commit, nil
}

func (env *env) commitRangeForBug() (*git.Commit, string, string, error) {
	cfg := env.cfg
	tags, err := git.PreviousReleaseTags(cfg.Manager.KernelSrc, cfg.Kernel.Commit)
	if err != nil {
		return nil, "", "", err
	}
	for i, tag := range tags {
		if tag == "v3.8" {
			// v3.8 does not work with modern perl, and as we go further in history
			// make stops to work, then binutils, glibc, etc. So we stop at v3.8.
			// Up to that point we only need an ancient gcc.
			tags = tags[:i]
			break
		}
	}
	if len(tags) == 0 {
		return nil, "", "", fmt.Errorf("no release tags before this commit")
	}
	lastBad := cfg.Kernel.Commit
	for i, tag := range tags {
		env.log("testing release %v", tag)
		commit, err := git.SwitchCommit(cfg.Manager.KernelSrc, tag)
		if err != nil {
			return nil, "", "", err
		}
		res, err := env.test()
		if err != nil {
			return nil, "", "", err
		}
		if res == git.BisectGood {
			return nil, lastBad, tag, nil
		}
		if res == git.BisectBad {
			lastBad = tag
		}
		if i == len(tags)-1 {
			return commit, "", "", nil
		}
	}
	panic("unreachable")
}

func (env *env) test() (git.BisectResult, error) {
	cfg := env.cfg
	env.numTests++
	current, err := git.HeadCommit(cfg.Manager.KernelSrc)
	if err != nil {
		return 0, err
	}
	be, err := env.buildEnvForCommit(current.Hash)
	if err != nil {
		return 0, err
	}
	compilerID, err := kernel.CompilerIdentity(be.compiler)
	if err != nil {
		return 0, err
	}
	env.log("testing commit %v with %v", current.Hash, compilerID)
	buildStart := time.Now()
	if err := kernel.Clean(cfg.Manager.KernelSrc); err != nil {
		return 0, fmt.Errorf("kernel clean failed: %v", err)
	}
	err = env.inst.BuildKernel(be.compiler, cfg.Kernel.Userspace,
		cfg.Kernel.Cmdline, cfg.Kernel.Sysctl, cfg.Kernel.Config)
	env.buildTime += time.Since(buildStart)
	if err != nil {
		if verr, ok := err.(*osutil.VerboseError); ok {
			env.log("%v", verr.Title)
			env.saveDebugFile(current.Hash, 0, verr.Output)
		} else {
			env.log("%v", err)
		}
		return git.BisectSkip, nil
	}
	testStart := time.Now()
	results, err := env.inst.Test(8, cfg.Repro.Syz, cfg.Repro.Opts, cfg.Repro.C)
	env.testTime += time.Since(testStart)
	if err != nil {
		env.log("failed: %v", err)
		return git.BisectSkip, nil
	}
	bad, good := env.processResults(current, results)
	res := git.BisectSkip
	if bad != 0 {
		res = git.BisectBad
	} else if good != 0 {
		res = git.BisectGood
	}
	return res, nil
}

func (env *env) processResults(current *git.Commit, results []error) (bad, good int) {
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

// Note: linux-specific.
func (env *env) buildEnvForCommit(commit string) (*buildEnv, error) {
	cfg := env.cfg
	tags, err := git.PreviousReleaseTags(cfg.Manager.KernelSrc, commit)
	if err != nil {
		return nil, err
	}
	be := &buildEnv{
		compiler: filepath.Join(cfg.BinDir, "gcc-"+linuxCompilerVersion(tags), "bin", "gcc"),
	}
	return be, nil
}

func linuxCompilerVersion(tags []string) string {
	for _, tag := range tags {
		switch tag {
		case "v4.12":
			return "8.1.0"
		case "v4.11":
			return "7.3.0"
		case "v3.19":
			return "5.5.0"
		}
	}
	return "4.9.4"
}

func (env *env) saveDebugFile(hash string, idx int, data []byte) {
	if env.cfg.DebugDir == "" || len(data) == 0 {
		return
	}
	osutil.WriteFile(filepath.Join(env.cfg.DebugDir, fmt.Sprintf("%v.%v", hash, idx)), data)
}

func (env *env) log(msg string, args ...interface{}) {
	fmt.Fprintf(env.cfg.Trace, msg+"\n", args...)
}
