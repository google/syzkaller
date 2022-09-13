// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-bisect runs bisection to find cause/fix commit for a crash.
//
// The tool is originally created to test pkg/bisect logic.
//
// The tool requires a config file passed in -config flag, see Config type below for details,
// and a directory with info about the crash passed in -crash flag).
// If -fix flag is specified, it does fix bisection. Otherwise it does cause bisection. Also
// wanted syzkaller and kernel commits can be specified using -syzkaller_commit and
// -kernel_commit. HEAD is used if commits are not specified.
//
// The crash dir should contain the following files:
//  - repro.cprog or repro.prog: reproducer for the crash
//  - repro.opts: syzkaller reproducer options (e.g. {"procs":1,"sandbox":"none",...}) (optional)
//
// The tool stores bisection result into cause.commit or fix.commit.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/google/syzkaller/pkg/bisect"
	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/debugtracer"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/vcs"
)

var (
	flagConfig            = flag.String("config", "", "bisect config file")
	flagCrash             = flag.String("crash", "", "dir with crash info")
	flagFix               = flag.Bool("fix", false, "search for crash fix")
	flagKernelCommit      = flag.String("kernel_commit", "", "original kernel commit")
	flagKernelCommitTitle = flag.String("kernel_commit_title", "", "original kernel commit title")
	flagSyzkallerCommit   = flag.String("syzkaller_commit", "", "original syzkaller commit")
)

type Config struct {
	Compiler string `json:"compiler"`
	// Currently either 'gcc' or 'clang'. Note that pkg/bisect requires
	// explicit plumbing for every os/compiler combination.
	CompilerType string `json:"compiler_type"`
	// BinDir must point to a dir that contains compilers required to build
	// older versions of the kernel. For linux, it needs to include several
	// compiler versions.
	BinDir        string `json:"bin_dir"`
	Ccache        string `json:"ccache"`
	KernelRepo    string `json:"kernel_repo"`
	KernelBranch  string `json:"kernel_branch"`
	SyzkallerRepo string `json:"syzkaller_repo"`
	// Directory with user-space system for building kernel images
	// (for linux that's the input to tools/create-gce-image.sh).
	Userspace string `json:"userspace"`
	// Sysctl/cmdline files used to build the image which was used to crash the kernel, e.g. see:
	// dashboard/config/upstream.sysctl
	// dashboard/config/upstream-selinux.cmdline
	Sysctl  string `json:"sysctl"`
	Cmdline string `json:"cmdline"`

	KernelConfig         string `json:"kernel_config"`
	KernelBaselineConfig string `json:"kernel_baseline_config"`

	// Manager config that was used to obtain the crash.
	Manager json.RawMessage `json:"manager"`
}

func main() {
	flag.Parse()
	os.Setenv("SYZ_DISABLE_SANDBOXING", "yes")
	mycfg := new(Config)
	if err := config.LoadFile(*flagConfig, mycfg); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	mgrcfg, err := mgrconfig.LoadData(mycfg.Manager)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if mgrcfg.Workdir == "" {
		mgrcfg.Workdir, err = ioutil.TempDir("", "syz-bisect")
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to create temp dir: %v\n", err)
			os.Exit(1)
		}
		defer os.RemoveAll(mgrcfg.Workdir)
	}
	cfg := &bisect.Config{
		Trace: &debugtracer.GenericTracer{
			TraceWriter: os.Stdout,
			OutDir:      *flagCrash,
		},
		Fix:             *flagFix,
		DefaultCompiler: mycfg.Compiler,
		CompilerType:    mycfg.CompilerType,
		BinDir:          mycfg.BinDir,
		Ccache:          mycfg.Ccache,
		Kernel: bisect.KernelConfig{
			Repo:        mycfg.KernelRepo,
			Branch:      mycfg.KernelBranch,
			Commit:      *flagKernelCommit,
			CommitTitle: *flagKernelCommitTitle,
			Userspace:   mycfg.Userspace,
			Sysctl:      mycfg.Sysctl,
			Cmdline:     mycfg.Cmdline,
		},
		Syzkaller: bisect.SyzkallerConfig{
			Repo:   mycfg.SyzkallerRepo,
			Commit: *flagSyzkallerCommit,
		},
		Manager: mgrcfg,
	}
	loadFile("", mycfg.KernelConfig, &cfg.Kernel.Config, true)
	loadFile("", mycfg.KernelBaselineConfig, &cfg.Kernel.BaselineConfig, false)
	loadFile(*flagCrash, "repro.prog", &cfg.Repro.Syz, false)
	loadFile(*flagCrash, "repro.cprog", &cfg.Repro.C, false)
	loadFile(*flagCrash, "repro.opts", &cfg.Repro.Opts, false)

	if len(cfg.Repro.Syz) == 0 && len(cfg.Repro.C) == 0 {
		fmt.Fprintf(os.Stderr, "no repro.cprog or repro.prog found\n")
		os.Exit(1)
	}

	if cfg.Syzkaller.Commit == "" {
		cfg.Syzkaller.Commit = vcs.HEAD
	}
	if cfg.Kernel.Commit == "" {
		cfg.Kernel.Commit = vcs.HEAD
	}

	result, err := bisect.Run(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bisection failed: %v\n", err)
		os.Exit(1)
	}

	saveResultCommits(result.Commits)
}

func loadFile(path, file string, dst *[]byte, mandatory bool) {
	filename := filepath.Join(path, file)
	if !mandatory && !osutil.IsExist(filename) {
		return
	}
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	*dst = data
}

func saveResultCommits(commits []*vcs.Commit) {
	var result string
	if len(commits) > 0 {
		for _, commit := range commits {
			result = result + commit.Hash + "\n"
		}
	} else if *flagFix {
		result = "the crash still happens on HEAD\n"
	} else {
		result = "the crash already happened on the oldest tested release\n"
	}

	var fileName string
	if *flagFix {
		fileName = filepath.Join(*flagCrash, "fix.commit")
	} else {
		fileName = filepath.Join(*flagCrash, "cause.commit")
	}
	osutil.WriteFile(fileName, []byte(result))
}
