// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-bisect runs bisection to find cause/fix commit for a crash.
//
// The tool is originally created to test pkg/bisect logic,
// the interface is not particularly handy to use.
//
// The tool requires a config file passed in -config flag, see Config type below for details,
// and a directory with info about the crash passed in -crash flag).
// If -fix flag is specified, it does fix bisection. Otherwise it does cause bisection.
//
// The crash dir should contain the following files:
//  - repro.c: C reproducer for the crash (optional)
//  - repro.syz: syzkaller reproducer for the crash
//  - repro.opts: syzkaller reproducer options (e.g. {"procs":1,"sandbox":"none",...})
//  - syzkaller.commit: hash of syzkaller commit which was used to trigger the crash
//  - kernel.commit: hash of kernel commit on which the crash was triggered
//  - kernel.config: kernel config file
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/syzkaller/pkg/bisect"
	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
)

var (
	flagConfig = flag.String("config", "", "bisect config file")
	flagCrash  = flag.String("crash", "", "dir with crash info")
	flagFix    = flag.Bool("fix", false, "search for crash fix")
)

type Config struct {
	// BinDir must point to a dir that contains compilers required to build
	// older versions of the kernel. For linux, it needs to include several
	// gcc versions. A working archive can be downloaded from:
	// https://storage.googleapis.com/syzkaller/bisect_bin.tar.gz
	BinDir        string `json:"bin_dir"`
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
	mgrcfg, err := mgrconfig.LoadPartialData(mycfg.Manager)
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
		Trace:    os.Stdout,
		Fix:      *flagFix,
		BinDir:   mycfg.BinDir,
		DebugDir: *flagCrash,
		Kernel: bisect.KernelConfig{
			Repo:      mycfg.KernelRepo,
			Branch:    mycfg.KernelBranch,
			Userspace: mycfg.Userspace,
			Sysctl:    mycfg.Sysctl,
			Cmdline:   mycfg.Cmdline,
		},
		Syzkaller: bisect.SyzkallerConfig{
			Repo: mycfg.SyzkallerRepo,
		},
		Manager: *mgrcfg,
	}
	loadString("syzkaller.commit", &cfg.Syzkaller.Commit)
	loadString("kernel.commit", &cfg.Kernel.Commit)
	loadFile("kernel.config", &cfg.Kernel.Config, true)
	loadFile("kernel.baseline_config", &cfg.Kernel.BaselineConfig, false)
	loadFile("repro.syz", &cfg.Repro.Syz, false)
	loadFile("repro.c", &cfg.Repro.C, false)
	loadFile("repro.opts", &cfg.Repro.Opts, true)

	if _, err := bisect.Run(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "bisection failed: %v\n", err)
		os.Exit(1)
	}
}

func loadString(file string, dst *string) {
	data, err := ioutil.ReadFile(filepath.Join(*flagCrash, file))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	*dst = strings.TrimSpace(string(data))
}

func loadFile(file string, dst *[]byte, mandatory bool) {
	filename := filepath.Join(*flagCrash, file)
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
