// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

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
)

var (
	flagConfig = flag.String("config", "", "bisect config file")
	flagCrash  = flag.String("crash", "", "dir with crash info")
	flagFix    = flag.Bool("fix", false, "search for crash fix")
)

type Config struct {
	BinDir        string          `json:"bin_dir"`
	KernelRepo    string          `json:"kernel_repo"`
	KernelBranch  string          `json:"kernel_branch"`
	Compiler      string          `json:"compiler"`
	Userspace     string          `json:"userspace"`
	Sysctl        string          `json:"sysctl"`
	Cmdline       string          `json:"cmdline"`
	SyzkallerRepo string          `json:"syzkaller_repo"`
	Manager       json.RawMessage `json:"manager"`
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
	loadFile("kernel.config", &cfg.Kernel.Config)
	loadFile("repro.syz", &cfg.Repro.Syz)
	loadFile("repro.opts", &cfg.Repro.Opts)
	if _, _, err := bisect.Run(cfg); err != nil {
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

func loadFile(file string, dst *[]byte) {
	data, err := ioutil.ReadFile(filepath.Join(*flagCrash, file))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	*dst = data
}
