// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-ci is a continuous fuzzing system for syzkaller.
// It runs several syz-manager's, polls and rebuilds images for managers
// and polls and rebuilds syzkaller binaries.
// For usage instructions see: docs/ci.md.
package main

// Implementation details:
//
// 2 main components:
//  - SyzUpdater: handles syzkaller updates
//  - Manager: handles kernel build and syz-manager process (one per manager)
// Both operate in a similar way and keep 2 builds:
//  - latest: latest known good build (i.e. we tested it)
//    preserved across restarts/reboots, i.e. we can start fuzzing even when
//    current syzkaller/kernel git head is broken, or git is down, or anything else
//  - current: currently used build (a copy of one of the latest builds)
// Other important points:
//  - syz-ci is always built on the same revision as the rest of syzkaller binaries,
//    this allows us to handle e.g. changes in manager config format.
//  - consequently, syzkaller binaries are never updated on-the-fly,
//    instead we re-exec and then update
//  - we understand when the latest build is fresh even after reboot,
//    i.e. we store enough information to identify it (git hash, compiler identity, etc),
//    so we don't rebuild unnecessary (kernel builds take time)
//  - we generally avoid crashing the process and handle all errors gracefully
//    (this is a continuous system), except for some severe/user errors during start
//    (e.g. bad config file, or can't create necessary dirs)
//
// Directory/file structure:
// syz-ci			: current executable
// syzkaller/
//	latest/			: latest good syzkaller build
//	current/		: syzkaller build currently in use
// managers/
//	manager1/		: one dir per manager
//		kernel/		: kernel checkout
//		workdir/	: manager workdir (never deleted)
//		latest/		: latest good kernel image build
//		current/	: kernel image currently in use
// jobs/
//	linux/			: one dir per target OS
//		kernel/		: kernel checkout
//		image/		: currently used image
//		workdir/	: some temp files
//
// Current executable, syzkaller and kernel builds are marked with tag files.
// Tag files uniquely identify the build (git hash, compiler identity, kernel config, etc).
// For tag files both contents and modification time are important,
// modification time allows us to understand if we need to rebuild after a restart.

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"regexp"
	"sync"

	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
)

var (
	flagConfig     = flag.String("config", "", "config file")
	flagAutoUpdate = flag.Bool("autoupdate", true, "auto-update the binary (for testing)")
	flagManagers   = flag.Bool("managers", true, "start managers (for testing)")
	flagDebug      = flag.Bool("debug", false, "debug mode (for testing)")
)

type Config struct {
	Name string `json:"name"`
	HTTP string `json:"http"`
	// If manager http address is not specified, give it an address starting from this port. Optional.
	ManagerPort     int    `json:"manager_port_start"`
	DashboardAddr   string `json:"dashboard_addr"`   // Optional.
	DashboardClient string `json:"dashboard_client"` // Optional.
	DashboardKey    string `json:"dashboard_key"`    // Optional.
	HubAddr         string `json:"hub_addr"`         // Optional.
	HubKey          string `json:"hub_key"`          // Optional.
	Goroot          string `json:"goroot"`           // Go 1.8+ toolchain dir.
	SyzkallerRepo   string `json:"syzkaller_repo"`
	SyzkallerBranch string `json:"syzkaller_branch"` // Defaults to "master".
	// Dir with additional syscall descriptions (.txt and .const files).
	SyzkallerDescriptions string `json:"syzkaller_descriptions"`
	// Protocol-specific path to upload coverage reports from managers (optional).
	// Supported protocols: GCS (gs://) and HTTP PUT (http:// or https://).
	CoverUploadPath string           `json:"cover_upload_path"`
	BisectBinDir    string           `json:"bisect_bin_dir"`
	Ccache          string           `json:"ccache"`
	Managers        []*ManagerConfig `json:"managers"`
	// Poll period for jobs in seconds (optional, defaults to 10 seconds)
	JobPollPeriod int `json:"job_poll_period"`
	// Poll period for commits in seconds (optional, defaults to 3600 seconds)
	CommitPollPeriod int `json:"commit_poll_period"`
}

type ManagerConfig struct {
	// If Name is specified, syz-manager name is set to Config.Name-ManagerConfig.Name.
	// This is old naming scheme, it does not allow to move managers between ci instances.
	// For new naming scheme set ManagerConfig.ManagerConfig.Name instead and leave this field empty.
	// This allows to move managers as their name does not depend on cfg.Name.
	// Generally, if you have:
	// {
	//   "name": "ci",
	//   "managers": [
	//     {
	//       "name": "foo",
	//       ...
	//     }
	//   ]
	// }
	// you want to change it to:
	// {
	//   "name": "ci",
	//   "managers": [
	//     {
	//       ...
	//       "manager_config": {
	//         "name": "ci-foo"
	//       }
	//     }
	//   ]
	// }
	// and rename managers/foo to managers/ci-foo. Then this instance can be moved
	// to another ci along with managers/ci-foo dir.
	Name            string `json:"name"`
	Disabled        string `json:"disabled"` // If not empty, don't build/start this manager.
	DashboardClient string `json:"dashboard_client"`
	DashboardKey    string `json:"dashboard_key"`
	Repo            string `json:"repo"`
	// Short name of the repo (e.g. "linux-next"), used only for reporting.
	RepoAlias    string `json:"repo_alias"`
	Branch       string `json:"branch"` // Defaults to "master".
	Compiler     string `json:"compiler"`
	Ccache       string `json:"ccache"`
	Userspace    string `json:"userspace"`
	KernelConfig string `json:"kernel_config"`
	// Baseline config for bisection, see pkg/bisect.KernelConfig.BaselineConfig.
	KernelBaselineConfig string `json:"kernel_baseline_config"`
	// File with kernel cmdline values (optional).
	KernelCmdline string `json:"kernel_cmdline"`
	// File with sysctl values (e.g. output of sysctl -a, optional).
	KernelSysctl string      `json:"kernel_sysctl"`
	Jobs         ManagerJobs `json:"jobs"`

	ManagerConfig json.RawMessage `json:"manager_config"`
	managercfg    *mgrconfig.Config
}

type ManagerJobs struct {
	TestPatches bool `json:"test_patches"` // enable patch testing jobs
	PollCommits bool `json:"poll_commits"` // poll info about fix commits
	BisectCause bool `json:"bisect_cause"` // do cause bisection
	BisectFix   bool `json:"bisect_fix"`   // do fix bisection
}

func main() {
	flag.Parse()
	log.EnableLogCaching(1000, 1<<20)
	cfg, err := loadConfig(*flagConfig)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	shutdownPending := make(chan struct{})
	osutil.HandleInterrupts(shutdownPending)

	serveHTTP(cfg)

	os.Unsetenv("GOPATH")
	if cfg.Goroot != "" {
		os.Setenv("GOROOT", cfg.Goroot)
		os.Setenv("PATH", filepath.Join(cfg.Goroot, "bin")+
			string(filepath.ListSeparator)+os.Getenv("PATH"))
	}

	updatePending := make(chan struct{})
	updater := NewSyzUpdater(cfg)
	updater.UpdateOnStart(*flagAutoUpdate, shutdownPending)
	if *flagAutoUpdate {
		go func() {
			updater.WaitForUpdate()
			close(updatePending)
		}()
	}

	var wg sync.WaitGroup
	wg.Add(1)
	stop := make(chan struct{})
	go func() {
		select {
		case <-shutdownPending:
		case <-updatePending:
		}
		kernelBuildSem <- struct{}{} // wait for all current builds
		close(stop)
		wg.Done()
	}()

	var managers []*Manager
	for _, mgrcfg := range cfg.Managers {
		mgr, err := createManager(cfg, mgrcfg, stop, *flagDebug)
		if err != nil {
			log.Logf(0, "failed to create manager %v: %v", mgrcfg.Name, err)
			continue
		}
		managers = append(managers, mgr)
	}
	if len(managers) == 0 {
		log.Fatalf("failed to create all managers")
	}
	if *flagManagers {
		for _, mgr := range managers {
			mgr := mgr
			wg.Add(1)
			go func() {
				defer wg.Done()
				mgr.loop()
			}()
		}
	}

	jp := newJobProcessor(cfg, managers, stop, shutdownPending)
	wg.Add(1)
	go func() {
		defer wg.Done()
		jp.loop()
	}()

	// For testing. Racy. Use with care.
	http.HandleFunc("/upload_cover", func(w http.ResponseWriter, r *http.Request) {
		for _, mgr := range managers {
			if err := mgr.uploadCoverReport(); err != nil {
				w.Write([]byte(fmt.Sprintf("failed for %v: %v <br>\n", mgr.name, err)))
				return
			}
			w.Write([]byte(fmt.Sprintf("upload cover for %v <br>\n", mgr.name)))
		}
	})

	wg.Wait()

	select {
	case <-shutdownPending:
	case <-updatePending:
		updater.UpdateAndRestart()
	}
}

func serveHTTP(cfg *Config) {
	ln, err := net.Listen("tcp4", cfg.HTTP)
	if err != nil {
		log.Fatalf("failed to listen on %v: %v", cfg.HTTP, err)
	}
	log.Logf(0, "serving http on http://%v", ln.Addr())
	go func() {
		err := http.Serve(ln, nil)
		log.Fatalf("failed to serve http: %v", err)
	}()
}

func loadConfig(filename string) (*Config, error) {
	cfg := &Config{
		SyzkallerRepo:    "https://github.com/google/syzkaller.git",
		SyzkallerBranch:  "master",
		ManagerPort:      10000,
		Goroot:           os.Getenv("GOROOT"),
		JobPollPeriod:    10,
		CommitPollPeriod: 3600,
	}
	if err := config.LoadFile(filename, cfg); err != nil {
		return nil, err
	}
	if cfg.Name == "" {
		return nil, fmt.Errorf("param 'name' is empty")
	}
	if cfg.HTTP == "" {
		return nil, fmt.Errorf("param 'http' is empty")
	}
	cfg.Goroot = osutil.Abs(cfg.Goroot)
	cfg.SyzkallerDescriptions = osutil.Abs(cfg.SyzkallerDescriptions)
	cfg.BisectBinDir = osutil.Abs(cfg.BisectBinDir)
	cfg.Ccache = osutil.Abs(cfg.Ccache)
	var managers []*ManagerConfig
	for _, mgr := range cfg.Managers {
		if mgr.Disabled == "" {
			managers = append(managers, mgr)
		}
		if err := loadManagerConfig(cfg, mgr); err != nil {
			return nil, err
		}
	}
	cfg.Managers = managers
	if len(cfg.Managers) == 0 {
		return nil, fmt.Errorf("no managers specified")
	}
	return cfg, nil
}

func loadManagerConfig(cfg *Config, mgr *ManagerConfig) error {
	managercfg, err := mgrconfig.LoadPartialData(mgr.ManagerConfig)
	if err != nil {
		return fmt.Errorf("manager config: %v", err)
	}
	if managercfg.Name != "" && mgr.Name != "" {
		return fmt.Errorf("both managercfg.Name=%q and mgr.Name=%q are specified", managercfg.Name, mgr.Name)
	}
	if managercfg.Name == "" && mgr.Name == "" {
		return fmt.Errorf("no managercfg.Name nor mgr.Name are specified")
	}
	if managercfg.Name != "" {
		mgr.Name = managercfg.Name
	} else {
		managercfg.Name = cfg.Name + "-" + mgr.Name
	}
	// Manager name must not contain dots because it is used as GCE image name prefix.
	managerNameRe := regexp.MustCompile("^[a-zA-Z0-9-_]{3,64}$")
	if !managerNameRe.MatchString(mgr.Name) {
		return fmt.Errorf("param 'managers.name' has bad value: %q", mgr.Name)
	}
	if mgr.Branch == "" {
		mgr.Branch = "master"
	}
	if (mgr.Jobs.TestPatches || mgr.Jobs.PollCommits ||
		mgr.Jobs.BisectCause || mgr.Jobs.BisectFix) &&
		(cfg.DashboardAddr == "" || cfg.DashboardClient == "") {
		return fmt.Errorf("manager %v: has jobs but no dashboard info", mgr.Name)
	}
	if mgr.Jobs.PollCommits && (cfg.DashboardAddr == "" || mgr.DashboardClient == "") {
		return fmt.Errorf("manager %v: commit_poll is set but no dashboard info", mgr.Name)
	}
	if (mgr.Jobs.BisectCause || mgr.Jobs.BisectFix) && cfg.BisectBinDir == "" {
		return fmt.Errorf("manager %v: enabled bisection but no bisect_bin_dir", mgr.Name)
	}
	mgr.managercfg = managercfg
	managercfg.Syzkaller = filepath.FromSlash("syzkaller/current")
	if managercfg.HTTP == "" {
		managercfg.HTTP = fmt.Sprintf(":%v", cfg.ManagerPort)
		cfg.ManagerPort++
	}
	// Note: we don't change Compiler/Ccache because it may be just "gcc" referring
	// to the system binary, or pkg/build/netbsd.go uses "g++" and "clang++" as special marks.
	mgr.Userspace = osutil.Abs(mgr.Userspace)
	mgr.KernelConfig = osutil.Abs(mgr.KernelConfig)
	mgr.KernelBaselineConfig = osutil.Abs(mgr.KernelBaselineConfig)
	mgr.KernelCmdline = osutil.Abs(mgr.KernelCmdline)
	mgr.KernelSysctl = osutil.Abs(mgr.KernelSysctl)
	return nil
}
