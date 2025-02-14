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
	"strings"
	"sync"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/asset"
	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/vcs"
)

var (
	flagConfig     = flag.String("config", "", "config file")
	flagAutoUpdate = flag.Bool("autoupdate", true, "auto-update the binary (for testing)")
	flagManagers   = flag.Bool("managers", true, "start managers (for testing)")
	flagDebug      = flag.Bool("debug", false, "debug mode (for testing)")
	// nolint: lll
	flagExitOnUpgrade = flag.Bool("exit-on-upgrade", false, "exit after a syz-ci upgrade is applied; otherwise syz-ci restarts")
)

type Config struct {
	Name string `json:"name"`
	HTTP string `json:"http"`
	// If manager http address is not specified, give it an address starting from this port. Optional.
	// This is also used to auto-assign ports for test instances.
	ManagerPort int `json:"manager_port_start"`
	// If manager rpc address is not specified, give it addresses starting from this port. By default 30000.
	// This is also used to auto-assign ports for test instances.
	RPCPort         int    `json:"rpc_port_start"`
	DashboardAddr   string `json:"dashboard_addr"`   // Optional.
	DashboardClient string `json:"dashboard_client"` // Optional.
	DashboardKey    string `json:"dashboard_key"`    // Optional.
	HubAddr         string `json:"hub_addr"`         // Optional.
	HubKey          string `json:"hub_key"`          // Optional.
	Goroot          string `json:"goroot"`           // Go 1.8+ toolchain dir.
	SyzkallerRepo   string `json:"syzkaller_repo"`
	SyzkallerBranch string `json:"syzkaller_branch"` // Defaults to "master".
	// Dir with additional syscall descriptions.
	// - *.txt and *.const files are copied to syzkaller/sys/linux/
	// - *.test files are copied to syzkaller/sys/linux/test/
	// - *.h files are copied to syzkaller/executor/
	SyzkallerDescriptions string `json:"syzkaller_descriptions"`
	// Path to upload coverage reports from managers (optional).
	// Supported protocols: GCS (gs://) and HTTP PUT (http:// or https://).
	CoverUploadPath string `json:"cover_upload_path"`
	// Path to upload json coverage reports from managers (optional).
	CoverPipelinePath string `json:"cover_pipeline_path"`
	// Path to upload corpus.db from managers (optional).
	// Supported protocols: GCS (gs://) and HTTP PUT (http:// or https://).
	CorpusUploadPath string `json:"corpus_upload_path"`
	// Make files uploaded via CoverUploadPath and CorpusUploadPath public.
	PublishGCS bool `json:"publish_gcs"`
	// Path to upload bench data from instances (optional).
	// Supported protocols: GCS (gs://) and HTTP PUT (http:// or https://).
	BenchUploadPath string `json:"bench_upload_path"`
	// BinDir must point to a dir that contains compilers required to build
	// older versions of the kernel. For linux, it needs to include several
	// compiler versions.
	BisectBinDir string `json:"bisect_bin_dir"`
	// Keys of BisectIgnore are full commit hashes that should never be reported
	// in bisection results.
	// Values of the map are ignored and can e.g. serve as comments.
	BisectIgnore map[string]string `json:"bisect_ignore"`
	// Extra commits to cherry-pick to older kernel revisions.
	// The list is concatenated with the similar parameter from ManagerConfig.
	BisectBackports []vcs.BackportCommit `json:"bisect_backports"`
	Ccache          string               `json:"ccache"`
	// BuildCPUs defines the maximum number of parallel kernel build threads.
	BuildCPUs int              `json:"build_cpus"`
	Managers  []*ManagerConfig `json:"managers"`
	// Poll period for jobs in seconds (optional, defaults to 10 seconds)
	JobPollPeriod int `json:"job_poll_period"`
	// Set up a second (parallel) job processor to speed up processing.
	// For now, this second job processor only handles patch testing requests.
	ParallelJobs bool `json:"parallel_jobs"`
	// Poll period for commits in seconds (optional, defaults to 3600 seconds)
	CommitPollPeriod int `json:"commit_poll_period"`
	// Asset Storage config.
	AssetStorage *asset.Config `json:"asset_storage"`
	// Per-vm type JSON diffs that will be applied to every instace of the
	// corresponding VM type.
	PatchVMConfigs map[string]json.RawMessage `json:"patch_vm_configs"`
	// Some commits don't live long.
	// Push all commits used in kernel builds to this git repo URL.
	// The archive is later used by coverage merger.
	GitArchive string `json:"git_archive"`
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
	Disabled        string `json:"disabled"`         // If not empty, don't build/start this manager.
	DashboardClient string `json:"dashboard_client"` // Optional.
	DashboardKey    string `json:"dashboard_key"`    // Optional.
	Repo            string `json:"repo"`
	// Short name of the repo (e.g. "linux-next"), used only for reporting.
	RepoAlias string `json:"repo_alias"`
	Branch    string `json:"branch"` // Defaults to "master".
	// Currently either 'gcc' or 'clang'. Note that pkg/bisect requires
	// explicit plumbing for every os/compiler combination.
	CompilerType string `json:"compiler_type"` // Defaults to "gcc"
	Compiler     string `json:"compiler"`
	Make         string `json:"make"`
	Linker       string `json:"linker"`
	Ccache       string `json:"ccache"`
	Userspace    string `json:"userspace"`
	KernelConfig string `json:"kernel_config"`
	// KernelSrcSuffix adds a suffix to the kernel_src manager config. This is needed for cases where
	// the kernel source root as reported in the coverage UI is a subdirectory of the VCS root.
	KernelSrcSuffix string `json:"kernel_src_suffix"`
	// Build-type-specific parameters.
	// Parameters for concrete types are in Config type in pkg/build/TYPE.go, e.g. pkg/build/android.go.
	Build json.RawMessage `json:"build"`
	// Baseline config for bisection, see pkg/bisect.KernelConfig.BaselineConfig.
	// If not specified, syz-ci generates a `-base.config` path counterpart for `kernel_config` and,
	// if it exists, uses it as default.
	KernelBaselineConfig string `json:"kernel_baseline_config"`
	// File with kernel cmdline values (optional).
	KernelCmdline string `json:"kernel_cmdline"`
	// File with sysctl values (e.g. output of sysctl -a, optional).
	KernelSysctl string      `json:"kernel_sysctl"`
	Jobs         ManagerJobs `json:"jobs"`
	// Extra commits to cherry pick to older kernel revisions.
	BisectBackports []vcs.BackportCommit `json:"bisect_backports"`
	// Base syz-manager config for the instance.
	ManagerConfig json.RawMessage `json:"manager_config"`
	// By default we want to archive git commits.
	// This opt-out is needed for *BSD systems.
	DisableGitArchive bool `json:"disable_git_archive"`
	// If the kernel's commit is older than MaxKernelLagDays days,
	// fuzzing won't be started on this instance.
	// By default it's 30 days.
	MaxKernelLagDays int `json:"max_kernel_lag_days"`
	managercfg       *mgrconfig.Config

	// Auto-assigned ports used by test instances.
	testRPCPort int
}

type ManagerJobs struct {
	TestPatches bool `json:"test_patches"` // enable patch testing jobs
	PollCommits bool `json:"poll_commits"` // poll info about fix commits
	BisectCause bool `json:"bisect_cause"` // do cause bisection
	BisectFix   bool `json:"bisect_fix"`   // do fix bisection
}

func (m *ManagerJobs) AnyEnabled() bool {
	return m.TestPatches || m.PollCommits || m.BisectCause || m.BisectFix
}

func (m *ManagerJobs) Filter(filter *ManagerJobs) *ManagerJobs {
	return &ManagerJobs{
		TestPatches: m.TestPatches && filter.TestPatches,
		PollCommits: m.PollCommits && filter.PollCommits,
		BisectCause: m.BisectCause && filter.BisectCause,
		BisectFix:   m.BisectFix && filter.BisectFix,
	}
}

func main() {
	flag.Parse()
	log.EnableLogCaching(1000, 1<<20)
	cfg, err := loadConfig(*flagConfig)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}
	log.SetName(cfg.Name)

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

	stop := make(chan struct{})
	var managers []*Manager
	for _, mgrcfg := range cfg.Managers {
		mgr, err := createManager(cfg, mgrcfg, stop, *flagDebug)
		if err != nil {
			log.Errorf("failed to create manager %v: %v", mgrcfg.Name, err)
			continue
		}
		managers = append(managers, mgr)
	}
	if len(managers) == 0 {
		log.Fatalf("failed to create all managers")
	}
	var wg sync.WaitGroup
	if *flagManagers {
		for _, mgr := range managers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				mgr.loop()
			}()
		}
	}
	jp, err := newJobManager(cfg, managers, shutdownPending)
	if err != nil {
		log.Fatalf("failed to create dashapi connection %v", err)
	}
	stopJobs := jp.startLoop(&wg)

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

	wg.Add(1)
	go deprecateAssets(cfg, stop, &wg)

	select {
	case <-shutdownPending:
	case <-updatePending:
	}
	stopJobs() // Gracefully wait for the running jobs to finish.
	close(stop)
	wg.Wait()

	select {
	case <-shutdownPending:
	default:
		updater.UpdateAndRestart()
	}
}

func deprecateAssets(cfg *Config, stop chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	if cfg.DashboardAddr == "" || cfg.AssetStorage.IsEmpty() ||
		!cfg.AssetStorage.DoDeprecation {
		return
	}
	dash, err := dashapi.New(cfg.DashboardClient, cfg.DashboardAddr, cfg.DashboardKey)
	if err != nil {
		log.Fatalf("failed to create dashapi during asset deprecation: %v", err)
		return
	}
	storage, err := asset.StorageFromConfig(cfg.AssetStorage, dash)
	if err != nil {
		log.Errorf("failed to create asset storage during asset deprecation: %v", err)
		return
	}
loop:
	for {
		const sleepDuration = 6 * time.Hour
		select {
		case <-stop:
			break loop
		case <-time.After(sleepDuration):
		}
		log.Logf(1, "start asset deprecation")
		stats, err := storage.DeprecateAssets()
		if err != nil {
			log.Errorf("asset deprecation failed: %v", err)
		}
		log.Logf(0, "asset deprecation: needed=%d, existing=%d, deleted=%d",
			stats.Needed, stats.Existing, stats.Deleted)
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
		RPCPort:          30000,
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
	if cfg.AssetStorage != nil {
		if err := cfg.AssetStorage.Validate(); err != nil {
			return nil, fmt.Errorf("asset storage config error: %w", err)
		}
	}
	return cfg, nil
}

func loadManagerConfig(cfg *Config, mgr *ManagerConfig) error {
	managercfg, err := mgrconfig.LoadPartialData(mgr.ManagerConfig)
	if err != nil {
		return fmt.Errorf("manager config: %w", err)
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
	if mgr.CompilerType == "" {
		mgr.CompilerType = "gcc"
	}
	if mgr.Branch == "" {
		mgr.Branch = "master"
	}
	mgr.managercfg = managercfg
	managercfg.Syzkaller = filepath.FromSlash("syzkaller/current")
	if managercfg.HTTP == "" {
		managercfg.HTTP = fmt.Sprintf(":%v", cfg.ManagerPort)
		cfg.ManagerPort++
	}
	if managercfg.RPC == ":0" {
		managercfg.RPC = fmt.Sprintf(":%v", cfg.RPCPort)
		cfg.RPCPort++
	}
	mgr.testRPCPort = cfg.RPCPort
	cfg.RPCPort++
	// Note: we don't change Compiler/Ccache because it may be just "gcc" referring
	// to the system binary, or pkg/build/netbsd.go uses "g++" and "clang++" as special marks.
	mgr.Userspace = osutil.Abs(mgr.Userspace)
	mgr.KernelConfig = osutil.Abs(mgr.KernelConfig)
	mgr.KernelBaselineConfig = osutil.Abs(mgr.KernelBaselineConfig)
	mgr.KernelCmdline = osutil.Abs(mgr.KernelCmdline)
	mgr.KernelSysctl = osutil.Abs(mgr.KernelSysctl)
	if mgr.KernelConfig != "" && mgr.KernelBaselineConfig == "" {
		mgr.KernelBaselineConfig = inferBaselineConfig(mgr.KernelConfig)
	}
	if mgr.MaxKernelLagDays == 0 {
		mgr.MaxKernelLagDays = 30
	}
	if err := mgr.validate(cfg); err != nil {
		return err
	}

	if cfg.PatchVMConfigs[managercfg.Type] != nil {
		managercfg.VM, err = config.MergeJSONs(managercfg.VM, cfg.PatchVMConfigs[managercfg.Type])
		if err != nil {
			return fmt.Errorf("failed to patch manager %v's VM: %w", mgr.Name, err)
		}
	}
	return nil
}

func inferBaselineConfig(kernelConfig string) string {
	suffixPos := strings.LastIndex(kernelConfig, ".config")
	if suffixPos < 0 {
		return ""
	}
	candidate := kernelConfig[:suffixPos] + "-base.config"
	if !osutil.IsExist(candidate) {
		return ""
	}
	return candidate
}
