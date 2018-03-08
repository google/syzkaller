// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/git"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/kernel"
	. "github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/syz-manager/mgrconfig"
)

// This is especially slightly longer than syzkaller rebuild period.
// If we set kernelRebuildPeriod = syzkallerRebuildPeriod and both are changed
// during that period (or around that period), we can rebuild kernel, restart
// manager and then instantly shutdown everything for syzkaller update.
// Instead we rebuild syzkaller, restart and then rebuild kernel.
const kernelRebuildPeriod = syzkallerRebuildPeriod + time.Hour

// List of required files in kernel build (contents of latest/current dirs).
var imageFiles = []string{
	"tag",           // serialized BuildInfo
	"kernel.config", // kernel config used for build
	"image",         // kernel image
	"key",           // root ssh key for the image
	"obj/vmlinux",   // vmlinux with debug info
}

// Manager represents a single syz-manager instance.
// Handles kernel polling, image rebuild and manager process management.
// As syzkaller builder, it maintains 2 builds:
//  - latest: latest known good kernel build
//  - current: currently used kernel build
type Manager struct {
	name            string
	workDir         string
	kernelDir       string
	currentDir      string
	latestDir       string
	compilerID      string
	syzkallerCommit string
	configTag       string
	cfg             *Config
	mgrcfg          *ManagerConfig
	managercfg      *mgrconfig.Config
	cmd             *ManagerCmd
	dash            *dashapi.Dashboard
	stop            chan struct{}
}

func createManager(cfg *Config, mgrcfg *ManagerConfig, stop chan struct{}) *Manager {
	dir := osutil.Abs(filepath.Join("managers", mgrcfg.Name))
	if err := osutil.MkdirAll(dir); err != nil {
		Fatal(err)
	}
	if mgrcfg.Repo_Alias == "" {
		mgrcfg.Repo_Alias = mgrcfg.Repo
	}

	var dash *dashapi.Dashboard
	if cfg.Dashboard_Addr != "" && mgrcfg.Dashboard_Client != "" {
		dash = dashapi.New(mgrcfg.Dashboard_Client, cfg.Dashboard_Addr, mgrcfg.Dashboard_Key)
	}

	// Assume compiler and config don't change underneath us.
	compilerID, err := kernel.CompilerIdentity(mgrcfg.Compiler)
	if err != nil {
		Fatal(err)
	}
	configData, err := ioutil.ReadFile(mgrcfg.Kernel_Config)
	if err != nil {
		Fatal(err)
	}
	syzkallerCommit, _ := readTag(filepath.FromSlash("syzkaller/current/tag"))
	if syzkallerCommit == "" {
		Fatalf("no tag in syzkaller/current/tag")
	}

	// Prepare manager config skeleton (other fields are filled in writeConfig).
	managercfg := mgrconfig.DefaultValues()
	if err := config.LoadData(mgrcfg.Manager_Config, managercfg); err != nil {
		Fatalf("failed to load manager %v config: %v", mgrcfg.Name, err)
	}
	managercfg.TargetOS, managercfg.TargetVMArch, managercfg.TargetArch, err = mgrconfig.SplitTarget(managercfg.Target)
	if err != nil {
		Fatalf("failed to load manager %v config: %v", mgrcfg.Name, err)
	}
	managercfg.Name = cfg.Name + "-" + mgrcfg.Name

	mgr := &Manager{
		name:            managercfg.Name,
		workDir:         filepath.Join(dir, "workdir"),
		kernelDir:       filepath.Join(dir, "kernel"),
		currentDir:      filepath.Join(dir, "current"),
		latestDir:       filepath.Join(dir, "latest"),
		compilerID:      compilerID,
		syzkallerCommit: syzkallerCommit,
		configTag:       hash.String(configData),
		cfg:             cfg,
		mgrcfg:          mgrcfg,
		managercfg:      managercfg,
		dash:            dash,
		stop:            stop,
	}
	os.RemoveAll(mgr.currentDir)
	return mgr
}

// Gates kernel builds.
// Kernel builds take whole machine, so we don't run more than one at a time.
// Also current image build script uses some global resources (/dev/nbd0) and can't run in parallel.
var kernelBuildSem = make(chan struct{}, 1)

func (mgr *Manager) loop() {
	lastCommit := ""
	nextBuildTime := time.Now()
	var managerRestartTime time.Time
	latestInfo := mgr.checkLatest()
	if latestInfo != nil && time.Since(latestInfo.Time) < kernelRebuildPeriod/2 {
		// If we have a reasonably fresh build,
		// start manager straight away and don't rebuild kernel for a while.
		Logf(0, "%v: using latest image built on %v", mgr.name, latestInfo.KernelCommit)
		managerRestartTime = latestInfo.Time
		nextBuildTime = time.Now().Add(kernelRebuildPeriod)
		mgr.restartManager()
	} else if latestInfo != nil {
		Logf(0, "%v: latest image is on %v", mgr.name, latestInfo.KernelCommit)
	}

	ticker := time.NewTicker(buildRetryPeriod)
	defer ticker.Stop()

loop:
	for {
		if time.Since(nextBuildTime) >= 0 {
			rebuildAfter := buildRetryPeriod
			commit, err := git.Poll(mgr.kernelDir, mgr.mgrcfg.Repo, mgr.mgrcfg.Branch)
			if err != nil {
				mgr.Errorf("failed to poll: %v", err)
			} else {
				Logf(0, "%v: poll: %v", mgr.name, commit.Hash)
				if commit.Hash != lastCommit &&
					(latestInfo == nil ||
						commit.Hash != latestInfo.KernelCommit ||
						mgr.compilerID != latestInfo.CompilerID ||
						mgr.configTag != latestInfo.KernelConfigTag) {
					lastCommit = commit.Hash
					select {
					case kernelBuildSem <- struct{}{}:
						Logf(0, "%v: building kernel...", mgr.name)
						if err := mgr.build(); err != nil {
							Logf(0, "%v: %v", mgr.name, err)
						} else {
							Logf(0, "%v: build successful, [re]starting manager", mgr.name)
							rebuildAfter = kernelRebuildPeriod
							latestInfo = mgr.checkLatest()
							if latestInfo == nil {
								mgr.Errorf("failed to read build info after build")
							}
						}
						<-kernelBuildSem
					case <-mgr.stop:
						break loop
					}
				}
			}
			nextBuildTime = time.Now().Add(rebuildAfter)
		}

		select {
		case <-mgr.stop:
			break loop
		default:
		}

		if latestInfo != nil && (latestInfo.Time != managerRestartTime || mgr.cmd == nil) {
			managerRestartTime = latestInfo.Time
			mgr.restartManager()
		}

		select {
		case <-ticker.C:
		case <-mgr.stop:
			break loop
		}
	}

	if mgr.cmd != nil {
		mgr.cmd.Close()
		mgr.cmd = nil
	}
	Logf(0, "%v: stopped", mgr.name)
}

// BuildInfo characterizes a kernel build.
type BuildInfo struct {
	Time              time.Time // when the build was done
	Tag               string    // unique tag combined from compiler id, kernel commit and config tag
	CompilerID        string    // compiler identity string (e.g. "gcc 7.1.1")
	KernelRepo        string
	KernelBranch      string
	KernelCommit      string // git hash of kernel checkout
	KernelCommitTitle string
	KernelCommitDate  time.Time
	KernelConfigTag   string // SHA1 hash of .config contents
}

func loadBuildInfo(dir string) (*BuildInfo, error) {
	info := new(BuildInfo)
	if err := config.LoadFile(filepath.Join(dir, "tag"), info); err != nil {
		return nil, err
	}
	return info, nil
}

// checkLatest checks if we have a good working latest build and returns its build info.
// If the build is missing/broken, nil is returned.
func (mgr *Manager) checkLatest() *BuildInfo {
	if !osutil.FilesExist(mgr.latestDir, imageFiles) {
		return nil
	}
	info, _ := loadBuildInfo(mgr.latestDir)
	return info
}

func (mgr *Manager) build() error {
	kernelCommit, err := git.HeadCommit(mgr.kernelDir)
	if err != nil {
		return fmt.Errorf("failed to get git HEAD commit: %v", err)
	}

	var tagData []byte
	tagData = append(tagData, mgr.name...)
	tagData = append(tagData, kernelCommit.Hash...)
	tagData = append(tagData, mgr.compilerID...)
	tagData = append(tagData, mgr.configTag...)
	info := &BuildInfo{
		Time:              time.Now(),
		Tag:               hash.String(tagData),
		CompilerID:        mgr.compilerID,
		KernelRepo:        mgr.mgrcfg.Repo,
		KernelBranch:      mgr.mgrcfg.Branch,
		KernelCommit:      kernelCommit.Hash,
		KernelCommitTitle: kernelCommit.Title,
		KernelCommitDate:  kernelCommit.Date,
		KernelConfigTag:   mgr.configTag,
	}

	// We first form the whole image in tmp dir and then rename it to latest.
	tmpDir := mgr.latestDir + ".tmp"
	if err := os.RemoveAll(tmpDir); err != nil {
		return fmt.Errorf("failed to remove tmp dir: %v", err)
	}
	if err := osutil.MkdirAll(tmpDir); err != nil {
		return fmt.Errorf("failed to create tmp dir: %v", err)
	}
	kernelConfig := filepath.Join(tmpDir, "kernel.config")
	if err := osutil.CopyFile(mgr.mgrcfg.Kernel_Config, kernelConfig); err != nil {
		return err
	}
	if err := config.SaveFile(filepath.Join(tmpDir, "tag"), info); err != nil {
		return fmt.Errorf("failed to write tag file: %v", err)
	}

	if err := kernel.Build(mgr.kernelDir, mgr.mgrcfg.Compiler, kernelConfig); err != nil {
		rep := &report.Report{
			Title:  fmt.Sprintf("%v build error", mgr.mgrcfg.Repo_Alias),
			Output: []byte(err.Error()),
		}
		if err := mgr.reportBuildError(rep, info, tmpDir); err != nil {
			mgr.Errorf("failed to report image error: %v", err)
		}
		return fmt.Errorf("kernel build failed: %v", err)
	}
	if err := osutil.CopyFile(filepath.Join(mgr.kernelDir, ".config"), kernelConfig); err != nil {
		return err
	}

	image := filepath.Join(tmpDir, "image")
	key := filepath.Join(tmpDir, "key")
	err = kernel.CreateImage(mgr.kernelDir, mgr.mgrcfg.Userspace,
		mgr.mgrcfg.Kernel_Cmdline, mgr.mgrcfg.Kernel_Sysctl, image, key)
	if err != nil {
		return fmt.Errorf("image build failed: %v", err)
	}

	vmlinux := filepath.Join(mgr.kernelDir, "vmlinux")
	objDir := filepath.Join(tmpDir, "obj")
	osutil.MkdirAll(objDir)
	if err := os.Rename(vmlinux, filepath.Join(objDir, "vmlinux")); err != nil {
		return fmt.Errorf("failed to rename vmlinux file: %v", err)
	}

	if err := mgr.testImage(tmpDir, info); err != nil {
		return err
	}

	// Now try to replace latest with our tmp dir as atomically as we can get on Linux.
	if err := os.RemoveAll(mgr.latestDir); err != nil {
		return fmt.Errorf("failed to remove latest dir: %v", err)
	}
	return os.Rename(tmpDir, mgr.latestDir)
}

func (mgr *Manager) restartManager() {
	if !osutil.FilesExist(mgr.latestDir, imageFiles) {
		mgr.Errorf("can't start manager, image files missing")
		return
	}
	if mgr.cmd != nil {
		mgr.cmd.Close()
		mgr.cmd = nil
	}
	if err := osutil.LinkFiles(mgr.latestDir, mgr.currentDir, imageFiles); err != nil {
		mgr.Errorf("failed to create current image dir: %v", err)
		return
	}
	info, err := loadBuildInfo(mgr.currentDir)
	if err != nil {
		mgr.Errorf("failed to load build info: %v", err)
		return
	}
	buildTag, err := mgr.uploadBuild(info, mgr.currentDir)
	if err != nil {
		mgr.Errorf("failed to upload build: %v", err)
		return
	}
	cfgFile, err := mgr.writeConfig(buildTag)
	if err != nil {
		mgr.Errorf("failed to create manager config: %v", err)
		return
	}
	bin := filepath.FromSlash("syzkaller/current/bin/syz-manager")
	logFile := filepath.Join(mgr.currentDir, "manager.log")
	mgr.cmd = NewManagerCmd(mgr.name, logFile, mgr.Errorf, bin, "-config", cfgFile)
}

func (mgr *Manager) testImage(imageDir string, info *BuildInfo) error {
	Logf(0, "%v: testing image...", mgr.name)
	mgrcfg, err := mgr.createTestConfig(imageDir, info)
	if err != nil {
		return fmt.Errorf("failed to create manager config: %v", err)
	}
	switch typ := mgrcfg.Type; typ {
	case "gce", "qemu":
	default:
		// Other types don't support creating machines out of thin air.
		return nil
	}
	if err := osutil.MkdirAll(mgrcfg.Workdir); err != nil {
		return fmt.Errorf("failed to create tmp dir: %v", err)
	}
	defer os.RemoveAll(mgrcfg.Workdir)

	inst, reporter, rep, err := bootInstance(mgrcfg)
	if err != nil {
		return err
	}
	if rep != nil {
		rep.Title = fmt.Sprintf("%v boot error: %v", mgr.mgrcfg.Repo_Alias, rep.Title)
		if err := mgr.reportBuildError(rep, info, imageDir); err != nil {
			mgr.Errorf("failed to report image error: %v", err)
		}
		return fmt.Errorf("VM boot failed with: %v", rep.Title)
	}
	defer inst.Close()
	rep, err = testInstance(inst, reporter, mgrcfg)
	if err != nil {
		return err
	}
	if rep != nil {
		rep.Title = fmt.Sprintf("%v test error: %v", mgr.mgrcfg.Repo_Alias, rep.Title)
		if err := mgr.reportBuildError(rep, info, imageDir); err != nil {
			mgr.Errorf("failed to report image error: %v", err)
		}
		return fmt.Errorf("VM testing failed with: %v", rep.Title)
	}
	return nil
}

func (mgr *Manager) reportBuildError(rep *report.Report, info *BuildInfo, imageDir string) error {
	if mgr.dash == nil {
		Logf(0, "%v: image testing failed: %v\n\n%s\n\n%s\n",
			mgr.name, rep.Title, rep.Report, rep.Output)
		return nil
	}
	build, err := mgr.createDashboardBuild(info, imageDir, "error")
	if err != nil {
		return err
	}
	req := &dashapi.BuildErrorReq{
		Build: *build,
		Crash: dashapi.Crash{
			Title:       rep.Title,
			Corrupted:   false, // Otherwise they get merged with other corrupted reports.
			Maintainers: rep.Maintainers,
			Log:         rep.Output,
			Report:      rep.Report,
		},
	}
	return mgr.dash.ReportBuildError(req)
}

func (mgr *Manager) createTestConfig(imageDir string, info *BuildInfo) (*mgrconfig.Config, error) {
	mgrcfg := new(mgrconfig.Config)
	*mgrcfg = *mgr.managercfg
	mgrcfg.Name += "-test"
	mgrcfg.Tag = info.KernelCommit
	mgrcfg.Workdir = filepath.Join(imageDir, "workdir")
	mgrcfg.Vmlinux = filepath.Join(imageDir, "obj", "vmlinux")
	mgrcfg.Image = filepath.Join(imageDir, "image")
	mgrcfg.SSHKey = filepath.Join(imageDir, "key")
	mgrcfg.Kernel_Src = mgr.kernelDir
	mgrcfg.Syzkaller = filepath.FromSlash("syzkaller/current")
	cfgdata, err := config.SaveData(mgrcfg)
	if err != nil {
		return nil, fmt.Errorf("failed to save manager config: %v", err)
	}
	mgrcfg, err = mgrconfig.LoadData(cfgdata)
	if err != nil {
		return nil, fmt.Errorf("failed to reload manager config: %v", err)
	}
	return mgrcfg, nil
}

func (mgr *Manager) writeConfig(buildTag string) (string, error) {
	mgrcfg := new(mgrconfig.Config)
	*mgrcfg = *mgr.managercfg

	if mgr.dash != nil {
		mgrcfg.Dashboard_Client = mgr.dash.Client
		mgrcfg.Dashboard_Addr = mgr.dash.Addr
		mgrcfg.Dashboard_Key = mgr.dash.Key
	}
	if mgr.cfg.Hub_Addr != "" {
		mgrcfg.Hub_Client = mgr.cfg.Name
		mgrcfg.Hub_Addr = mgr.cfg.Hub_Addr
		mgrcfg.Hub_Key = mgr.cfg.Hub_Key
	}
	mgrcfg.Tag = buildTag
	mgrcfg.Workdir = mgr.workDir
	mgrcfg.Vmlinux = filepath.Join(mgr.currentDir, "obj", "vmlinux")
	// Strictly saying this is somewhat racy as builder can concurrently
	// update the source, or even delete and re-clone. If this causes
	// problems, we need to make a copy of sources after build.
	mgrcfg.Kernel_Src = mgr.kernelDir
	mgrcfg.Syzkaller = filepath.FromSlash("syzkaller/current")
	mgrcfg.Image = filepath.Join(mgr.currentDir, "image")
	mgrcfg.SSHKey = filepath.Join(mgr.currentDir, "key")

	configFile := filepath.Join(mgr.currentDir, "manager.cfg")
	if err := config.SaveFile(configFile, mgrcfg); err != nil {
		return "", err
	}
	if _, err := mgrconfig.LoadFile(configFile); err != nil {
		return "", err
	}
	return configFile, nil
}

func (mgr *Manager) uploadBuild(info *BuildInfo, imageDir string) (string, error) {
	if mgr.dash == nil {
		// Dashboard identifies builds by unique tags that are combined
		// from kernel tag, compiler tag and config tag.
		// This combined tag is meaningless without dashboard,
		// so we use kenrel tag (commit tag) because it communicates
		// at least some useful information.
		return info.KernelCommit, nil
	}

	build, err := mgr.createDashboardBuild(info, imageDir, "normal")
	if err != nil {
		return "", err
	}
	commitTitles, fixCommits, err := mgr.pollCommits(info.KernelCommit)
	if err != nil {
		// This is not critical for operation.
		mgr.Errorf("failed to poll commits: %v", err)
	}
	build.Commits = commitTitles
	build.FixCommits = fixCommits
	if err := mgr.dash.UploadBuild(build); err != nil {
		return "", err
	}
	return build.ID, nil
}

func (mgr *Manager) createDashboardBuild(info *BuildInfo, imageDir, typ string) (*dashapi.Build, error) {
	kernelConfig, err := ioutil.ReadFile(filepath.Join(imageDir, "kernel.config"))
	if err != nil {
		return nil, fmt.Errorf("failed to read kernel.config: %v", err)
	}
	// Resulting build depends on both kernel build tag and syzkaller commmit.
	// Also mix in build type, so that image error builds are not merged into normal builds.
	var tagData []byte
	tagData = append(tagData, info.Tag...)
	tagData = append(tagData, mgr.syzkallerCommit...)
	tagData = append(tagData, typ...)
	build := &dashapi.Build{
		Manager:           mgr.name,
		ID:                hash.String(tagData),
		OS:                mgr.managercfg.TargetOS,
		Arch:              mgr.managercfg.TargetArch,
		VMArch:            mgr.managercfg.TargetVMArch,
		SyzkallerCommit:   mgr.syzkallerCommit,
		CompilerID:        info.CompilerID,
		KernelRepo:        info.KernelRepo,
		KernelBranch:      info.KernelBranch,
		KernelCommit:      info.KernelCommit,
		KernelCommitTitle: info.KernelCommitTitle,
		KernelCommitDate:  info.KernelCommitDate,
		KernelConfig:      kernelConfig,
	}
	return build, nil
}

// pollCommits asks dashboard what commits it is interested in (i.e. fixes for
// open bugs) and returns subset of these commits that are present in a build
// on commit buildCommit.
func (mgr *Manager) pollCommits(buildCommit string) ([]string, []dashapi.FixCommit, error) {
	resp, err := mgr.dash.BuilderPoll(mgr.name)
	if err != nil || len(resp.PendingCommits) == 0 {
		return nil, nil, err
	}
	var present []string
	if len(resp.PendingCommits) != 0 {
		commits, err := git.ListRecentCommits(mgr.kernelDir, buildCommit)
		if err != nil {
			return nil, nil, err
		}
		m := make(map[string]bool, len(commits))
		for _, com := range commits {
			m[git.CanonicalizeCommit(com)] = true
		}
		for _, com := range resp.PendingCommits {
			if m[git.CanonicalizeCommit(com)] {
				present = append(present, com)
			}
		}
	}
	var fixCommits []dashapi.FixCommit
	if resp.ReportEmail != "" {
		// TODO(dvyukov): mmots contains weird squashed commits titled "linux-next" or "origin",
		// which contain hundreds of other commits. This makes fix attribution totally broken.
		if mgr.mgrcfg.Repo != "git://git.cmpxchg.org/linux-mmots.git" {
			commits, err := git.ExtractFixTagsFromCommits(mgr.kernelDir, buildCommit, resp.ReportEmail)
			if err != nil {
				return nil, nil, err
			}
			for _, com := range commits {
				fixCommits = append(fixCommits, dashapi.FixCommit{
					Title: com.Title,
					BugID: com.Tag,
				})
			}
		}
	}
	return present, fixCommits, nil
}

// Errorf logs non-fatal error and sends it to dashboard.
func (mgr *Manager) Errorf(msg string, args ...interface{}) {
	Logf(0, mgr.name+": "+msg, args...)
	if mgr.dash != nil {
		mgr.dash.LogError(mgr.name, msg, args...)
	}
}
