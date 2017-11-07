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
	name       string
	workDir    string
	kernelDir  string
	currentDir string
	latestDir  string
	compilerID string
	configTag  string
	cfg        *Config
	mgrcfg     *ManagerConfig
	cmd        *ManagerCmd
	dash       *dashapi.Dashboard
	stop       chan struct{}
}

func createManager(cfg *Config, mgrcfg *ManagerConfig, stop chan struct{}) *Manager {
	dir := osutil.Abs(filepath.Join("managers", mgrcfg.Name))
	if err := osutil.MkdirAll(dir); err != nil {
		Fatal(err)
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

	mgr := &Manager{
		name:       cfg.Name + "-" + mgrcfg.Name,
		workDir:    filepath.Join(dir, "workdir"),
		kernelDir:  filepath.Join(dir, "kernel"),
		currentDir: filepath.Join(dir, "current"),
		latestDir:  filepath.Join(dir, "latest"),
		compilerID: compilerID,
		configTag:  hash.String(configData),
		cfg:        cfg,
		mgrcfg:     mgrcfg,
		dash:       dash,
		stop:       stop,
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
				Logf(0, "%v: failed to poll: %v", mgr.name, err)
			} else {
				Logf(0, "%v: poll: %v", mgr.name, commit)
				if commit != lastCommit &&
					(latestInfo == nil ||
						commit != latestInfo.KernelCommit ||
						mgr.compilerID != latestInfo.CompilerID ||
						mgr.configTag != latestInfo.KernelConfigTag) {
					lastCommit = commit
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
								Logf(0, "%v: failed to read build info after build", mgr.name)
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
	Time            time.Time // when the build was done
	Tag             string    // unique tag combined from compiler id, kernel commit and config tag
	CompilerID      string    // compiler identity string (e.g. "gcc 7.1.1")
	KernelRepo      string
	KernelBranch    string
	KernelCommit    string // git hash of kernel checkout
	KernelConfigTag string // SHA1 hash of .config contents
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
	if err := kernel.Build(mgr.kernelDir, mgr.mgrcfg.Compiler, mgr.mgrcfg.Kernel_Config); err != nil {
		return fmt.Errorf("kernel build failed: %v", err)
	}

	// We first form the whole image in tmp dir and then rename it to latest.
	tmpDir := mgr.latestDir + ".tmp"
	if err := os.RemoveAll(tmpDir); err != nil {
		return fmt.Errorf("failed to remove tmp dir: %v", err)
	}
	if err := osutil.MkdirAll(tmpDir); err != nil {
		return fmt.Errorf("failed to create tmp dir: %v", err)
	}

	image := filepath.Join(tmpDir, "image")
	key := filepath.Join(tmpDir, "key")
	err = kernel.CreateImage(mgr.kernelDir, mgr.mgrcfg.Userspace,
		mgr.mgrcfg.Kernel_Cmdline, mgr.mgrcfg.Kernel_Sysctl, image, key)
	if err != nil {
		return fmt.Errorf("image build failed: %v", err)
	}
	// TODO(dvyukov): test that the image is good (boots and we can ssh into it).

	vmlinux := filepath.Join(mgr.kernelDir, "vmlinux")
	objDir := filepath.Join(tmpDir, "obj")
	osutil.MkdirAll(objDir)
	if err := os.Rename(vmlinux, filepath.Join(objDir, "vmlinux")); err != nil {
		return fmt.Errorf("failed to rename vmlinux file: %v", err)
	}
	kernelConfig := filepath.Join(tmpDir, "kernel.config")
	if err := osutil.CopyFile(mgr.mgrcfg.Kernel_Config, kernelConfig); err != nil {
		return err
	}

	var tagData []byte
	tagData = append(tagData, kernelCommit...)
	tagData = append(tagData, mgr.compilerID...)
	tagData = append(tagData, mgr.configTag...)
	info := &BuildInfo{
		Time:            time.Now(),
		Tag:             hash.String(tagData),
		CompilerID:      mgr.compilerID,
		KernelRepo:      mgr.mgrcfg.Repo,
		KernelBranch:    mgr.mgrcfg.Branch,
		KernelCommit:    kernelCommit,
		KernelConfigTag: mgr.configTag,
	}
	if err := config.SaveFile(filepath.Join(tmpDir, "tag"), info); err != nil {
		return fmt.Errorf("failed to write tag file: %v", err)
	}

	// Now try to replace latest with our tmp dir as atomically as we can get on Linux.
	if err := os.RemoveAll(mgr.latestDir); err != nil {
		return fmt.Errorf("failed to remove latest dir: %v", err)
	}
	return os.Rename(tmpDir, mgr.latestDir)
}

func (mgr *Manager) restartManager() {
	if !osutil.FilesExist(mgr.latestDir, imageFiles) {
		Logf(0, "%v: can't start manager, image files missing", mgr.name)
		return
	}
	if mgr.cmd != nil {
		mgr.cmd.Close()
		mgr.cmd = nil
	}
	if err := osutil.LinkFiles(mgr.latestDir, mgr.currentDir, imageFiles); err != nil {
		Logf(0, "%v: failed to create current image dir: %v", mgr.name, err)
		return
	}
	info, err := loadBuildInfo(mgr.currentDir)
	if err != nil {
		Logf(0, "%v: failed to load build info: %v", mgr.name, err)
		return
	}
	cfgFile, err := mgr.writeConfig(info)
	if err != nil {
		Logf(0, "%v: failed to create manager config: %v", mgr.name, err)
		return
	}
	if err := mgr.uploadBuild(info); err != nil {
		Logf(0, "%v: failed to upload build: %v", mgr.name, err)
		return
	}
	bin := filepath.FromSlash("syzkaller/current/bin/syz-manager")
	logFile := filepath.Join(mgr.currentDir, "manager.log")
	mgr.cmd = NewManagerCmd(mgr.name, logFile, bin, "-config", cfgFile)
}

func (mgr *Manager) writeConfig(info *BuildInfo) (string, error) {
	mgrcfg := mgrconfig.DefaultValues()
	err := config.LoadData(mgr.mgrcfg.Manager_Config, mgrcfg)
	if err != nil {
		return "", err
	}
	if mgrcfg.Target == "" {
		// TODO(dvyukov): temporal measure to handle upgrade.
		// Remove this once ci configs have targets.
		mgrcfg.Target = "linux/amd64"
		mgrcfg.TargetOS = "linux"
		mgrcfg.TargetVMArch = "amd64"
		mgrcfg.TargetArch = "amd64"
	}
	current := mgr.currentDir
	if mgr.dash != nil {
		mgrcfg.Tag = info.Tag

		mgrcfg.Dashboard_Client = mgr.dash.Client
		mgrcfg.Dashboard_Addr = mgr.dash.Addr
		mgrcfg.Dashboard_Key = mgr.dash.Key
	} else {
		// Dashboard identifies builds by unique tags that are combined
		// from kernel tag, compiler tag and config tag.
		// This combined tag is meaningless without dashboard,
		// so we use kenrel tag (commit tag) because it communicates
		// at least some useful information.
		mgrcfg.Tag = info.KernelCommit
	}
	mgrcfg.Name = mgr.name
	if mgr.cfg.Hub_Addr != "" {
		mgrcfg.Hub_Client = mgr.cfg.Name
		mgrcfg.Hub_Addr = mgr.cfg.Hub_Addr
		mgrcfg.Hub_Key = mgr.cfg.Hub_Key
	}
	mgrcfg.Workdir = mgr.workDir
	mgrcfg.Vmlinux = filepath.Join(current, "obj", "vmlinux")
	// Strictly saying this is somewhat racy as builder can concurrently
	// update the source, or even delete and re-clone. If this causes
	// problems, we need to make a copy of sources after build.
	mgrcfg.Kernel_Src = mgr.kernelDir
	mgrcfg.Syzkaller = filepath.FromSlash("syzkaller/current")
	mgrcfg.Image = filepath.Join(current, "image")
	mgrcfg.Sshkey = filepath.Join(current, "key")

	configFile := filepath.Join(current, "manager.cfg")
	if err := config.SaveFile(configFile, mgrcfg); err != nil {
		return "", err
	}
	if _, err := mgrconfig.LoadFile(configFile); err != nil {
		return "", err
	}
	return configFile, nil
}

func (mgr *Manager) uploadBuild(info *BuildInfo) error {
	if mgr.dash == nil {
		return nil
	}

	syzkallerCommit, _ := readTag(filepath.FromSlash("syzkaller/current/tag"))
	if syzkallerCommit == "" {
		return fmt.Errorf("no tag in syzkaller/current/tag")
	}
	kernelConfig, err := ioutil.ReadFile(filepath.Join(mgr.currentDir, "kernel.config"))
	if err != nil {
		return fmt.Errorf("failed to read kernel.config: %v", err)
	}
	mgrcfg := new(mgrconfig.Config)
	if err := config.LoadData(mgr.mgrcfg.Manager_Config, mgrcfg); err != nil {
		return fmt.Errorf("failed to load manager %v config: %v", mgr.name, err)
	}
	os, vmarch, arch, err := mgrconfig.SplitTarget(mgrcfg.Target)
	if err != nil {
		return fmt.Errorf("failed to load manager %v config: %v", mgr.name, err)
	}
	commits, err := mgr.pollCommits(info.KernelCommit)
	if err != nil {
		// This is not critical for operation.
		Logf(0, "%v: failed to poll commits: %v", mgr.name, err)
	}
	build := &dashapi.Build{
		Manager:         mgr.name,
		ID:              info.Tag,
		OS:              os,
		Arch:            arch,
		VMArch:          vmarch,
		SyzkallerCommit: syzkallerCommit,
		CompilerID:      info.CompilerID,
		KernelRepo:      info.KernelRepo,
		KernelBranch:    info.KernelBranch,
		KernelCommit:    info.KernelCommit,
		KernelConfig:    kernelConfig,
		Commits:         commits,
	}
	return mgr.dash.UploadBuild(build)
}

// pollCommits asks dashboard what commits it is interested in (i.e. fixes for
// open bugs) and returns subset of these commits that are present in a build
// on commit buildCommit.
func (mgr *Manager) pollCommits(buildCommit string) ([]string, error) {
	resp, err := mgr.dash.BuilderPoll(mgr.name)
	if err != nil || len(resp.PendingCommits) == 0 {
		return nil, err
	}
	commits, err := git.ListRecentCommits(mgr.kernelDir, buildCommit)
	if err != nil {
		return nil, err
	}
	m := make(map[string]bool, len(commits))
	for _, com := range commits {
		m[git.CanonicalizeCommit(com)] = true
	}
	var present []string
	for _, com := range resp.PendingCommits {
		if m[git.CanonicalizeCommit(com)] {
			present = append(present, com)
		}
	}
	return present, nil
}
