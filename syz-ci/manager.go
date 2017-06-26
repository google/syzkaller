// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/fileutil"
	"github.com/google/syzkaller/pkg/git"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/kernel"
	. "github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/syz-dash/dashboard"
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
	"kernel.tag",    // git hash of kernel checkout
	"compiler.tag",  // compiler identity string (e.g. "gcc 7.1.1")
	"kernel.config", // kernel config used for the build (identified with SHA1 hash of contents)
	"tag",           // SHA1 hash of the previous 3 tags (this is what uniquely identifies the build)
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
	name        string
	workDir     string
	kernelDir   string
	currentDir  string
	latestDir   string
	compilerTag string
	configTag   string
	cfg         *Config
	mgrcfg      *ManagerConfig
	cmd         *ManagerCmd
	dash        *dashboard.Dashboard
	stop        chan struct{}
}

func createManager(dash *dashboard.Dashboard, cfg *Config, mgrcfg *ManagerConfig, stop chan struct{}) *Manager {
	dir := osutil.Abs(filepath.Join("managers", mgrcfg.Name))
	if err := os.MkdirAll(dir, osutil.DefaultDirPerm); err != nil {
		Fatal(err)
	}

	// Assume compiler and config don't change underneath us.
	compilerTag, err := kernel.CompilerIdentity(mgrcfg.Compiler)
	if err != nil {
		Fatal(err)
	}
	configData, err := ioutil.ReadFile(mgrcfg.Kernel_Config)
	if err != nil {
		Fatal(err)
	}

	mgr := &Manager{
		name:        mgrcfg.Name,
		workDir:     filepath.Join(dir, "workdir"),
		kernelDir:   filepath.Join(dir, "kernel"),
		currentDir:  filepath.Join(dir, "current"),
		latestDir:   filepath.Join(dir, "latest"),
		compilerTag: compilerTag,
		configTag:   hash.String(configData),
		cfg:         cfg,
		mgrcfg:      mgrcfg,
		dash:        dash,
		stop:        stop,
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
	latestTime, latestKernelTag, latestCompilerTag, latestConfigTag := mgr.checkLatest()
	if time.Since(latestTime) < kernelRebuildPeriod/2 {
		// If we have a reasonably fresh build,
		// start manager straight away and don't rebuild kernel for a while.
		Logf(0, "%v: using latest image built on %v", mgr.name, latestKernelTag)
		managerRestartTime = latestTime
		nextBuildTime = time.Now().Add(kernelRebuildPeriod)
		mgr.restartManager()
	} else {
		Logf(0, "%v: latest image is on %v", mgr.name, formatTag(latestKernelTag))
	}

	ticker := time.NewTicker(kernelRebuildPeriod)
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
					(commit != latestKernelTag ||
						mgr.compilerTag != latestCompilerTag ||
						mgr.configTag != latestConfigTag) {
					lastCommit = commit
					select {
					case kernelBuildSem <- struct{}{}:
						Logf(0, "%v: building kernel...", mgr.name)
						if err := mgr.build(); err != nil {
							Logf(0, "%v: %v", mgr.name, err)
						} else {
							Logf(0, "%v: build successful, [re]starting manager", mgr.name)
							rebuildAfter = kernelRebuildPeriod
							latestTime, latestKernelTag, latestCompilerTag, latestConfigTag = mgr.checkLatest()
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

		if managerRestartTime != latestTime {
			managerRestartTime = latestTime
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

// checkLatest checks if we have a good working latest build
// and returns its kernel/compiler/config tags.
// If the build is missing/broken, zero mod time is returned.
func (mgr *Manager) checkLatest() (mod time.Time, kernelTag, compilerTag, configTag string) {
	if !osutil.FilesExist(mgr.latestDir, imageFiles) {
		return
	}
	configData, err := ioutil.ReadFile(filepath.Join(mgr.latestDir, "kernel.config"))
	if err != nil {
		return
	}
	configTag = hash.String(configData)
	compilerTag, _ = readTag(filepath.Join(mgr.latestDir, "compiler.tag"))
	if compilerTag == "" {
		return
	}
	kernelTag, mod = readTag(filepath.Join(mgr.latestDir, "kernel.tag"))
	return
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
	if err := os.MkdirAll(tmpDir, osutil.DefaultDirPerm); err != nil {
		return fmt.Errorf("failed to create tmp dir: %v", err)
	}

	image := filepath.Join(tmpDir, "image")
	key := filepath.Join(tmpDir, "key")
	if err := kernel.CreateImage(mgr.kernelDir, mgr.mgrcfg.Userspace, image, key); err != nil {
		return fmt.Errorf("image build failed: %v", err)
	}
	// TODO(dvyukov): test that the image is good (boots and we can ssh into it).

	vmlinux := filepath.Join(mgr.kernelDir, "vmlinux")
	objDir := filepath.Join(tmpDir, "obj")
	os.MkdirAll(objDir, osutil.DefaultDirPerm)
	if err := os.Rename(vmlinux, filepath.Join(objDir, "vmlinux")); err != nil {
		return fmt.Errorf("failed to rename vmlinux file: %v", err)
	}
	kernelConfig := filepath.Join(tmpDir, "kernel.config")
	if err := fileutil.CopyFile(mgr.mgrcfg.Kernel_Config, kernelConfig); err != nil {
		return err
	}

	writeTagFile := func(filename, data string) error {
		f := filepath.Join(tmpDir, filename)
		if err := ioutil.WriteFile(f, []byte(data), osutil.DefaultFilePerm); err != nil {
			return fmt.Errorf("failed to write tag file: %v", err)
		}
		return nil
	}
	if err := writeTagFile("kernel.tag", kernelCommit); err != nil {
		return err
	}
	if err := writeTagFile("compiler.tag", mgr.compilerTag); err != nil {
		return err
	}

	var tag []byte
	tag = append(tag, kernelCommit...)
	tag = append(tag, mgr.configTag...)
	tag = append(tag, mgr.compilerTag...)
	if err := writeTagFile("tag", hash.String(tag)); err != nil {
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
	cfgFile, err := mgr.writeConfig()
	if err != nil {
		Logf(0, "%v: failed to create manager config: %v", mgr.name, err)
		return
	}
	bin := filepath.FromSlash("syzkaller/current/bin/syz-manager")
	logFile := filepath.Join(mgr.currentDir, "manager.log")
	mgr.cmd = NewManagerCmd(mgr.name, logFile, bin, "-config", cfgFile)
}

func (mgr *Manager) writeConfig() (string, error) {
	mgrcfg := &mgrconfig.Config{
		Cover:     true,
		Reproduce: true,
		Sandbox:   "setuid",
		Rpc:       "localhost:0",
		Procs:     1,
	}
	err := config.LoadData(mgr.mgrcfg.Manager_Config, mgrcfg)
	if err != nil {
		return "", err
	}
	current := mgr.currentDir
	// TODO(dvyukov): we use kernel.tag because dashboard does not support build info yet.
	// Later we should use tag file because it identifies kernel+compiler+config.
	tag, err := ioutil.ReadFile(filepath.Join(current, "kernel.tag"))
	if err != nil {
		return "", fmt.Errorf("failed to read tag file: %v", err)
	}
	mgrcfg.Name = mgr.cfg.Name + "-" + mgr.name
	mgrcfg.Hub_Addr = mgr.cfg.Hub_Addr
	mgrcfg.Hub_Key = mgr.cfg.Hub_Key
	mgrcfg.Dashboard_Addr = mgr.cfg.Dashboard_Addr
	mgrcfg.Dashboard_Key = mgr.cfg.Dashboard_Key
	mgrcfg.Workdir = mgr.workDir
	mgrcfg.Vmlinux = filepath.Join(current, "obj", "vmlinux")
	mgrcfg.Tag = string(tag)
	mgrcfg.Syzkaller = filepath.FromSlash("syzkaller/current")
	mgrcfg.Image = filepath.Join(current, "image")
	mgrcfg.Sshkey = filepath.Join(current, "key")

	configFile := filepath.Join(current, "manager.cfg")
	if err := config.SaveFile(configFile, mgrcfg); err != nil {
		return "", err
	}
	if _, _, err := mgrconfig.LoadFile(configFile); err != nil {
		return "", err
	}
	return configFile, nil
}
