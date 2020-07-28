// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/build"
	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/gcs"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/vm"
)

// This is especially slightly longer than syzkaller rebuild period.
// If we set kernelRebuildPeriod = syzkallerRebuildPeriod and both are changed
// during that period (or around that period), we can rebuild kernel, restart
// manager and then instantly shutdown everything for syzkaller update.
// Instead we rebuild syzkaller, restart and then rebuild kernel.
const kernelRebuildPeriod = syzkallerRebuildPeriod + time.Hour

// List of required files in kernel build (contents of latest/current dirs).
var imageFiles = map[string]bool{
	"tag":           true,  // serialized BuildInfo
	"kernel.config": false, // kernel config used for build
	"image":         true,  // kernel image
	"kernel":        false,
	"initrd":        false,
	"key":           false, // root ssh key for the image
}

func init() {
	for _, arches := range targets.List {
		for _, arch := range arches {
			if arch.KernelObject != "" {
				imageFiles["obj/"+arch.KernelObject] = false
			}
		}
	}
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
	configData []byte
	cfg        *Config
	repo       vcs.Repo
	mgrcfg     *ManagerConfig
	managercfg *mgrconfig.Config
	cmd        *ManagerCmd
	dash       *dashapi.Dashboard
	stop       chan struct{}
}

func createManager(cfg *Config, mgrcfg *ManagerConfig, stop chan struct{}) (*Manager, error) {
	dir := osutil.Abs(filepath.Join("managers", mgrcfg.Name))
	if err := osutil.MkdirAll(dir); err != nil {
		log.Fatal(err)
	}
	if mgrcfg.RepoAlias == "" {
		mgrcfg.RepoAlias = mgrcfg.Repo
	}

	var dash *dashapi.Dashboard
	if cfg.DashboardAddr != "" && mgrcfg.DashboardClient != "" {
		dash = dashapi.New(mgrcfg.DashboardClient, cfg.DashboardAddr, mgrcfg.DashboardKey)
	}

	// Assume compiler and config don't change underneath us.
	compilerID, err := build.CompilerIdentity(mgrcfg.Compiler)
	if err != nil {
		return nil, err
	}
	var configData []byte
	if mgrcfg.KernelConfig != "" {
		if configData, err = ioutil.ReadFile(mgrcfg.KernelConfig); err != nil {
			return nil, err
		}
	}
	kernelDir := filepath.Join(dir, "kernel")
	repo, err := vcs.NewRepo(mgrcfg.managercfg.TargetOS, mgrcfg.managercfg.Type, kernelDir)
	if err != nil {
		log.Fatalf("failed to create repo for %v: %v", mgrcfg.Name, err)
	}

	mgr := &Manager{
		name:       mgrcfg.managercfg.Name,
		workDir:    filepath.Join(dir, "workdir"),
		kernelDir:  kernelDir,
		currentDir: filepath.Join(dir, "current"),
		latestDir:  filepath.Join(dir, "latest"),
		compilerID: compilerID,
		configTag:  hash.String(configData),
		configData: configData,
		cfg:        cfg,
		repo:       repo,
		mgrcfg:     mgrcfg,
		managercfg: mgrcfg.managercfg,
		dash:       dash,
		stop:       stop,
	}
	os.RemoveAll(mgr.currentDir)
	return mgr, nil
}

// Gates kernel builds.
// Kernel builds take whole machine, so we don't run more than one at a time.
// Also current image build script uses some global resources (/dev/nbd0) and can't run in parallel.
var kernelBuildSem = make(chan struct{}, 1)

func (mgr *Manager) loop() {
	lastCommit := ""
	nextBuildTime := time.Now()
	var managerRestartTime, coverUploadTime time.Time
	latestInfo := mgr.checkLatest()
	if latestInfo != nil && time.Since(latestInfo.Time) < kernelRebuildPeriod/2 && mgr.managercfg.TargetOS != "fuchsia" {
		// If we have a reasonably fresh build,
		// start manager straight away and don't rebuild kernel for a while.
		// Fuchsia is a special case: it builds with syz-executor, so if we just updated syzkaller, we need
		// to rebuild fuchsia as well.
		log.Logf(0, "%v: using latest image built on %v", mgr.name, latestInfo.KernelCommit)
		managerRestartTime = latestInfo.Time
		nextBuildTime = time.Now().Add(kernelRebuildPeriod)
		mgr.restartManager()
	} else if latestInfo != nil {
		log.Logf(0, "%v: latest image is on %v", mgr.name, latestInfo.KernelCommit)
	}

	ticker := time.NewTicker(buildRetryPeriod)
	defer ticker.Stop()

loop:
	for {
		if time.Since(nextBuildTime) >= 0 {
			var rebuildAfter time.Duration
			lastCommit, latestInfo, rebuildAfter = mgr.pollAndBuild(lastCommit, latestInfo)
			nextBuildTime = time.Now().Add(rebuildAfter)
		}
		if !coverUploadTime.IsZero() && time.Now().After(coverUploadTime) {
			coverUploadTime = time.Time{}
			if err := mgr.uploadCoverReport(); err != nil {
				mgr.Errorf("failed to upload cover report: %v", err)
			}
		}

		select {
		case <-mgr.stop:
			break loop
		default:
		}

		if latestInfo != nil && (latestInfo.Time != managerRestartTime || mgr.cmd == nil) {
			managerRestartTime = latestInfo.Time
			mgr.restartManager()
			if mgr.cmd != nil && mgr.managercfg.Cover && mgr.cfg.CoverUploadPath != "" {
				coverUploadTime = time.Now().Add(6 * time.Hour)
			}
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
	log.Logf(0, "%v: stopped", mgr.name)
}

func (mgr *Manager) pollAndBuild(lastCommit string, latestInfo *BuildInfo) (
	string, *BuildInfo, time.Duration) {
	rebuildAfter := buildRetryPeriod
	commit, err := mgr.repo.Poll(mgr.mgrcfg.Repo, mgr.mgrcfg.Branch)
	if err != nil {
		mgr.Errorf("failed to poll: %v", err)
	} else {
		log.Logf(0, "%v: poll: %v", mgr.name, commit.Hash)
		if commit.Hash != lastCommit &&
			(latestInfo == nil ||
				commit.Hash != latestInfo.KernelCommit ||
				mgr.compilerID != latestInfo.CompilerID ||
				mgr.configTag != latestInfo.KernelConfigTag) {
			lastCommit = commit.Hash
			select {
			case kernelBuildSem <- struct{}{}:
				log.Logf(0, "%v: building kernel...", mgr.name)
				if err := mgr.build(commit); err != nil {
					log.Logf(0, "%v: %v", mgr.name, err)
				} else {
					log.Logf(0, "%v: build successful, [re]starting manager", mgr.name)
					rebuildAfter = kernelRebuildPeriod
					latestInfo = mgr.checkLatest()
					if latestInfo == nil {
						mgr.Errorf("failed to read build info after build")
					}
				}
				<-kernelBuildSem
			case <-mgr.stop:
			}
		}
	}
	return lastCommit, latestInfo, rebuildAfter
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

func (mgr *Manager) build(kernelCommit *vcs.Commit) error {
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
	if err := config.SaveFile(filepath.Join(tmpDir, "tag"), info); err != nil {
		return fmt.Errorf("failed to write tag file: %v", err)
	}
	params := &build.Params{
		TargetOS:     mgr.managercfg.TargetOS,
		TargetArch:   mgr.managercfg.TargetVMArch,
		VMType:       mgr.managercfg.Type,
		KernelDir:    mgr.kernelDir,
		OutputDir:    tmpDir,
		Compiler:     mgr.mgrcfg.Compiler,
		UserspaceDir: mgr.mgrcfg.Userspace,
		CmdlineFile:  mgr.mgrcfg.KernelCmdline,
		SysctlFile:   mgr.mgrcfg.KernelSysctl,
		Config:       mgr.configData,
	}
	if _, err := build.Image(params); err != nil {
		rep := &report.Report{
			Title: fmt.Sprintf("%v build error", mgr.mgrcfg.RepoAlias),
		}
		switch err1 := err.(type) {
		case *build.KernelError:
			rep.Report = err1.Report
			rep.Output = err1.Output
			rep.Recipients = err1.Recipients
		case *osutil.VerboseError:
			rep.Report = []byte(err1.Title)
			rep.Output = err1.Output
		default:
			rep.Report = []byte(err.Error())
		}
		if err := mgr.reportBuildError(rep, info, tmpDir); err != nil {
			mgr.Errorf("failed to report image error: %v", err)
		}
		return fmt.Errorf("kernel build failed: %v", err)
	}

	if err := mgr.testImage(tmpDir, info); err != nil {
		return err
	}

	// Now try to replace latest with our tmp dir as atomically as we can get on Linux.
	if err := os.RemoveAll(mgr.latestDir); err != nil {
		return fmt.Errorf("failed to remove latest dir: %v", err)
	}
	return osutil.Rename(tmpDir, mgr.latestDir)
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
	log.Logf(0, "%v: testing image...", mgr.name)
	mgrcfg, err := mgr.createTestConfig(imageDir, info)
	if err != nil {
		return fmt.Errorf("failed to create manager config: %v", err)
	}
	defer os.RemoveAll(mgrcfg.Workdir)
	if !vm.AllowsOvercommit(mgrcfg.Type) {
		return nil // No support for creating machines out of thin air.
	}
	env, err := instance.NewEnv(mgrcfg)
	if err != nil {
		return err
	}
	const (
		testVMs     = 3
		maxFailures = 1
	)
	results, err := env.Test(testVMs, nil, nil, nil)
	if err != nil {
		return err
	}
	failures := 0
	var failureErr error
	for _, res := range results {
		if res == nil {
			continue
		}
		failures++
		switch err := res.(type) {
		case *instance.TestError:
			if rep := err.Report; rep != nil {
				what := "test"
				if err.Boot {
					what = "boot"
				}
				rep.Title = fmt.Sprintf("%v %v error: %v",
					mgr.mgrcfg.RepoAlias, what, rep.Title)
				if err := mgr.reportBuildError(rep, info, imageDir); err != nil {
					mgr.Errorf("failed to report image error: %v", err)
				}
			}
			if err.Boot {
				failureErr = fmt.Errorf("VM boot failed with: %v", err)
			} else {
				failureErr = fmt.Errorf("VM testing failed with: %v", err)
			}
		default:
			failureErr = res
		}
	}
	if failures > maxFailures {
		return failureErr
	}
	return nil
}

func (mgr *Manager) reportBuildError(rep *report.Report, info *BuildInfo, imageDir string) error {
	if mgr.dash == nil {
		log.Logf(0, "%v: image testing failed: %v\n\n%s\n\n%s",
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
			Title:      rep.Title,
			Corrupted:  false, // Otherwise they get merged with other corrupted reports.
			Recipients: rep.Recipients.ToDash(),
			Log:        rep.Output,
			Report:     rep.Report,
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
	if err := instance.SetConfigImage(mgrcfg, imageDir, true); err != nil {
		return nil, err
	}
	mgrcfg.KernelSrc = mgr.kernelDir
	if err := mgrconfig.Complete(mgrcfg); err != nil {
		return nil, fmt.Errorf("bad manager config: %v", err)
	}
	return mgrcfg, nil
}

func (mgr *Manager) writeConfig(buildTag string) (string, error) {
	mgrcfg := new(mgrconfig.Config)
	*mgrcfg = *mgr.managercfg

	if mgr.dash != nil {
		mgrcfg.DashboardClient = mgr.dash.Client
		mgrcfg.DashboardAddr = mgr.dash.Addr
		mgrcfg.DashboardKey = mgr.dash.Key
	}
	if mgr.cfg.HubAddr != "" {
		mgrcfg.HubClient = mgr.cfg.Name
		mgrcfg.HubAddr = mgr.cfg.HubAddr
		mgrcfg.HubKey = mgr.cfg.HubKey
	}
	mgrcfg.Tag = buildTag
	mgrcfg.Workdir = mgr.workDir
	if err := instance.SetConfigImage(mgrcfg, mgr.currentDir, false); err != nil {
		return "", err
	}
	// Strictly saying this is somewhat racy as builder can concurrently
	// update the source, or even delete and re-clone. If this causes
	// problems, we need to make a copy of sources after build.
	mgrcfg.KernelSrc = mgr.kernelDir
	if err := mgrconfig.Complete(mgrcfg); err != nil {
		return "", fmt.Errorf("bad manager config: %v", err)
	}
	configFile := filepath.Join(mgr.currentDir, "manager.cfg")
	if err := config.SaveFile(configFile, mgrcfg); err != nil {
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
	var kernelConfig []byte
	if kernelConfigFile := filepath.Join(imageDir, "kernel.config"); osutil.IsExist(kernelConfigFile) {
		var err error
		if kernelConfig, err = ioutil.ReadFile(kernelConfigFile); err != nil {
			return nil, fmt.Errorf("failed to read kernel.config: %v", err)
		}
	}
	// Resulting build depends on both kernel build tag and syzkaller commmit.
	// Also mix in build type, so that image error builds are not merged into normal builds.
	var tagData []byte
	tagData = append(tagData, info.Tag...)
	tagData = append(tagData, prog.GitRevisionBase...)
	tagData = append(tagData, typ...)
	build := &dashapi.Build{
		Manager:             mgr.name,
		ID:                  hash.String(tagData),
		OS:                  mgr.managercfg.TargetOS,
		Arch:                mgr.managercfg.TargetArch,
		VMArch:              mgr.managercfg.TargetVMArch,
		SyzkallerCommit:     prog.GitRevisionBase,
		SyzkallerCommitDate: prog.GitRevisionDate,
		CompilerID:          info.CompilerID,
		KernelRepo:          info.KernelRepo,
		KernelBranch:        info.KernelBranch,
		KernelCommit:        info.KernelCommit,
		KernelCommitTitle:   info.KernelCommitTitle,
		KernelCommitDate:    info.KernelCommitDate,
		KernelConfig:        kernelConfig,
	}
	return build, nil
}

// pollCommits asks dashboard what commits it is interested in (i.e. fixes for
// open bugs) and returns subset of these commits that are present in a build
// on commit buildCommit.
func (mgr *Manager) pollCommits(buildCommit string) ([]string, []dashapi.Commit, error) {
	resp, err := mgr.dash.BuilderPoll(mgr.name)
	if err != nil || len(resp.PendingCommits) == 0 && resp.ReportEmail == "" {
		return nil, nil, err
	}
	var present []string
	if len(resp.PendingCommits) != 0 {
		commits, err := mgr.repo.ListRecentCommits(buildCommit)
		if err != nil {
			return nil, nil, err
		}
		m := make(map[string]bool, len(commits))
		for _, com := range commits {
			m[vcs.CanonicalizeCommit(com)] = true
		}
		for _, com := range resp.PendingCommits {
			if m[vcs.CanonicalizeCommit(com)] {
				present = append(present, com)
			}
		}
	}
	var fixCommits []dashapi.Commit
	if resp.ReportEmail != "" {
		if !brokenRepo(mgr.mgrcfg.Repo) {
			commits, err := mgr.repo.ExtractFixTagsFromCommits(buildCommit, resp.ReportEmail)
			if err != nil {
				return nil, nil, err
			}
			for _, com := range commits {
				fixCommits = append(fixCommits, dashapi.Commit{
					Title:  com.Title,
					BugIDs: com.Tags,
					Date:   com.Date,
				})
			}
		}
	}
	return present, fixCommits, nil
}

func (mgr *Manager) uploadCoverReport() error {
	GCS, err := gcs.NewClient()
	if err != nil {
		return fmt.Errorf("failed to create GCS client: %v", err)
	}
	defer GCS.Close()
	addr := mgr.managercfg.HTTP
	if addr != "" && addr[0] == ':' {
		addr = "127.0.0.1" + addr // in case addr is ":port"
	}
	resp, err := http.Get(fmt.Sprintf("http://%v/cover", addr))
	if err != nil {
		return fmt.Errorf("failed to get report: %v", err)
	}
	defer resp.Body.Close()
	gcsPath := filepath.Join(mgr.cfg.CoverUploadPath, mgr.name+".html")
	gcsWriter, err := GCS.FileWriter(gcsPath)
	if err != nil {
		return fmt.Errorf("failed to create GCS writer: %v", err)
	}
	if _, err := io.Copy(gcsWriter, resp.Body); err != nil {
		gcsWriter.Close()
		return fmt.Errorf("failed to copy report: %v", err)
	}
	if err := gcsWriter.Close(); err != nil {
		return fmt.Errorf("failed to close gcs writer: %v", err)
	}
	return GCS.Publish(gcsPath)
}

// Errorf logs non-fatal error and sends it to dashboard.
func (mgr *Manager) Errorf(msg string, args ...interface{}) {
	log.Logf(0, mgr.name+": "+msg, args...)
	if mgr.dash != nil {
		mgr.dash.LogError(mgr.name, msg, args...)
	}
}
