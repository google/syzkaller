// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/asset"
	"github.com/google/syzkaller/pkg/build"
	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/cover"
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
//   - latest: latest known good kernel build
//   - current: currently used kernel build
type Manager struct {
	name           string
	workDir        string
	kernelBuildDir string
	kernelSrcDir   string
	currentDir     string
	latestDir      string
	configTag      string
	configData     []byte
	cfg            *Config
	repo           vcs.Repo
	mgrcfg         *ManagerConfig
	managercfg     *mgrconfig.Config
	cmd            *ManagerCmd
	dash           ManagerDashapi
	debugStorage   bool
	storage        *asset.Storage
	stop           chan struct{}
	debug          bool
	lastBuild      *dashapi.Build
	buildFailed    bool
}

type ManagerDashapi interface {
	ReportBuildError(req *dashapi.BuildErrorReq) error
	UploadBuild(build *dashapi.Build) error
	BuilderPoll(manager string) (*dashapi.BuilderPollResp, error)
	LogError(name, msg string, args ...interface{})
	CommitPoll() (*dashapi.CommitPollResp, error)
	UploadCommits(commits []dashapi.Commit) error
}

func createManager(cfg *Config, mgrcfg *ManagerConfig, stop chan struct{},
	debug bool) (*Manager, error) {
	dir := osutil.Abs(filepath.Join("managers", mgrcfg.Name))
	err := osutil.MkdirAll(dir)
	if err != nil {
		log.Fatal(err)
	}
	if mgrcfg.RepoAlias == "" {
		mgrcfg.RepoAlias = mgrcfg.Repo
	}

	var dash *dashapi.Dashboard
	if cfg.DashboardAddr != "" && mgrcfg.DashboardClient != "" {
		dash, err = dashapi.New(mgrcfg.DashboardClient, cfg.DashboardAddr, mgrcfg.DashboardKey)
		if err != nil {
			return nil, err
		}
	}
	var assetStorage *asset.Storage
	if !cfg.AssetStorage.IsEmpty() {
		assetStorage, err = asset.StorageFromConfig(cfg.AssetStorage, dash)
		if err != nil {
			log.Fatalf("failed to create asset storage: %v", err)
		}
	}
	var configData []byte
	if mgrcfg.KernelConfig != "" {
		if configData, err = os.ReadFile(mgrcfg.KernelConfig); err != nil {
			return nil, err
		}
	}
	kernelDir := filepath.Join(dir, "kernel")
	repo, err := vcs.NewRepo(mgrcfg.managercfg.TargetOS, mgrcfg.managercfg.Type, kernelDir)
	if err != nil {
		log.Fatalf("failed to create repo for %v: %v", mgrcfg.Name, err)
	}

	mgr := &Manager{
		name:           mgrcfg.managercfg.Name,
		workDir:        filepath.Join(dir, "workdir"),
		kernelSrcDir:   path.Join(kernelDir, mgrcfg.KernelSrcSuffix),
		kernelBuildDir: kernelDir,
		currentDir:     filepath.Join(dir, "current"),
		latestDir:      filepath.Join(dir, "latest"),
		configTag:      hash.String(configData),
		configData:     configData,
		cfg:            cfg,
		repo:           repo,
		mgrcfg:         mgrcfg,
		managercfg:     mgrcfg.managercfg,
		dash:           dash,
		storage:        assetStorage,
		debugStorage:   !cfg.AssetStorage.IsEmpty() && cfg.AssetStorage.Debug,
		stop:           stop,
		debug:          debug,
	}

	os.RemoveAll(mgr.currentDir)
	return mgr, nil
}

// Gates kernel builds, syzkaller builds and coverage report generation.
// Kernel builds take whole machine, so we don't run more than one at a time.
// Also current image build script uses some global resources (/dev/nbd0) and can't run in parallel.
var buildSem = instance.NewSemaphore(1)

// Gates tests that require extra VMs.
// Currently we overcommit instances in such cases, so we'd like to minimize the number of
// simultaneous env.Test calls.
var testSem = instance.NewSemaphore(1)

const fuzzingMinutesBeforeCover = 360

func (mgr *Manager) loop() {
	lastCommit := ""
	nextBuildTime := time.Now()
	var managerRestartTime, artifactUploadTime time.Time
	latestInfo := mgr.checkLatest()
	if latestInfo != nil && time.Since(latestInfo.Time) < kernelRebuildPeriod/2 &&
		mgr.managercfg.TargetOS != targets.Fuchsia {
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
		if !artifactUploadTime.IsZero() && time.Now().After(artifactUploadTime) {
			artifactUploadTime = time.Time{}
			if err := mgr.uploadCoverReport(); err != nil {
				mgr.Errorf("failed to upload cover report: %v", err)
			}
			if err := mgr.uploadCoverStat(fuzzingMinutesBeforeCover); err != nil {
				mgr.Errorf("failed to upload coverage stat: %v", err)
			}
			if err := mgr.uploadCorpus(); err != nil {
				mgr.Errorf("failed to upload corpus: %v", err)
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
			if mgr.cmd != nil {
				artifactUploadTime = time.Now().Add(fuzzingMinutesBeforeCover * time.Minute)
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
		mgr.buildFailed = true
		mgr.Errorf("failed to poll: %v", err)
	} else {
		log.Logf(0, "%v: poll: %v", mgr.name, commit.Hash)
		needsUpdate := (latestInfo == nil ||
			commit.Hash != latestInfo.KernelCommit ||
			mgr.configTag != latestInfo.KernelConfigTag)
		mgr.buildFailed = needsUpdate
		if commit.Hash != lastCommit && needsUpdate {
			lastCommit = commit.Hash
			select {
			case <-buildSem.WaitC():
				log.Logf(0, "%v: building kernel...", mgr.name)
				if err := mgr.build(commit); err != nil {
					log.Logf(0, "%v: %v", mgr.name, err)
				} else {
					log.Logf(0, "%v: build successful, [re]starting manager", mgr.name)
					mgr.buildFailed = false
					rebuildAfter = kernelRebuildPeriod
					latestInfo = mgr.checkLatest()
					if latestInfo == nil {
						mgr.Errorf("failed to read build info after build")
					}
				}
				buildSem.Signal()
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

func (mgr *Manager) createBuildInfo(kernelCommit *vcs.Commit, compilerID string) *BuildInfo {
	var tagData []byte
	tagData = append(tagData, mgr.name...)
	tagData = append(tagData, kernelCommit.Hash...)
	tagData = append(tagData, compilerID...)
	tagData = append(tagData, mgr.configTag...)
	return &BuildInfo{
		Time:              time.Now(),
		Tag:               hash.String(tagData),
		CompilerID:        compilerID,
		KernelRepo:        mgr.mgrcfg.Repo,
		KernelBranch:      mgr.mgrcfg.Branch,
		KernelCommit:      kernelCommit.Hash,
		KernelCommitTitle: kernelCommit.Title,
		KernelCommitDate:  kernelCommit.CommitDate,
		KernelConfigTag:   mgr.configTag,
	}
}

func (mgr *Manager) build(kernelCommit *vcs.Commit) error {
	// We first form the whole image in tmp dir and then rename it to latest.
	tmpDir := mgr.latestDir + ".tmp"
	if err := os.RemoveAll(tmpDir); err != nil {
		return fmt.Errorf("failed to remove tmp dir: %w", err)
	}
	if err := osutil.MkdirAll(tmpDir); err != nil {
		return fmt.Errorf("failed to create tmp dir: %w", err)
	}
	params := build.Params{
		TargetOS:     mgr.managercfg.TargetOS,
		TargetArch:   mgr.managercfg.TargetVMArch,
		VMType:       mgr.managercfg.Type,
		KernelDir:    mgr.kernelBuildDir,
		OutputDir:    tmpDir,
		Compiler:     mgr.mgrcfg.Compiler,
		Linker:       mgr.mgrcfg.Linker,
		Ccache:       mgr.mgrcfg.Ccache,
		UserspaceDir: mgr.mgrcfg.Userspace,
		CmdlineFile:  mgr.mgrcfg.KernelCmdline,
		SysctlFile:   mgr.mgrcfg.KernelSysctl,
		Config:       mgr.configData,
		Build:        mgr.mgrcfg.Build,
	}
	details, err := build.Image(params)
	info := mgr.createBuildInfo(kernelCommit, details.CompilerID)
	if err != nil {
		rep := &report.Report{
			Title: fmt.Sprintf("%v build error", mgr.mgrcfg.RepoAlias),
		}
		var kernelError *build.KernelError
		var verboseError *osutil.VerboseError
		switch {
		case errors.As(err, &kernelError):
			rep.Report = kernelError.Report
			rep.Output = kernelError.Output
			rep.Recipients = kernelError.Recipients
		case errors.As(err, &verboseError):
			rep.Report = []byte(verboseError.Title)
			rep.Output = verboseError.Output
		default:
			rep.Report = []byte(err.Error())
		}
		if err := mgr.reportBuildError(rep, info, tmpDir); err != nil {
			mgr.Errorf("failed to report image error: %v", err)
		}
		return fmt.Errorf("kernel build failed: %w", err)
	}

	if err := config.SaveFile(filepath.Join(tmpDir, "tag"), info); err != nil {
		return fmt.Errorf("failed to write tag file: %w", err)
	}

	if err := mgr.testImage(tmpDir, info); err != nil {
		return err
	}

	// Now try to replace latest with our tmp dir as atomically as we can get on Linux.
	if err := os.RemoveAll(mgr.latestDir); err != nil {
		return fmt.Errorf("failed to remove latest dir: %w", err)
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
	daysSinceCommit := time.Since(info.KernelCommitDate).Hours() / 24
	if mgr.buildFailed && daysSinceCommit > float64(mgr.mgrcfg.MaxKernelLagDays) {
		log.Logf(0, "%s: the kernel is now too old (%.1f days since last commit), fuzzing is stopped",
			mgr.name, daysSinceCommit)
		return
	}
	cfgFile, err := mgr.writeConfig(buildTag)
	if err != nil {
		mgr.Errorf("failed to create manager config: %v", err)
		return
	}
	bin := filepath.FromSlash("syzkaller/current/bin/syz-manager")
	logFile := filepath.Join(mgr.currentDir, "manager.log")
	args := []string{"-config", cfgFile, "-vv", "1"}
	if mgr.debug {
		args = append(args, "-debug")
	}
	mgr.cmd = NewManagerCmd(mgr.name, logFile, mgr.Errorf, bin, args...)
}

func (mgr *Manager) testImage(imageDir string, info *BuildInfo) error {
	log.Logf(0, "%v: testing image...", mgr.name)
	mgrcfg, err := mgr.createTestConfig(imageDir, info)
	if err != nil {
		return fmt.Errorf("failed to create manager config: %w", err)
	}
	if !vm.AllowsOvercommit(mgrcfg.Type) {
		return nil // No support for creating machines out of thin air.
	}
	osutil.MkdirAll(mgrcfg.Workdir)
	configFile := filepath.Join(mgrcfg.Workdir, "manager.cfg")
	if err := config.SaveFile(configFile, mgrcfg); err != nil {
		return err
	}

	testSem.Wait()
	defer testSem.Signal()

	timeout := 30 * time.Minute * mgrcfg.Timeouts.Scale
	bin := filepath.Join(mgrcfg.Syzkaller, "bin", "syz-manager")
	output, retErr := osutil.RunCmd(timeout, "", bin, "-config", configFile, "-mode=smoke-test")
	if retErr == nil {
		return nil
	}

	var verboseErr *osutil.VerboseError
	if errors.As(retErr, &verboseErr) {
		// Caller will log the error, so don't include full output.
		retErr = errors.New(verboseErr.Title)
	}
	// If there was a kernel bug, report it to dashboard.
	// Otherwise just save the output in a temp file and log an error, unclear what else we can do.
	reportData, err := os.ReadFile(filepath.Join(mgrcfg.Workdir, "report.json"))
	if err != nil {
		if os.IsNotExist(err) {
			mgr.Errorf("image testing failed w/o kernel bug")
			tmp, err := os.CreateTemp(mgr.workDir, "smoke-test-error")
			if err != nil {
				mgr.Errorf("failed to create smoke test error file: %v", err)
			} else {
				tmp.Write(output)
				tmp.Close()
			}
		} else {
			mgr.Errorf("failed to read smoke test report: %v", err)
		}
	} else {
		rep := new(report.Report)
		if err := json.Unmarshal(reportData, rep); err != nil {
			mgr.Errorf("failed to unmarshal smoke test report: %v", err)
		} else {
			rep.Title = fmt.Sprintf("%v test error: %v", mgr.mgrcfg.RepoAlias, rep.Title)
			retErr = errors.New(rep.Title)
			// There are usually no duplicates for boot errors, so we reset AltTitles.
			// But if we pass them, we would need to add the same prefix as for Title
			// in order to avoid duping boot bugs with non-boot bugs.
			rep.AltTitles = nil
			if err := mgr.reportBuildError(rep, info, imageDir); err != nil {
				mgr.Errorf("failed to report image error: %v", err)
			}
		}
	}
	return retErr
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
	if mgr.storage != nil {
		// We have to send assets together with the other info because the report
		// might be generated immediately.
		uploadedAssets, err := mgr.uploadBuildAssets(build, imageDir)
		if err == nil {
			build.Assets = uploadedAssets
		} else {
			log.Logf(0, "%v: failed to upload build assets: %s", mgr.name, err)
		}
	}
	req := &dashapi.BuildErrorReq{
		Build: *build,
		Crash: dashapi.Crash{
			Title:      rep.Title,
			AltTitles:  rep.AltTitles,
			Corrupted:  false, // Otherwise they get merged with other corrupted reports.
			Recipients: rep.Recipients.ToDash(),
			Log:        rep.Output,
			Report:     rep.Report,
		},
	}
	if rep.GuiltyFile != "" {
		req.Crash.GuiltyFiles = []string{rep.GuiltyFile}
	}
	if err := mgr.dash.ReportBuildError(req); err != nil {
		return err
	}
	return nil
}

func (mgr *Manager) createTestConfig(imageDir string, info *BuildInfo) (*mgrconfig.Config, error) {
	mgrcfg := new(mgrconfig.Config)
	*mgrcfg = *mgr.managercfg
	mgrcfg.Name += "-test"
	mgrcfg.Tag = info.KernelCommit
	// Use designated ports not to collide with the ports of other managers.
	mgrcfg.HTTP = fmt.Sprintf("localhost:%v", mgr.mgrcfg.testHTTPPort)
	// For GCE VMs, we need to bind to a real networking interface, so no localhost.
	mgrcfg.RPC = fmt.Sprintf(":%v", mgr.mgrcfg.testRPCPort)
	mgrcfg.Workdir = filepath.Join(imageDir, "workdir")
	if err := instance.SetConfigImage(mgrcfg, imageDir, true); err != nil {
		return nil, err
	}
	if err := instance.OverrideVMCount(mgrcfg, 3); err != nil {
		return nil, err
	}
	mgrcfg.KernelSrc = mgr.kernelSrcDir
	if err := mgrconfig.Complete(mgrcfg); err != nil {
		return nil, fmt.Errorf("bad manager config: %w", err)
	}
	return mgrcfg, nil
}

func (mgr *Manager) writeConfig(buildTag string) (string, error) {
	mgrcfg := new(mgrconfig.Config)
	*mgrcfg = *mgr.managercfg

	if mgr.dash != nil {
		mgrcfg.DashboardClient = mgr.mgrcfg.DashboardClient
		mgrcfg.DashboardAddr = mgr.cfg.DashboardAddr
		mgrcfg.DashboardKey = mgr.mgrcfg.DashboardKey
		mgrcfg.AssetStorage = mgr.cfg.AssetStorage
	}
	if mgr.cfg.HubAddr != "" {
		mgrcfg.HubClient = mgr.cfg.Name
		mgrcfg.HubAddr = mgr.cfg.HubAddr
		mgrcfg.HubKey = mgr.cfg.HubKey
	}
	mgrcfg.Tag = buildTag
	mgrcfg.Workdir = mgr.workDir
	// There's not much point in keeping disabled progs in the syz-ci corpuses.
	// If the syscalls on some instance are enabled again, syz-hub will provide
	// it with the missing progs over time.
	// And, on the other hand, PreserveCorpus=false lets us disable syscalls in
	// the least destructive way for the rest of the corpus - calls will be cut
	// out the of programs and the leftovers will be retriaged.
	mgrcfg.PreserveCorpus = false
	if err := instance.SetConfigImage(mgrcfg, mgr.currentDir, false); err != nil {
		return "", err
	}
	// Strictly saying this is somewhat racy as builder can concurrently
	// update the source, or even delete and re-clone. If this causes
	// problems, we need to make a copy of sources after build.
	mgrcfg.KernelSrc = mgr.kernelSrcDir
	if err := mgrconfig.Complete(mgrcfg); err != nil {
		return "", fmt.Errorf("bad manager config: %w", err)
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
	mgr.lastBuild = build
	commitTitles, fixCommits, err := mgr.pollCommits(info.KernelCommit)
	if err != nil {
		// This is not critical for operation.
		mgr.Errorf("failed to poll commits: %v", err)
	}
	build.Commits = commitTitles
	build.FixCommits = fixCommits
	if mgr.storage != nil {
		// We always upload build assets -- we create a separate Build object not just for
		// different kernel commits, but also for different syzkaller commits, configs, etc.
		// Since we deduplicate assets by hashing, this should not be a problem -- no assets
		// will be actually duplicated, only the records in the DB.
		assets, err := mgr.uploadBuildAssets(build, imageDir)
		if err != nil {
			mgr.Errorf("failed to upload build assets: %v", err)
			return "", err
		}
		build.Assets = assets
	}
	if err := mgr.dash.UploadBuild(build); err != nil {
		return "", err
	}
	return build.ID, nil
}

func (mgr *Manager) createDashboardBuild(info *BuildInfo, imageDir, typ string) (*dashapi.Build, error) {
	var kernelConfig []byte
	if kernelConfigFile := filepath.Join(imageDir, "kernel.config"); osutil.IsExist(kernelConfigFile) {
		var err error
		if kernelConfig, err = os.ReadFile(kernelConfigFile); err != nil {
			return nil, fmt.Errorf("failed to read kernel.config: %w", err)
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

	// We don't want to spend too much time querying commits from the history,
	// so let's pick a random subset of them each time.
	const sampleCommits = 25

	pendingCommits := resp.PendingCommits
	if len(pendingCommits) > sampleCommits {
		rand.New(rand.NewSource(time.Now().UnixNano())).Shuffle(
			len(pendingCommits), func(i, j int) {
				pendingCommits[i], pendingCommits[j] =
					pendingCommits[j], pendingCommits[i]
			})
		pendingCommits = pendingCommits[:sampleCommits]
	}

	var present []string
	if len(pendingCommits) != 0 {
		commits, _, err := mgr.repo.GetCommitsByTitles(pendingCommits)
		if err != nil {
			return nil, nil, err
		}
		m := make(map[string]bool, len(commits))
		for _, com := range commits {
			m[vcs.CanonicalizeCommit(com.Title)] = true
		}
		for _, com := range pendingCommits {
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

func (mgr *Manager) backportCommits() []vcs.BackportCommit {
	return append(
		append([]vcs.BackportCommit{}, mgr.cfg.BisectBackports...),
		mgr.mgrcfg.BisectBackports...,
	)
}

func (mgr *Manager) uploadBuildAssets(buildInfo *dashapi.Build, assetFolder string) ([]dashapi.NewAsset, error) {
	if mgr.storage == nil {
		// No reason to continue anyway.
		return nil, fmt.Errorf("asset storage is not configured")
	}
	type pendingAsset struct {
		path      string
		assetType dashapi.AssetType
		name      string
	}
	pending := []pendingAsset{}
	kernelFile := filepath.Join(assetFolder, "kernel")
	if osutil.IsExist(kernelFile) {
		fileName := "kernel"
		if buildInfo.OS == targets.Linux {
			fileName = path.Base(build.LinuxKernelImage(buildInfo.Arch))
		}
		pending = append(pending, pendingAsset{kernelFile, dashapi.KernelImage, fileName})
	}
	imageFile := filepath.Join(assetFolder, "image")
	if osutil.IsExist(imageFile) {
		if mgr.managercfg.Type == "qemu" {
			// For qemu we currently use non-bootable disk images.
			pending = append(pending, pendingAsset{imageFile, dashapi.NonBootableDisk,
				"non_bootable_disk.raw"})
		} else {
			pending = append(pending, pendingAsset{imageFile, dashapi.BootableDisk,
				"disk.raw"})
		}
	}
	target := mgr.managercfg.SysTarget
	kernelObjFile := filepath.Join(assetFolder, "obj", target.KernelObject)
	if osutil.IsExist(kernelObjFile) {
		pending = append(pending,
			pendingAsset{kernelObjFile, dashapi.KernelObject, target.KernelObject})
	}
	// TODO: add initrd?
	ret := []dashapi.NewAsset{}
	for _, pendingAsset := range pending {
		if !mgr.storage.AssetTypeEnabled(pendingAsset.assetType) {
			continue
		}
		file, err := os.Open(pendingAsset.path)
		if err != nil {
			log.Logf(0, "failed to open an asset for uploading: %s, %s",
				pendingAsset.path, err)
			continue
		}
		if mgr.debugStorage {
			log.Logf(0, "uploading an asset %s of type %s",
				pendingAsset.path, pendingAsset.assetType)
		}
		extra := &asset.ExtraUploadArg{SkipIfExists: true}
		hash := sha256.New()
		if _, err := io.Copy(hash, file); err != nil {
			log.Logf(0, "failed calculate hash for the asset %s: %s", pendingAsset.path, err)
			continue
		}
		extra.UniqueTag = fmt.Sprintf("%x", hash.Sum(nil))
		// Now we need to go back to the beginning of the file again.
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			log.Logf(0, "failed wind back the opened file for %s: %s", pendingAsset.path, err)
			continue
		}
		info, err := mgr.storage.UploadBuildAsset(file, pendingAsset.name,
			pendingAsset.assetType, buildInfo, extra)
		if err != nil {
			log.Logf(0, "failed to upload an asset: %s, %s",
				pendingAsset.path, err)
			continue
		} else if mgr.debugStorage {
			log.Logf(0, "uploaded an asset: %#v", info)
		}
		ret = append(ret, info)
	}
	return ret, nil
}

func (mgr *Manager) httpGET(path string) (resp *http.Response, err error) {
	addr := mgr.managercfg.HTTP
	if addr != "" && addr[0] == ':' {
		addr = "127.0.0.1" + addr // in case addr is ":port"
	}
	client := &http.Client{
		Timeout: time.Hour,
	}
	return client.Get(fmt.Sprintf("http://%s%s", addr, path))
}

func (mgr *Manager) uploadCoverReport() error {
	directUpload := mgr.managercfg.Cover && mgr.cfg.CoverUploadPath != ""
	if mgr.storage == nil && !directUpload {
		// Cover report uploading is disabled.
		return nil
	}
	if mgr.storage != nil && directUpload {
		return fmt.Errorf("cover report must be either uploaded directly or via asset storage")
	}
	// Report generation can consume lots of memory. Generate one at a time.
	select {
	case <-buildSem.WaitC():
	case <-mgr.stop:
		return nil
	}
	defer buildSem.Signal()

	resp, err := mgr.httpGET("/cover")
	if err != nil {
		return fmt.Errorf("failed to get report: %w", err)
	}
	defer resp.Body.Close()
	if directUpload {
		return mgr.uploadFile(mgr.cfg.CoverUploadPath, mgr.name+".html", resp.Body, true)
	}
	// Upload via the asset storage.
	newAsset, err := mgr.storage.UploadBuildAsset(resp.Body, mgr.name+".html",
		dashapi.HTMLCoverageReport, mgr.lastBuild, nil)
	if err != nil {
		return fmt.Errorf("failed to upload html coverage report: %w", err)
	}
	err = mgr.storage.ReportBuildAssets(mgr.lastBuild, newAsset)
	if err != nil {
		return fmt.Errorf("failed to report the html coverage report asset: %w", err)
	}
	return nil
}

func (mgr *Manager) uploadCoverStat(fuzzingMinutes int) error {
	if !mgr.managercfg.Cover || mgr.cfg.CoverPipelinePath == "" {
		return nil
	}

	// Report generation consumes 40G RAM. Generate one at a time.
	// TODO: remove it once #4585 (symbolization tuning) is closed
	select {
	case <-buildSem.WaitC():
	case <-mgr.stop:
		return nil
	}
	defer buildSem.Signal()

	// Coverage report generation consumes and caches lots of memory.
	// In the syz-ci context report generation won't be used after this point,
	// so tell manager to flush report generator.
	resp, err := mgr.httpGET("/cover?jsonl=1&flush=1")
	if err != nil {
		return fmt.Errorf("failed to httpGet /cover?jsonl=1 report: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		sb := new(strings.Builder)
		io.Copy(sb, resp.Body)
		return fmt.Errorf("failed to GET /cover?jsonl=1, httpStatus %d: %s",
			resp.StatusCode, sb.String())
	}

	curTime := time.Now()
	pr, pw := io.Pipe()
	defer pr.Close()
	go func() {
		decoder := json.NewDecoder(resp.Body)
		for decoder.More() {
			var covInfo cover.CoverageInfo
			if err := decoder.Decode(&covInfo); err != nil {
				pw.CloseWithError(fmt.Errorf("failed to decode CoverageInfo: %w", err))
				return
			}
			if err := cover.WriteCIJSONLine(pw, covInfo, cover.CIDetails{
				Version:        1,
				Timestamp:      curTime.Format(time.RFC3339Nano),
				FuzzingMinutes: fuzzingMinutes,
				Arch:           mgr.lastBuild.Arch,
				BuildID:        mgr.lastBuild.ID,
				Manager:        mgr.name,
				KernelRepo:     mgr.lastBuild.KernelRepo,
				KernelBranch:   mgr.lastBuild.KernelBranch,
				KernelCommit:   mgr.lastBuild.KernelCommit,
			}); err != nil {
				pw.CloseWithError(fmt.Errorf("failed to write CIJSONLine: %w", err))
				return
			}
		}
		pw.Close()
	}()
	fileName := fmt.Sprintf("%s/%s-%s-%d-%d.jsonl",
		mgr.mgrcfg.DashboardClient,
		mgr.name, curTime.Format(time.DateOnly),
		curTime.Hour(), curTime.Minute())
	if err := mgr.uploadFile(mgr.cfg.CoverPipelinePath, fileName, pr, false); err != nil {
		return fmt.Errorf("failed to uploadFileGCS(): %w", err)
	}
	return nil
}

func (mgr *Manager) uploadCorpus() error {
	if mgr.cfg.CorpusUploadPath == "" {
		return nil
	}
	f, err := os.Open(filepath.Join(mgr.workDir, "corpus.db"))
	if err != nil {
		return err
	}
	defer f.Close()
	return mgr.uploadFile(mgr.cfg.CorpusUploadPath, mgr.name+"-corpus.db", f, true)
}

func (mgr *Manager) uploadFile(dstPath, name string, file io.Reader, allowPublishing bool) error {
	URL, err := url.Parse(dstPath)
	if err != nil {
		return fmt.Errorf("failed to parse upload path: %w", err)
	}
	URL.Path = path.Join(URL.Path, name)
	URLStr := URL.String()
	log.Logf(0, "uploading %v to %v", name, URLStr)
	if strings.HasPrefix(URLStr, "http://") ||
		strings.HasPrefix(URLStr, "https://") {
		return uploadFileHTTPPut(URLStr, file)
	}
	return uploadFileGCS(URLStr, file, allowPublishing && mgr.cfg.PublishGCS)
}

func uploadFileGCS(URL string, file io.Reader, publish bool) error {
	URL = strings.TrimPrefix(URL, "gs://")
	GCS, err := gcs.NewClient()
	if err != nil {
		return fmt.Errorf("failed to create GCS client: %w", err)
	}
	defer GCS.Close()
	gcsWriter, err := GCS.FileWriter(URL)
	if err != nil {
		return fmt.Errorf("failed to create GCS writer: %w", err)
	}
	if _, err := io.Copy(gcsWriter, file); err != nil {
		gcsWriter.Close()
		return fmt.Errorf("failed to copy report: %w", err)
	}
	if err := gcsWriter.Close(); err != nil {
		return fmt.Errorf("failed to close gcs writer: %w", err)
	}
	if publish {
		return GCS.Publish(URL)
	}
	return nil
}

func uploadFileHTTPPut(URL string, file io.Reader) error {
	req, err := http.NewRequest(http.MethodPut, URL, file)
	if err != nil {
		return fmt.Errorf("failed to create HTTP PUT request: %w", err)
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to perform HTTP PUT request: %w", err)
	}
	defer resp.Body.Close()
	if !(resp.StatusCode >= 200 && resp.StatusCode <= 299) {
		return fmt.Errorf("HTTP PUT failed with status code: %v", resp.StatusCode)
	}
	return nil
}

// Errorf logs non-fatal error and sends it to dashboard.
func (mgr *Manager) Errorf(msg string, args ...interface{}) {
	log.Errorf(mgr.name+": "+msg, args...)
	if mgr.dash != nil {
		mgr.dash.LogError(mgr.name, msg, args...)
	}
}

func (mgr *ManagerConfig) validate(cfg *Config) error {
	// Manager name must not contain dots because it is used as GCE image name prefix.
	managerNameRe := regexp.MustCompile("^[a-zA-Z0-9-_]{3,64}$")
	if !managerNameRe.MatchString(mgr.Name) {
		return fmt.Errorf("param 'managers.name' has bad value: %q", mgr.Name)
	}
	if mgr.Jobs.AnyEnabled() && (cfg.DashboardAddr == "" || cfg.DashboardClient == "") {
		return fmt.Errorf("manager %v: has jobs but no dashboard info", mgr.Name)
	}
	if mgr.Jobs.PollCommits && (cfg.DashboardAddr == "" || mgr.DashboardClient == "") {
		return fmt.Errorf("manager %v: commit_poll is set but no dashboard info", mgr.Name)
	}
	if (mgr.Jobs.BisectCause || mgr.Jobs.BisectFix) && cfg.BisectBinDir == "" {
		return fmt.Errorf("manager %v: enabled bisection but no bisect_bin_dir", mgr.Name)
	}
	return nil
}
