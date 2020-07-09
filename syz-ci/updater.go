// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/prog"
)

const (
	syzkallerRebuildPeriod = 12 * time.Hour
	buildRetryPeriod       = 10 * time.Minute // used for both syzkaller and kernel
)

// SyzUpdater handles everything related to syzkaller updates.
// As kernel builder, it maintains 2 builds:
//  - latest: latest known good syzkaller build
//  - current: currently used syzkaller build
// Additionally it updates and restarts the current executable as necessary.
// Current executable is always built on the same revision as the rest of syzkaller binaries.
type SyzUpdater struct {
	repo          vcs.Repo
	exe           string
	repoAddress   string
	branch        string
	descriptions  string
	gopathDir     string
	syzkallerDir  string
	latestDir     string
	currentDir    string
	syzFiles      map[string]bool
	targets       map[string]bool
	dashboardAddr string
	compilerID    string
	cfg           *Config
}

func NewSyzUpdater(cfg *Config) *SyzUpdater {
	wd, err := os.Getwd()
	if err != nil {
		log.Fatalf("failed to get wd: %v", err)
	}
	bin := os.Args[0]
	if !filepath.IsAbs(bin) {
		bin = filepath.Join(wd, bin)
	}
	bin = filepath.Clean(bin)
	exe := filepath.Base(bin)
	if wd != filepath.Dir(bin) {
		log.Fatalf("%v executable must be in cwd (it will be overwritten on update)", exe)
	}

	gopath := filepath.Join(wd, "gopath")
	syzkallerDir := filepath.Join(gopath, "src", "github.com", "google", "syzkaller")
	osutil.MkdirAll(syzkallerDir)

	// List of required files in syzkaller build (contents of latest/current dirs).
	files := map[string]bool{
		"tag":             true, // contains syzkaller repo git hash
		"bin/syz-ci":      true, // these are just copied from syzkaller dir
		"bin/syz-manager": true,
	}
	targets := make(map[string]bool)
	for _, mgr := range cfg.Managers {
		mgrcfg := mgr.managercfg
		os, vmarch, arch := mgrcfg.TargetOS, mgrcfg.TargetVMArch, mgrcfg.TargetArch
		targets[os+"/"+vmarch+"/"+arch] = true
		files[fmt.Sprintf("bin/%v_%v/syz-fuzzer", os, vmarch)] = true
		files[fmt.Sprintf("bin/%v_%v/syz-execprog", os, vmarch)] = true
		files[fmt.Sprintf("bin/%v_%v/syz-executor", os, arch)] = true
	}
	syzFiles := make(map[string]bool)
	for f := range files {
		syzFiles[f] = true
	}
	compilerID, err := osutil.RunCmd(time.Minute, "", "go", "version")
	if err != nil {
		log.Fatalf("%v", err)
	}
	return &SyzUpdater{
		repo:          vcs.NewSyzkallerRepo(syzkallerDir),
		exe:           exe,
		repoAddress:   cfg.SyzkallerRepo,
		branch:        cfg.SyzkallerBranch,
		descriptions:  cfg.SyzkallerDescriptions,
		gopathDir:     gopath,
		syzkallerDir:  syzkallerDir,
		latestDir:     filepath.Join("syzkaller", "latest"),
		currentDir:    filepath.Join("syzkaller", "current"),
		syzFiles:      syzFiles,
		targets:       targets,
		dashboardAddr: cfg.DashboardAddr,
		compilerID:    strings.TrimSpace(string(compilerID)),
		cfg:           cfg,
	}
}

// UpdateOnStart does 3 things:
//  - ensures that the current executable is fresh
//  - ensures that we have a working syzkaller build in current
func (upd *SyzUpdater) UpdateOnStart(autoupdate bool, shutdown chan struct{}) {
	os.RemoveAll(upd.currentDir)
	latestTag := upd.checkLatest()
	if latestTag != "" {
		var exeMod time.Time
		if st, err := os.Stat(upd.exe); err == nil {
			exeMod = st.ModTime()
		}
		uptodate := prog.GitRevisionBase == latestTag && time.Since(exeMod) < time.Minute
		if uptodate || !autoupdate {
			if uptodate {
				// Have a fresh up-to-date build, probably just restarted.
				log.Logf(0, "current executable is up-to-date (%v)", latestTag)
			} else {
				log.Logf(0, "autoupdate is turned off, using latest build %v", latestTag)
			}
			if err := osutil.LinkFiles(upd.latestDir, upd.currentDir, upd.syzFiles); err != nil {
				log.Fatal(err)
			}
			return
		}
	}
	log.Logf(0, "current executable is on %v", prog.GitRevision)
	log.Logf(0, "latest syzkaller build is on %v", latestTag)

	// No syzkaller build or executable is stale.
	lastCommit := prog.GitRevisionBase
	if lastCommit != latestTag {
		// Latest build and syz-ci are inconsistent. Rebuild everything.
		lastCommit = ""
		latestTag = ""
	}
	for {
		lastCommit = upd.pollAndBuild(lastCommit)
		latestTag := upd.checkLatest()
		if latestTag != "" {
			// The build was successful or we had the latest build from previous runs.
			// Either way, use the latest build.
			log.Logf(0, "using syzkaller built on %v", latestTag)
			if err := osutil.LinkFiles(upd.latestDir, upd.currentDir, upd.syzFiles); err != nil {
				log.Fatal(err)
			}
			if autoupdate && prog.GitRevisionBase != latestTag {
				upd.UpdateAndRestart()
			}
			return
		}

		// No good build at all, try again later.
		log.Logf(0, "retrying in %v", buildRetryPeriod)
		select {
		case <-time.After(buildRetryPeriod):
		case <-shutdown:
			os.Exit(0)
		}
	}
}

// WaitForUpdate polls and rebuilds syzkaller.
// Returns when we have a new good build in latest.
func (upd *SyzUpdater) WaitForUpdate() {
	time.Sleep(syzkallerRebuildPeriod)
	latestTag := upd.checkLatest()
	lastCommit := latestTag
	for {
		lastCommit = upd.pollAndBuild(lastCommit)
		if latestTag != upd.checkLatest() {
			break
		}
		time.Sleep(buildRetryPeriod)
	}
	log.Logf(0, "syzkaller: update available, restarting")
}

// UpdateAndRestart updates and restarts the current executable.
// Does not return.
func (upd *SyzUpdater) UpdateAndRestart() {
	log.Logf(0, "restarting executable for update")
	latestBin := filepath.Join(upd.latestDir, "bin", upd.exe)
	if err := osutil.CopyFile(latestBin, upd.exe); err != nil {
		log.Fatal(err)
	}
	if err := syscall.Exec(upd.exe, os.Args, os.Environ()); err != nil {
		log.Fatal(err)
	}
	log.Fatalf("not reachable")
}

func (upd *SyzUpdater) pollAndBuild(lastCommit string) string {
	commit, err := upd.repo.Poll(upd.repoAddress, upd.branch)
	if err != nil {
		log.Logf(0, "syzkaller: failed to poll: %v", err)
		return lastCommit
	}
	log.Logf(0, "syzkaller: poll: %v (%v)", commit.Hash, commit.Title)
	if lastCommit == commit.Hash {
		return lastCommit
	}
	log.Logf(0, "syzkaller: building ...")
	if err := upd.build(commit); err != nil {
		log.Logf(0, "syzkaller: %v", err)
		upd.uploadBuildError(commit, err)
	}
	return commit.Hash
}

func (upd *SyzUpdater) build(commit *vcs.Commit) error {
	// syzkaller testing may be slowed down by concurrent kernel builds too much
	// and cause timeout failures, so we serialize it with other builds:
	// https://groups.google.com/forum/#!msg/syzkaller-openbsd-bugs/o-G3vEsyQp4/f_nFpoNKBQAJ
	kernelBuildSem <- struct{}{}
	defer func() { <-kernelBuildSem }()

	if upd.descriptions != "" {
		files, err := ioutil.ReadDir(upd.descriptions)
		if err != nil {
			return fmt.Errorf("failed to read descriptions dir: %v", err)
		}
		for _, f := range files {
			src := filepath.Join(upd.descriptions, f.Name())
			dst := filepath.Join(upd.syzkallerDir, "sys", "linux", f.Name())
			if err := osutil.CopyFile(src, dst); err != nil {
				return err
			}
		}
		cmd := osutil.Command(instance.MakeBin, "generate")
		cmd.Dir = upd.syzkallerDir
		cmd.Env = append([]string{"GOPATH=" + upd.gopathDir}, os.Environ()...)
		if _, err := osutil.Run(time.Hour, cmd); err != nil {
			return osutil.PrependContext("generate failed", err)
		}
	}
	// This will also generate descriptions and should go before the 'go test' below.
	cmd := osutil.Command(instance.MakeBin, "host", "ci")
	cmd.Dir = upd.syzkallerDir
	cmd.Env = append([]string{"GOPATH=" + upd.gopathDir}, os.Environ()...)
	if _, err := osutil.Run(time.Hour, cmd); err != nil {
		return osutil.PrependContext("make host failed", err)
	}
	for target := range upd.targets {
		parts := strings.Split(target, "/")
		cmd = osutil.Command(instance.MakeBin, "target")
		cmd.Dir = upd.syzkallerDir
		cmd.Env = append([]string{}, os.Environ()...)
		cmd.Env = append(cmd.Env,
			"GOPATH="+upd.gopathDir,
			"TARGETOS="+parts[0],
			"TARGETVMARCH="+parts[1],
			"TARGETARCH="+parts[2],
		)
		if _, err := osutil.Run(time.Hour, cmd); err != nil {
			return osutil.PrependContext("make target failed", err)
		}
	}
	cmd = osutil.Command("go", "test", "-short", "./...")
	cmd.Dir = upd.syzkallerDir
	cmd.Env = append([]string{
		"GOPATH=" + upd.gopathDir,
		"SYZ_DISABLE_SANDBOXING=yes",
	}, os.Environ()...)
	if _, err := osutil.Run(time.Hour, cmd); err != nil {
		return osutil.PrependContext("testing failed", err)
	}
	tagFile := filepath.Join(upd.syzkallerDir, "tag")
	if err := osutil.WriteFile(tagFile, []byte(commit.Hash)); err != nil {
		return fmt.Errorf("failed to write tag file: %v", err)
	}
	if err := osutil.CopyFiles(upd.syzkallerDir, upd.latestDir, upd.syzFiles); err != nil {
		return fmt.Errorf("failed to copy syzkaller: %v", err)
	}
	return nil
}

func (upd *SyzUpdater) uploadBuildError(commit *vcs.Commit, buildErr error) {
	var title string
	var output []byte
	if verbose, ok := buildErr.(*osutil.VerboseError); ok {
		title = verbose.Title
		output = verbose.Output
	} else {
		title = buildErr.Error()
	}
	title = "syzkaller: " + title
	for _, mgrcfg := range upd.cfg.Managers {
		if upd.dashboardAddr == "" || mgrcfg.DashboardClient == "" {
			log.Logf(0, "not uploading build error fr %v: no dashboard", mgrcfg.Name)
			continue
		}
		dash := dashapi.New(mgrcfg.DashboardClient, upd.dashboardAddr, mgrcfg.DashboardKey)
		managercfg := mgrcfg.managercfg
		req := &dashapi.BuildErrorReq{
			Build: dashapi.Build{
				Manager:             managercfg.Name,
				ID:                  commit.Hash,
				OS:                  managercfg.TargetOS,
				Arch:                managercfg.TargetArch,
				VMArch:              managercfg.TargetVMArch,
				SyzkallerCommit:     commit.Hash,
				SyzkallerCommitDate: commit.Date,
				CompilerID:          upd.compilerID,
				KernelRepo:          upd.repoAddress,
				KernelBranch:        upd.branch,
			},
			Crash: dashapi.Crash{
				Title: title,
				Log:   output,
			},
		}
		if err := dash.ReportBuildError(req); err != nil {
			// TODO: log ReportBuildError error to dashboard.
			log.Logf(0, "failed to report build error for %v: %v", mgrcfg.Name, err)
		}
	}
}

// checkLatest returns tag of the latest build,
// or an empty string if latest build is missing/broken.
func (upd *SyzUpdater) checkLatest() string {
	if !osutil.FilesExist(upd.latestDir, upd.syzFiles) {
		return ""
	}
	tag, _ := ioutil.ReadFile(filepath.Join(upd.latestDir, "tag"))
	return string(tag)
}
