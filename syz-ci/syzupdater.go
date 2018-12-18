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
	mgrcfg        *ManagerConfig
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
	os.Unsetenv("GOPATH")
	if cfg.Goroot != "" {
		os.Setenv("GOROOT", cfg.Goroot)
		os.Setenv("PATH", filepath.Join(cfg.Goroot, "bin")+
			string(filepath.ListSeparator)+os.Getenv("PATH"))
	}
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
		log.Fatalf("%v", exe)
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
		mgrcfg:        cfg.Managers[0],
	}
}

// UpdateOnStart does 3 things:
//  - ensures that the current executable is fresh
//  - ensures that we have a working syzkaller build in current
func (upd *SyzUpdater) UpdateOnStart(shutdown chan struct{}) {
	os.RemoveAll(upd.currentDir)
	exeTag, exeMod := readTag(upd.exe + ".tag")
	latestTag := upd.checkLatest()
	if exeTag == latestTag && time.Since(exeMod) < time.Minute {
		// Have a freash up-to-date build, probably just restarted.
		log.Logf(0, "current executable is up-to-date (%v)", exeTag)
		if err := osutil.LinkFiles(upd.latestDir, upd.currentDir, upd.syzFiles); err != nil {
			log.Fatal(err)
		}
		return
	}
	if exeTag == "" {
		log.Logf(0, "current executable is bootstrap")
	} else {
		log.Logf(0, "current executable is on %v", exeTag)
		log.Logf(0, "latest syzkaller build is on %v", latestTag)
	}

	// No syzkaller build or executable is stale.
	lastCommit := exeTag
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
			if exeTag != latestTag {
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
	latestTag := filepath.Join(upd.latestDir, "tag")
	if err := osutil.CopyFile(latestBin, upd.exe); err != nil {
		log.Fatal(err)
	}
	if err := osutil.CopyFile(latestTag, upd.exe+".tag"); err != nil {
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
	if lastCommit != commit.Hash {
		log.Logf(0, "syzkaller: building ...")
		lastCommit = commit.Hash
		if err := upd.build(commit); err != nil {
			log.Logf(0, "syzkaller: %v", err)
			upd.uploadBuildError(commit, err)
		}
	}
	return lastCommit
}

func (upd *SyzUpdater) build(commit *vcs.Commit) error {
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
	cmd.Env = append([]string{"GOPATH=" + upd.gopathDir}, os.Environ()...)
	if _, err := osutil.Run(time.Hour, cmd); err != nil {
		return osutil.PrependContext("testing failed: %v", err)
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
	// Build errors can't be uploaded using global client
	// as it is not associated with any namespace.
	// So we use the first manager client for this.
	if upd.dashboardAddr == "" || upd.mgrcfg.DashboardClient == "" {
		return
	}
	dash := dashapi.New(upd.dashboardAddr, upd.mgrcfg.DashboardClient, upd.mgrcfg.DashboardKey)
	var title string
	var output []byte
	if verbose, ok := buildErr.(*osutil.VerboseError); ok {
		title = verbose.Title
		output = verbose.Output
	} else {
		title = buildErr.Error()
	}
	title = "syzkaller: " + title
	managercfg := upd.mgrcfg.managercfg
	req := &dashapi.BuildErrorReq{
		Build: dashapi.Build{
			Manager:           managercfg.Name,
			ID:                commit.Hash,
			OS:                managercfg.TargetOS,
			Arch:              managercfg.TargetArch,
			VMArch:            managercfg.TargetVMArch,
			SyzkallerCommit:   commit.Hash,
			CompilerID:        upd.compilerID,
			KernelRepo:        upd.repoAddress,
			KernelBranch:      upd.branch,
			KernelCommit:      commit.Hash,
			KernelCommitTitle: commit.Title,
			KernelCommitDate:  commit.Date,
		},
		Crash: dashapi.Crash{
			Title: title,
			Log:   output,
		},
	}
	// TODO: log ReportBuildError error to dashboard.
	dash.ReportBuildError(req)
}

// checkLatest returns tag of the latest build,
// or an empty string if latest build is missing/broken.
func (upd *SyzUpdater) checkLatest() string {
	if !osutil.FilesExist(upd.latestDir, upd.syzFiles) {
		return ""
	}
	tag, _ := readTag(filepath.Join(upd.latestDir, "tag"))
	return tag
}

func readTag(file string) (tag string, mod time.Time) {
	data, _ := ioutil.ReadFile(file)
	tag = string(data)
	if st, err := os.Stat(file); err == nil {
		mod = st.ModTime()
	}
	if tag == "" || mod.IsZero() {
		tag = ""
		mod = time.Time{}
	}
	return
}
