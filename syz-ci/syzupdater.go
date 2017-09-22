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

	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/git"
	. "github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/syz-manager/mgrconfig"
)

const (
	syzkallerRebuildPeriod = 12 * time.Hour
	buildRetryPeriod       = 15 * time.Minute // used for both syzkaller and kernel
)

// SyzUpdater handles everything related to syzkaller updates.
// As kernel builder, it maintains 2 builds:
//  - latest: latest known good syzkaller build
//  - current: currently used syzkaller build
// Additionally it updates and restarts the current executable as necessary.
// Current executable is always built on the same revision as the rest of syzkaller binaries.
type SyzUpdater struct {
	exe          string
	repo         string
	branch       string
	descriptions string
	syzkallerDir string
	latestDir    string
	currentDir   string
	syzFiles     []string
	targets      map[string]bool
}

func NewSyzUpdater(cfg *Config) *SyzUpdater {
	wd, err := os.Getwd()
	if err != nil {
		Fatalf("failed to get wd: %v", err)
	}
	bin := os.Args[0]
	if !filepath.IsAbs(bin) {
		bin = filepath.Join(wd, bin)
	}
	bin = filepath.Clean(bin)
	exe := filepath.Base(bin)
	if wd != filepath.Dir(bin) {
		Fatalf("%v executable must be in cwd (it will be overwritten on update)", exe)
	}

	gopath := filepath.Join(wd, "gopath")
	os.Setenv("GOPATH", gopath)
	os.Setenv("GOROOT", cfg.Goroot)
	os.Setenv("PATH", filepath.Join(cfg.Goroot, "bin")+
		string(filepath.ListSeparator)+os.Getenv("PATH"))
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
		mgrcfg := new(mgrconfig.Config)
		if err := config.LoadData(mgr.Manager_Config, mgrcfg); err != nil {
			Fatalf("failed to load manager %v config: %v", mgr.Name, err)
		}
		os, vmarch, arch, err := mgrconfig.SplitTarget(mgrcfg.Target)
		if err != nil {
			Fatalf("failed to load manager %v config: %v", mgr.Name, err)
		}
		targets[os+"/"+vmarch+"/"+arch] = true
		files[fmt.Sprintf("bin/%v_%v/syz-fuzzer", os, vmarch)] = true
		files[fmt.Sprintf("bin/%v_%v/syz-execprog", os, vmarch)] = true
		files[fmt.Sprintf("bin/%v_%v/syz-executor", os, arch)] = true
	}
	var syzFiles []string
	for f := range files {
		syzFiles = append(syzFiles, f)
	}

	return &SyzUpdater{
		exe:          exe,
		repo:         cfg.Syzkaller_Repo,
		branch:       cfg.Syzkaller_Branch,
		descriptions: cfg.Syzkaller_Descriptions,
		syzkallerDir: syzkallerDir,
		latestDir:    filepath.Join("syzkaller", "latest"),
		currentDir:   filepath.Join("syzkaller", "current"),
		syzFiles:     syzFiles,
		targets:      targets,
	}
}

// UpdateOnStart does 3 things:
//  - ensures that the current executable is fresh
//  - ensures that we have a working syzkaller build in current
func (upd *SyzUpdater) UpdateOnStart(shutdown chan struct{}) {
	os.RemoveAll(upd.currentDir)
	exeTag, exeMod := readTag(upd.exe + ".tag")
	latestTag := upd.checkLatest()
	if exeTag == latestTag && time.Since(exeMod) < syzkallerRebuildPeriod/2 {
		// Have a freash up-to-date build, probably just restarted.
		Logf(0, "current executable is up-to-date (%v)", exeTag)
		if err := osutil.LinkFiles(upd.latestDir, upd.currentDir, upd.syzFiles); err != nil {
			Fatal(err)
		}
		return
	}
	if exeTag == "" {
		Logf(0, "current executable is bootstrap")
	} else {
		Logf(0, "current executable is on %v", exeTag)
		Logf(0, "latest syzkaller build is on %v", latestTag)
	}

	// No syzkaller build or executable is stale.
	lastCommit := exeTag
	for {
		lastCommit = upd.pollAndBuild(lastCommit)
		latestTag := upd.checkLatest()
		if latestTag != "" {
			// The build was successful or we had the latest build from previous runs.
			// Either way, use the latest build.
			Logf(0, "using syzkaller built on %v", latestTag)
			if err := osutil.LinkFiles(upd.latestDir, upd.currentDir, upd.syzFiles); err != nil {
				Fatal(err)
			}
			if exeTag != latestTag {
				upd.UpdateAndRestart()
			}
			return
		}

		// No good build at all, try again later.
		Logf(0, "retrying in %v", buildRetryPeriod)
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
	Logf(0, "syzkaller: update available, restarting")
}

// UpdateAndRestart updates and restarts the current executable.
// Does not return.
func (upd *SyzUpdater) UpdateAndRestart() {
	Logf(0, "restarting executable for update")
	latestBin := filepath.Join(upd.latestDir, "bin", upd.exe)
	latestTag := filepath.Join(upd.latestDir, "tag")
	if err := osutil.CopyFile(latestBin, upd.exe); err != nil {
		Fatal(err)
	}
	if err := osutil.CopyFile(latestTag, upd.exe+".tag"); err != nil {
		Fatal(err)
	}
	if err := syscall.Exec(upd.exe, os.Args, os.Environ()); err != nil {
		Fatal(err)
	}
	Fatalf("not reachable")
}

func (upd *SyzUpdater) pollAndBuild(lastCommit string) string {
	commit, err := git.Poll(upd.syzkallerDir, upd.repo, upd.branch)
	if err != nil {
		Logf(0, "syzkaller: failed to poll: %v", err)
	} else {
		Logf(0, "syzkaller: poll: %v", commit)
		if lastCommit != commit {
			Logf(0, "syzkaller: building ...")
			lastCommit = commit
			if err := upd.build(); err != nil {
				Logf(0, "syzkaller: %v", err)
			}
		}
	}
	return lastCommit
}

func (upd *SyzUpdater) build() error {
	commit, err := git.HeadCommit(upd.syzkallerDir)
	if err != nil {
		return fmt.Errorf("failed to get HEAD commit: %v", err)
	}
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
	}
	if _, err := osutil.RunCmd(time.Hour, upd.syzkallerDir, "make", "generate"); err != nil {
		return fmt.Errorf("build failed: %v", err)
	}
	if _, err := osutil.RunCmd(time.Hour, upd.syzkallerDir, "make", "host", "ci"); err != nil {
		return fmt.Errorf("build failed: %v", err)
	}
	for target := range upd.targets {
		parts := strings.Split(target, "/")
		env := []string{
			"TARGETOS=" + parts[0],
			"TARGETVMARCH=" + parts[1],
			"TARGETARCH=" + parts[2],
		}
		if _, err := osutil.RunCmdEnv(time.Hour, env, upd.syzkallerDir, "make", "target"); err != nil {
			return fmt.Errorf("build failed: %v", err)
		}
	}
	if _, err := osutil.RunCmd(time.Hour, upd.syzkallerDir, "go", "test", "-short", "./..."); err != nil {
		return fmt.Errorf("tests failed: %v", err)
	}
	tagFile := filepath.Join(upd.syzkallerDir, "tag")
	if err := osutil.WriteFile(tagFile, []byte(commit)); err != nil {
		return fmt.Errorf("filed to write tag file: %v", err)
	}
	if err := osutil.CopyFiles(upd.syzkallerDir, upd.latestDir, upd.syzFiles); err != nil {
		return fmt.Errorf("filed to copy syzkaller: %v", err)
	}
	return nil
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
