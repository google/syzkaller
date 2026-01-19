// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package updater

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

const (
	RebuildPeriod    = 12 * time.Hour
	BuildRetryPeriod = 10 * time.Minute // used for both syzkaller and kernel
)

// Updater handles everything related to syzkaller updates.
// As kernel builder, it maintains 2 builds:
//   - latest: latest known good syzkaller build
//   - current: currently used syzkaller build
//
// Additionally it updates and restarts the current executable as necessary.
// Current executable is always built on the same revision as the rest of syzkaller binaries.
type Updater struct {
	repo         vcs.Repo
	exe          string
	repoAddress  string
	branch       string
	descriptions string
	gopathDir    string
	syzkallerDir string
	latestDir    string
	currentDir   string
	syzFiles     map[string]bool
	compilerID   string
	cfg          *Config
}

type Config struct {
	// If set, exit on updates instead of restarting the current binary.
	ExitOnUpdate          bool
	BuildSem              *osutil.Semaphore
	ReportBuildError      func(commit *vcs.Commit, compilerID string, buildErr error)
	SyzkallerRepo         string
	SyzkallerBranch       string
	SyzkallerDescriptions string
	Targets               map[Target]bool
}

type Target struct {
	OS     string
	VMArch string
	Arch   string
}

func New(cfg *Config) (*Updater, error) {
	os.Unsetenv("GOPATH")
	wd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("updater: failed to get wd: %w", err)
	}
	bin := os.Args[0]
	if !filepath.IsAbs(bin) {
		bin = filepath.Join(wd, bin)
	}
	bin = filepath.Clean(bin)
	exe := filepath.Base(bin)
	if wd != filepath.Dir(bin) {
		return nil, fmt.Errorf("updater: %v executable must be in cwd (it will be overwritten on update)", exe)
	}

	gopath := filepath.Join(wd, "gopath")
	syzkallerDir := filepath.Join(gopath, "src", "github.com", "google", "syzkaller")
	osutil.MkdirAll(syzkallerDir)

	// List of required files in syzkaller build (contents of latest/current dirs).
	syzFiles := map[string]bool{
		"tag":             true, // contains syzkaller repo git hash
		"bin/syz-ci":      true, // these are just copied from syzkaller dir
		"bin/syz-manager": true,
		"bin/syz-agent":   true,
		"sys/*/test/*":    true,
	}
	for target := range cfg.Targets {
		sysTarget := targets.Get(target.OS, target.VMArch)
		if sysTarget == nil {
			return nil, fmt.Errorf("unsupported OS/arch: %v/%v", target.OS, target.VMArch)
		}
		syzFiles[fmt.Sprintf("bin/%v_%v/syz-execprog", target.OS, target.VMArch)] = true
		if sysTarget.ExecutorBin == "" {
			syzFiles[fmt.Sprintf("bin/%v_%v/syz-executor", target.OS, target.Arch)] = true
		}
	}
	compilerID, err := osutil.RunCmd(time.Minute, "", "go", "version")
	if err != nil {
		return nil, err
	}
	return &Updater{
		repo:         vcs.NewSyzkallerRepo(syzkallerDir),
		exe:          exe,
		repoAddress:  cfg.SyzkallerRepo,
		branch:       cfg.SyzkallerBranch,
		descriptions: cfg.SyzkallerDescriptions,
		gopathDir:    gopath,
		syzkallerDir: syzkallerDir,
		latestDir:    filepath.Join("syzkaller", "latest"),
		currentDir:   filepath.Join("syzkaller", "current"),
		syzFiles:     syzFiles,
		compilerID:   strings.TrimSpace(string(compilerID)),
		cfg:          cfg,
	}, nil
}

// UpdateOnStart does 3 things:
//   - ensures that the current executable is fresh
//   - ensures that we have a working syzkaller build in current
func (upd *Updater) UpdateOnStart(autoupdate bool, updatePending, shutdown chan struct{}) {
	if autoupdate {
		defer func() {
			go func() {
				upd.waitForUpdate()
				close(updatePending)
			}()
		}()
	}

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
			break
		}

		// No good build at all, try again later.
		log.Logf(0, "retrying in %v", BuildRetryPeriod)
		select {
		case <-time.After(BuildRetryPeriod):
		case <-shutdown:
			os.Exit(0)
		}
	}
}

// waitForUpdate polls and rebuilds syzkaller.
// Returns when we have a new good build in latest.
func (upd *Updater) waitForUpdate() {
	time.Sleep(RebuildPeriod)
	latestTag := upd.checkLatest()
	lastCommit := latestTag
	for {
		lastCommit = upd.pollAndBuild(lastCommit)
		if latestTag != upd.checkLatest() {
			break
		}
		time.Sleep(BuildRetryPeriod)
	}
	log.Logf(0, "syzkaller: update available, restarting")
}

// UpdateAndRestart updates and restarts the current executable.
// If ExitOnUpdate is set, exits without restarting instead.
// Does not return.
func (upd *Updater) UpdateAndRestart() {
	log.Logf(0, "restarting executable for update")
	latestBin := filepath.Join(upd.latestDir, "bin", upd.exe)
	if err := osutil.CopyFile(latestBin, upd.exe); err != nil {
		log.Fatal(err)
	}
	if upd.cfg.ExitOnUpdate {
		log.Logf(0, "exiting, please restart syz-ci to run the new version")
		os.Exit(0)
	}
	if err := syscall.Exec(upd.exe, os.Args, os.Environ()); err != nil {
		log.Fatal(err)
	}
	log.Fatalf("not reachable")
}

func (upd *Updater) pollAndBuild(lastCommit string) string {
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
		log.Errorf("syzkaller: failed to build: %v", err)
		if upd.cfg.ReportBuildError != nil {
			upd.cfg.ReportBuildError(commit, upd.compilerID, err)
		}
	}
	return commit.Hash
}

func (upd *Updater) build(commit *vcs.Commit) error {
	// syzkaller testing may be slowed down by concurrent kernel builds too much
	// and cause timeout failures, so we serialize it with other builds:
	// https://groups.google.com/forum/#!msg/syzkaller-openbsd-bugs/o-G3vEsyQp4/f_nFpoNKBQAJ
	upd.cfg.BuildSem.Wait()
	defer upd.cfg.BuildSem.Signal()

	if upd.descriptions != "" {
		files, err := os.ReadDir(upd.descriptions)
		if err != nil {
			return fmt.Errorf("failed to read descriptions dir: %w", err)
		}
		for _, f := range files {
			src := filepath.Join(upd.descriptions, f.Name())
			dst := ""
			switch filepath.Ext(src) {
			case ".txt", ".const":
				dst = filepath.Join(upd.syzkallerDir, "sys", targets.Linux, f.Name())
			case ".test":
				dst = filepath.Join(upd.syzkallerDir, "sys", targets.Linux, "test", f.Name())
			case ".h":
				dst = filepath.Join(upd.syzkallerDir, "executor", f.Name())
			default:
				continue
			}
			if err := osutil.CopyFile(src, dst); err != nil {
				return err
			}
		}
	}
	// This will also generate descriptions and should go before the 'go test' below.
	cmd := osutil.Command(instance.MakeBin, "host", "ci", "agent")
	cmd.Dir = upd.syzkallerDir
	cmd.Env = append([]string{"GOPATH=" + upd.gopathDir}, os.Environ()...)
	if _, err := osutil.Run(time.Hour, cmd); err != nil {
		return fmt.Errorf("make host failed: %w", err)
	}
	for target := range upd.cfg.Targets {
		cmd = osutil.Command(instance.MakeBin, "target")
		cmd.Dir = upd.syzkallerDir
		cmd.Env = append([]string{}, os.Environ()...)
		cmd.Env = append(cmd.Env,
			"GOPATH="+upd.gopathDir,
			"TARGETOS="+target.OS,
			"TARGETVMARCH="+target.VMArch,
			"TARGETARCH="+target.Arch,
		)
		if _, err := osutil.Run(time.Hour, cmd); err != nil {
			return fmt.Errorf("make target failed: %w", err)
		}
	}
	cmd = osutil.Command("go", "test", "-short", "./...")
	cmd.Dir = upd.syzkallerDir
	cmd.Env = append([]string{
		"GOPATH=" + upd.gopathDir,
		"SYZ_DISABLE_SANDBOXING=yes",
	}, os.Environ()...)
	if _, err := osutil.Run(time.Hour, cmd); err != nil {
		return fmt.Errorf("testing failed: %w", err)
	}
	tagFile := filepath.Join(upd.syzkallerDir, "tag")
	if err := osutil.WriteFile(tagFile, []byte(commit.Hash)); err != nil {
		return fmt.Errorf("failed to write tag file: %w", err)
	}
	if err := osutil.CopyFiles(upd.syzkallerDir, upd.latestDir, upd.syzFiles); err != nil {
		return fmt.Errorf("failed to copy syzkaller: %w", err)
	}
	return nil
}

// checkLatest returns tag of the latest build,
// or an empty string if latest build is missing/broken.
func (upd *Updater) checkLatest() string {
	if !osutil.FilesExist(upd.latestDir, upd.syzFiles) {
		return ""
	}
	tag, _ := os.ReadFile(filepath.Join(upd.latestDir, "tag"))
	return string(tag)
}
