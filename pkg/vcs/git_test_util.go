// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vcs

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
)

const (
	userEmail           = `test@syzkaller.com`
	userName            = `Test Syzkaller`
	extractFixTagsEmail = `"syzbot" <syzbot@my.mail.com>`
)

type TestRepo struct {
	t       *testing.T
	Dir     string
	name    string
	Commits map[string]map[string]*Commit
	repo    *gitRepo
}

func (repo *TestRepo) Git(args ...string) {
	repo.t.Helper()
	if _, err := repo.repo.Run(args...); err != nil {
		repo.t.Fatal(osutil.VerboseMessage(err))
	}
}

func MakeTestRepo(t *testing.T, dir string) *TestRepo {
	if err := osutil.MkdirAll(dir); err != nil {
		t.Fatal(err)
	}
	// t.TempDir() creates 0700 dirs that the sandbox user can't traverse,
	// so make dir and its ancestors below os.TempDir() world-traversable.
	// dir must be under os.TempDir(), otherwise the loop would make every
	// ancestor of dir up to / world-traversable.
	absDir, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	tmpDir := filepath.Clean(os.TempDir())
	if rel, err := filepath.Rel(tmpDir, absDir); err != nil || rel == "." || !filepath.IsLocal(rel) {
		t.Fatalf("test repo dir %q must be a subdir of %q", dir, tmpDir)
	}
	for p := absDir; p != tmpDir; p = filepath.Dir(p) {
		if err := os.Chmod(p, osutil.DefaultDirPerm); err != nil {
			t.Fatal(err)
		}
	}
	if err := osutil.SandboxChown(dir); err != nil {
		t.Fatal(err)
	}
	ignoreCC := map[string]bool{
		"stable@vger.kernel.org": true,
	}
	repo := &TestRepo{
		t:       t,
		Dir:     dir,
		name:    filepath.Base(dir),
		Commits: make(map[string]map[string]*Commit),
		repo:    newGitRepo(dir, ignoreCC, []RepoOpt{OptPrecious}),
	}
	repo.Git("init")
	repo.Git("config", "--add", "user.email", userEmail)
	repo.Git("config", "--add", "user.name", userName)
	repo.Git("config", "--add", "gc.auto", "0")
	repo.Git("config", "--add", "gc.autoDetach", "false")
	repo.Git("config", "--add", "maintenance.auto", "false")
	repo.Git("config", "--add", "maintenance.autoDetach", "false")
	return repo
}

func (repo *TestRepo) CommitFileChange(branch, change string) {
	id := fmt.Sprintf("%v-%v-%v", repo.name, branch, change)
	file := filepath.Join(repo.Dir, "file")
	osutil.WriteSandboxFile(repo.t, file, []byte(id))
	repo.Git("add", file)
	repo.Git("commit", "-m", id)
	if repo.Commits[branch] == nil {
		repo.Commits[branch] = make(map[string]*Commit)
	}
	com, err := repo.repo.Commit(HEAD)
	if err != nil {
		repo.t.Fatal(osutil.VerboseMessage(err))
	}
	repo.Commits[branch][change] = com
}

func (repo *TestRepo) CommitChange(description string) *Commit {
	return repo.CommitChangeset(description)
}

func (repo *TestRepo) CommitChangeAt(description string, date time.Time) {
	dateStr := date.Format(time.RFC3339)
	git := Git{
		Dir:     repo.Dir,
		Sandbox: true,
		Env: append(filterEnv(),
			"GIT_AUTHOR_DATE="+dateStr,
			"GIT_COMMITTER_DATE="+dateStr,
		),
	}
	if _, err := git.Run("commit", "--allow-empty", "-m", description); err != nil {
		repo.t.Fatal(err)
	}
}

type FileContent struct {
	File    string
	Content string
}

func (fc *FileContent) Apply(repo *TestRepo) {
	repo.t.Helper()
	osutil.WriteSandboxFile(repo.t, filepath.Join(repo.Dir, fc.File), []byte(fc.Content))
	repo.Git("add", fc.File)
}

func (repo *TestRepo) CommitChangeset(description string, actions ...FileContent) *Commit {
	for _, action := range actions {
		action.Apply(repo)
	}
	repo.Git("commit", "--allow-empty", "-m", description)
	com, err := repo.repo.Commit(HEAD)
	if err != nil {
		repo.t.Fatal(osutil.VerboseMessage(err))
	}
	repo.t.Logf("%q's hash is %s", description, com.Hash)
	return com
}

func (repo *TestRepo) SetTag(tag string) {
	repo.Git("tag", tag)
}

func (repo *TestRepo) SupportsBisection() bool {
	// Detect too old git binary. --no-contains appeared in git 2.13.
	_, err := repo.repo.previousReleaseTags("HEAD", true, false, false)
	return err == nil ||
		!strings.Contains(err.Error(), "usage: git tag") &&
			!strings.Contains(err.Error(), "error: unknown option")
}

func CreateTestRepo(t *testing.T, baseDir, name string) *TestRepo {
	repo := MakeTestRepo(t, filepath.Join(baseDir, name))
	repo.Git("checkout", "-b", "master")
	repo.CommitFileChange("master", "0")
	for _, branch := range []string{"branch1", "branch2"} {
		repo.Git("checkout", "-b", branch, "master")
		repo.CommitFileChange(branch, "0")
		repo.CommitFileChange(branch, "1")
	}
	repo.Git("checkout", "master")
	repo.CommitFileChange("master", "1")
	return repo
}
