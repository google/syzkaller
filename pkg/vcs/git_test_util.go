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
	cmd := osutil.Command("git", args...)
	cmd.Dir = repo.Dir
	cmd.Env = filterEnv()

	if _, err := osutil.Run(time.Minute, cmd); err != nil {
		repo.t.Fatal(err)
	}
}

func MakeTestRepo(t *testing.T, dir string) *TestRepo {
	if err := osutil.MkdirAll(dir); err != nil {
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
		repo:    newGitRepo(dir, ignoreCC, []RepoOpt{OptPrecious, OptDontSandbox}),
	}
	repo.Git("init")
	repo.Git("config", "--add", "user.email", userEmail)
	repo.Git("config", "--add", "user.name", userName)
	return repo
}

func (repo *TestRepo) CommitFileChange(branch, change string) {
	id := fmt.Sprintf("%v-%v-%v", repo.name, branch, change)
	file := filepath.Join(repo.Dir, "file")
	if err := osutil.WriteFile(file, []byte(id)); err != nil {
		repo.t.Fatal(err)
	}
	repo.Git("add", file)
	repo.Git("commit", "-m", id)
	if repo.Commits[branch] == nil {
		repo.Commits[branch] = make(map[string]*Commit)
	}
	com, err := repo.repo.Commit(HEAD)
	if err != nil {
		repo.t.Fatal(err)
	}
	repo.Commits[branch][change] = com
}

func (repo *TestRepo) CommitChange(description string) *Commit {
	return repo.CommitChangeset(description)
}

type FileContent struct {
	File    string
	Content string
}

func (fc *FileContent) Apply(repo *TestRepo) error {
	err := os.WriteFile(filepath.Join(repo.Dir, fc.File), []byte(fc.Content), 0644)
	if err != nil {
		return err
	}
	repo.Git("add", fc.File)
	return nil
}

func (repo *TestRepo) CommitChangeset(description string, actions ...FileContent) *Commit {
	for i, action := range actions {
		if err := action.Apply(repo); err != nil {
			repo.t.Fatalf("failed to apply action %d: %v", i, err)
		}
	}
	repo.Git("commit", "--allow-empty", "-m", description)
	com, err := repo.repo.Commit(HEAD)
	if err != nil {
		repo.t.Fatal(err)
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
