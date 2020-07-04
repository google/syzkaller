// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vcs

import (
	"fmt"
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
	repo    *git
}

func (repo *TestRepo) Git(args ...string) {
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
		repo:    newGit(dir, ignoreCC),
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
	com, err := repo.repo.HeadCommit()
	if err != nil {
		repo.t.Fatal(err)
	}
	repo.Commits[branch][change] = com
}

func (repo *TestRepo) CommitChange(description string) *Commit {
	repo.Git("commit", "--allow-empty", "-m", description)
	com, err := repo.repo.HeadCommit()
	if err != nil {
		repo.t.Fatal(err)
	}
	return com
}

func (repo *TestRepo) SetTag(tag string) {
	repo.Git("tag", tag)
}

func (repo *TestRepo) SupportsBisection() bool {
	// Detect too old git binary. --no-contains appeared in git 2.13.
	_, err := repo.repo.previousReleaseTags("HEAD", true)
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

func CloneTestRepo(t *testing.T, baseDir, name string, originRepo *TestRepo) *TestRepo {
	dir := filepath.Join(baseDir, name)
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
		repo:    newGit(dir, ignoreCC),
	}
	repo.Git("clone", originRepo.Dir, repo.Dir)
	return repo
}
