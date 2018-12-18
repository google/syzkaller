// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vcs

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/syzkaller/pkg/osutil"
)

func init() {
	// Disable sandboxing entirely because we create test repos without sandboxing.
	os.Setenv("SYZ_DISABLE_SANDBOXING", "yes")
}

func TestGitRepo(t *testing.T) {
	baseDir, err := ioutil.TempDir("", "syz-git-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(baseDir)
	repo1 := createTestRepo(t, baseDir, "repo1")
	repo2 := createTestRepo(t, baseDir, "repo2")
	repo := newGit(filepath.Join(baseDir, "repo"))
	{
		com, err := repo.Poll(repo1.dir, "master")
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(com, repo1.commits["master"]["1"]); diff != "" {
			t.Fatal(diff)
		}
	}
	{
		com, err := repo.CheckoutBranch(repo1.dir, "branch1")
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(com, repo1.commits["branch1"]["1"]); diff != "" {
			t.Fatal(diff)
		}
	}
	{
		want := repo1.commits["branch1"]["0"]
		com, err := repo.CheckoutCommit(repo1.dir, want.Hash)
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(com, want); diff != "" {
			t.Fatal(diff)
		}
	}
	{
		commits, err := repo.ListRecentCommits(repo1.commits["branch1"]["1"].Hash)
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"repo1-branch1-1", "repo1-branch1-0", "repo1-master-0"}
		if diff := cmp.Diff(commits, want); diff != "" {
			t.Fatal(diff)
		}
	}
	{
		want := repo2.commits["branch1"]["0"]
		com, err := repo.CheckoutCommit(repo2.dir, want.Hash)
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(com, want); diff != "" {
			t.Fatal(diff)
		}
	}
	{
		want := repo2.commits["branch1"]["1"]
		com, err := repo.CheckoutCommit(repo2.dir, want.Hash)
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(com, want); diff != "" {
			t.Fatal(diff)
		}
	}
	{
		com, err := repo.CheckoutBranch(repo2.dir, "branch2")
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(com, repo2.commits["branch2"]["1"]); diff != "" {
			t.Fatal(diff)
		}
	}
	{
		want := repo2.commits["branch2"]["0"]
		com, err := repo.SwitchCommit(want.Hash)
		if err != nil {
			t.Fatal(err)
		}
		if diff := cmp.Diff(com, want); diff != "" {
			t.Fatal(diff)
		}
	}
}

func createTestRepo(t *testing.T, baseDir, name string) *testRepo {
	repo := makeTestRepo(t, filepath.Join(baseDir, name))
	repo.git("checkout", "-b", "master")
	repo.commitFileChange("master", "0")
	for _, branch := range []string{"branch1", "branch2"} {
		repo.git("checkout", "-b", branch, "master")
		repo.commitFileChange(branch, "0")
		repo.commitFileChange(branch, "1")
	}
	repo.git("checkout", "master")
	repo.commitFileChange("master", "1")
	return repo
}

type testRepo struct {
	t       *testing.T
	dir     string
	name    string
	commits map[string]map[string]*Commit
}

func makeTestRepo(t *testing.T, dir string) *testRepo {
	if err := osutil.MkdirAll(dir); err != nil {
		t.Fatal(err)
	}
	repo := &testRepo{
		t:       t,
		dir:     dir,
		name:    filepath.Base(dir),
		commits: make(map[string]map[string]*Commit),
	}
	repo.git("init")
	return repo
}

func (repo *testRepo) git(args ...string) {
	if _, err := osutil.RunCmd(time.Minute, repo.dir, "git", args...); err != nil {
		repo.t.Fatal(err)
	}
}

func (repo *testRepo) commitFileChange(branch, change string) {
	id := fmt.Sprintf("%v-%v-%v", repo.name, branch, change)
	file := filepath.Join(repo.dir, "file")
	if err := osutil.WriteFile(file, []byte(id)); err != nil {
		repo.t.Fatal(err)
	}
	repo.git("add", file)
	repo.git("commit", "-m", id)
	if repo.commits[branch] == nil {
		repo.commits[branch] = make(map[string]*Commit)
	}
	com, err := newGit(repo.dir).HeadCommit()
	if err != nil {
		repo.t.Fatal(err)
	}
	repo.commits[branch][change] = com
}
