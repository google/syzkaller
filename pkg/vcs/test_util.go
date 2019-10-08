package vcs

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
)

const (
	userEmail           = `test@syzkaller.com`
	userName            = `Test Syzkaller`
	extractFixTagsEmail = `"syzbot" <syzbot@my.mail.com>`
)

type testWriter testing.T

func (t *testWriter) Write(data []byte) (int, error) {
	(*testing.T)(t).Log(string(data))
	return len(data), nil
}

type TestRepo struct {
	t       *testing.T
	Dir     string
	name    string
	Commits map[string]map[string]*Commit
	repo    *git
}

func (repo *TestRepo) git(args ...string) {
	if _, err := osutil.RunCmd(time.Minute, repo.Dir, "git", args...); err != nil {
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
	repo.git("init")
	repo.git("config", "--add", "user.email", userEmail)
	repo.git("config", "--add", "user.name", userName)
	return repo
}

func (repo *TestRepo) CommitFileChange(branch, change string) {
	id := fmt.Sprintf("%v-%v-%v", repo.name, branch, change)
	file := filepath.Join(repo.Dir, "file")
	if err := osutil.WriteFile(file, []byte(id)); err != nil {
		repo.t.Fatal(err)
	}
	repo.git("add", file)
	repo.git("commit", "-m", id)
	if repo.Commits[branch] == nil {
		repo.Commits[branch] = make(map[string]*Commit)
	}
	com, err := repo.repo.HeadCommit()
	if err != nil {
		repo.t.Fatal(err)
	}
	repo.Commits[branch][change] = com
}

func (repo *TestRepo) CommitChange(description string) {
	repo.git("commit", "--allow-empty", "-m", description)
}

func (repo *TestRepo) SetTag(tag string) {
	repo.git("tag", tag)
}

func CreateTestRepo(t *testing.T, baseDir, name string) *TestRepo {
	repo := MakeTestRepo(t, filepath.Join(baseDir, name))
	repo.git("checkout", "-b", "master")
	repo.CommitFileChange("master", "0")
	for _, branch := range []string{"branch1", "branch2"} {
		repo.git("checkout", "-b", branch, "master")
		repo.CommitFileChange(branch, "0")
		repo.CommitFileChange(branch, "1")
	}
	repo.git("checkout", "master")
	repo.CommitFileChange("master", "1")
	return repo
}

func CloneTestRepo(t *testing.T, baseDir string, name string, originRepo *TestRepo) *TestRepo {
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
	repo.git("clone", originRepo.Dir, repo.Dir)
	return repo
}
