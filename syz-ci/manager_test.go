// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"testing"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type dashapiMock struct {
	mock.Mock
}

func (dm *dashapiMock) BuilderPoll(manager string) (*dashapi.BuilderPollResp, error) {
	args := dm.Called(manager)
	return args.Get(0).(*dashapi.BuilderPollResp), args.Error(1)
}

// We don't care about the methods below for now.
func (dm *dashapiMock) ReportBuildError(req *dashapi.BuildErrorReq) error { return nil }
func (dm *dashapiMock) UploadBuild(build *dashapi.Build) error            { return nil }
func (dm *dashapiMock) LogError(name, msg string, args ...interface{})    {}
func (dm *dashapiMock) CommitPoll() (*dashapi.CommitPollResp, error)      { return nil, nil }
func (dm *dashapiMock) UploadCommits(commits []dashapi.Commit) error      { return nil }

func TestManagerPollCommits(t *testing.T) {
	// Mock a repository.
	baseDir := t.TempDir()
	repo := vcs.CreateTestRepo(t, baseDir, "")
	var lastCommit *vcs.Commit
	for _, title := range []string{
		"unrelated commit one",
		"commit1 title",
		"unrelated commit two",
		"commit3 title",
		`title with fix

Reported-by: foo+abcd000@bar.com`,
		"unrelated commit three",
	} {
		lastCommit = repo.CommitChange(title)
	}

	vcsRepo, err := vcs.NewRepo(targets.TestOS, targets.TestArch64, baseDir, vcs.OptPrecious)
	if err != nil {
		t.Fatal(err)
	}

	mock := new(dashapiMock)
	mgr := Manager{
		name:   "test-manager",
		dash:   mock,
		repo:   vcsRepo,
		mgrcfg: &ManagerConfig{},
	}

	// Mock BuilderPoll().
	commits := []string{
		"commit1 title",
		"commit2 title",
		"commit3 title",
		"commit4 title",
	}
	// Let's trigger sampling as well.
	for i := 0; i < 100; i++ {
		commits = append(commits, fmt.Sprintf("test%d", i))
	}
	mock.On("BuilderPoll", "test-manager").Return(&dashapi.BuilderPollResp{
		PendingCommits: commits,
		ReportEmail:    "foo@bar.com",
	}, nil)

	matches, fixCommits, err := mgr.pollCommits(lastCommit.Hash)
	if err != nil {
		t.Fatal(err)
	}

	foundCommits := map[string]bool{}
	// Call it several more times to catch all commits.
	for i := 0; i < 100; i++ {
		for _, name := range matches {
			foundCommits[name] = true
		}
		matches, _, err = mgr.pollCommits(lastCommit.Hash)
		if err != nil {
			t.Fatal(err)
		}
	}

	var foundCommitsSlice []string
	for title := range foundCommits {
		foundCommitsSlice = append(foundCommitsSlice, title)
	}
	assert.ElementsMatch(t, foundCommitsSlice, []string{
		"commit1 title", "commit3 title",
	})
	assert.Len(t, fixCommits, 1)
	commit := fixCommits[0]
	assert.Equal(t, commit.Title, "title with fix")
	assert.ElementsMatch(t, commit.BugIDs, []string{"abcd000"})
}
