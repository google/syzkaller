// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package covermerger

import (
	"fmt"
	"sync"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/sys/targets"
)

type FileVersProvider interface {
	GetFileVersions(c *Config, targetFilePath string, rbcs []RepoBranchCommit,
	) (fileVersions, error)
}

type monoRepo struct {
	repoCommits map[RepoBranchCommit]struct{}
	mu          sync.RWMutex
	repo        vcs.Repo
}

type fileVersions map[RepoBranchCommit]string

func (mr *monoRepo) GetFileVersions(c *Config, targetFilePath string, rbcs []RepoBranchCommit,
) (fileVersions, error) {
	mr.mu.RLock()
	if !mr.allRepoCommitsPresent(rbcs) {
		mr.mu.RUnlock()
		mr.cloneCommits(rbcs)
		mr.mu.RLock()
	}
	defer mr.mu.RUnlock()
	res := make(fileVersions)
	for _, rbc := range rbcs {
		fileBytes, err := mr.repo.Object(targetFilePath, rbc.Commit)
		// It is ok if some file doesn't exist. It means we have repo FS diff.
		// Or the upstream commit doesn't exist anymore
		if err != nil {
			log.Logf(1, "repo.Object(%s, %s) error: %s", targetFilePath, rbc.Commit, err.Error())
			continue
		}
		res[rbc] = string(fileBytes)
	}
	return res, nil
}

func (mr *monoRepo) allRepoCommitsPresent(rbcs []RepoBranchCommit) bool {
	for _, rbc := range rbcs {
		if !mr.repoCommitPresent(rbc) {
			return false
		}
	}
	return true
}

func (mr *monoRepo) repoCommitPresent(rbc RepoBranchCommit) bool {
	rbc.Branch = ""
	_, ok := mr.repoCommits[rbc]
	return ok
}

func (mr *monoRepo) addRepoCommit(rbc RepoBranchCommit) {
	log.Logf(0, "cloning repo: %s, branch: %s, commit %s", rbc.Repo, rbc.Branch, rbc.Commit)
	rbc.Branch = ""
	mr.repoCommits[rbc] = struct{}{}
	if rbc.Repo == "" || rbc.Commit == "" {
		panic("repo and commit are needed")
	}
	if _, err := mr.repo.CheckoutCommit(rbc.Repo, rbc.Commit); err != nil {
		log.Logf(0, "failed to CheckoutCommit(repo %s, commit %s): %s",
			rbc.Repo, rbc.Commit, err.Error())
	}
}

func MakeMonoRepo(workdir string) FileVersProvider {
	rbcPath := workdir + "/repos/linux_kernels"
	mr := &monoRepo{
		repoCommits: map[RepoBranchCommit]struct{}{},
	}
	var err error
	if mr.repo, err = vcs.NewRepo(targets.Linux, "none", rbcPath); err != nil {
		panic(fmt.Sprintf("failed to create/open repo at %s: %s", rbcPath, err.Error()))
	}
	return mr
}

func (mr *monoRepo) cloneCommits(rbcs []RepoBranchCommit) {
	mr.mu.Lock()
	defer mr.mu.Unlock()
	for _, rbc := range rbcs {
		if mr.repoCommitPresent(rbc) {
			continue
		}
		mr.addRepoCommit(rbc)
	}
}
