// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package covermerger

//go:generate ../../tools/mockery.sh --name FileVersProvider -r

import (
	"fmt"
	"path/filepath"
	"sync"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/sys/targets"
)

type FileVersProvider interface {
	GetFileVersions(targetFilePath string, repoCommits ...RepoCommit,
	) (FileVersions, error)
}

type monoRepo struct {
	repoCommits map[RepoCommit]struct{}
	mu          sync.RWMutex
	repo        vcs.Repo
}

type FileVersions map[RepoCommit]string

func (mr *monoRepo) GetFileVersions(targetFilePath string, repoCommits ...RepoCommit,
) (FileVersions, error) {
	mr.mu.RLock()
	if !mr.allRepoCommitsPresent(repoCommits) {
		mr.mu.RUnlock()
		mr.cloneCommits(repoCommits)
		mr.mu.RLock()
	}
	defer mr.mu.RUnlock()
	res := make(FileVersions)
	for _, repoCommit := range repoCommits {
		fileBytes, err := mr.repo.Object(targetFilePath, repoCommit.Commit)
		// It is ok if some file doesn't exist. It means we have repo FS diff.
		// Or the upstream commit doesn't exist anymore
		if err != nil {
			log.Logf(1, "repo.Object(%s, %s) error: %s", targetFilePath, repoCommit.Commit, err.Error())
			continue
		}
		res[repoCommit] = string(fileBytes)
	}
	return res, nil
}

func (mr *monoRepo) allRepoCommitsPresent(repoCommits []RepoCommit) bool {
	for _, repoCommit := range repoCommits {
		if _, exists := mr.repoCommits[repoCommit]; !exists {
			return false
		}
	}
	return true
}

func (mr *monoRepo) addRepoCommit(repoCommit RepoCommit) {
	log.Logf(0, "cloning repo: %s, commit %s", repoCommit.Repo, repoCommit.Commit)
	mr.repoCommits[repoCommit] = struct{}{}
	repo, commit := repoCommit.Repo, repoCommit.Commit
	if repo == "" || commit == "" {
		panic("repo and commit are needed")
	}
	if _, err := mr.repo.CheckoutCommit(repo, commit); err != nil {
		log.Logf(0, "failed to CheckoutCommit(repo %s, commit %s): %s", repo, commit, err.Error())
	}
}

func MakeMonoRepo(workdir string) FileVersProvider {
	repoPath := filepath.Join(workdir, "repos", "linux_kernels")
	mr := &monoRepo{
		repoCommits: map[RepoCommit]struct{}{},
	}
	var err error
	if mr.repo, err = vcs.NewRepo(targets.Linux, "none", repoPath); err != nil {
		panic(fmt.Sprintf("failed to create/open repo at %s: %s", repoPath, err.Error()))
	}
	return mr
}

func (mr *monoRepo) cloneCommits(repoCommits []RepoCommit) {
	mr.mu.Lock()
	defer mr.mu.Unlock()
	for _, repoCommit := range repoCommits {
		if _, exists := mr.repoCommits[repoCommit]; exists {
			continue
		}
		commitExistsInRepo, err := mr.repo.CommitExists(repoCommit.Commit)
		if err != nil {
			log.Logf(0, "can't check CommitExists: %s", err.Error())
		}
		if commitExistsInRepo {
			mr.repoCommits[repoCommit] = struct{}{}
			continue
		}
		mr.addRepoCommit(repoCommit)
	}
}
