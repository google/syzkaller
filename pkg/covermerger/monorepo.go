// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package covermerger

import (
	"fmt"
	"log"
	"sync"

	"github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/sys/targets"
)

type fileVersProvider interface {
	GetFileVersions(c *Config, targetFilePath string, rbcs []RepoBranchCommit,
	) (fileVersions, error)
}

type monoRepo struct {
	branches map[RepoBranchCommit]struct{}
	mu       sync.RWMutex
	repo     vcs.Repo
}

type fileVersions map[RepoBranchCommit]string

func (mr *monoRepo) GetFileVersions(c *Config, targetFilePath string, rbcs []RepoBranchCommit,
) (fileVersions, error) {
	mr.mu.RLock()
	if !mr.allRepoBranchesPresent(rbcs) {
		mr.mu.RUnlock()
		if err := mr.cloneBranches(rbcs); err != nil {
			return nil, fmt.Errorf("failed to clone repos: %w", err)
		}
		mr.mu.RLock()
	}
	defer mr.mu.RUnlock()
	res := make(fileVersions)
	for _, rbc := range rbcs {
		fileBytes, err := mr.repo.Object(targetFilePath, rbc.Commit)
		// It is ok if some file doesn't exist. It means we have repo FS diff.
		if err != nil {
			continue
		}
		res[rbc] = string(fileBytes)
	}
	return res, nil
}

func (mr *monoRepo) allRepoBranchesPresent(rbcs []RepoBranchCommit) bool {
	for _, rbc := range rbcs {
		if !mr.repoBranchPresent(rbc) {
			return false
		}
	}
	return true
}

func (mr *monoRepo) repoBranchPresent(rbc RepoBranchCommit) bool {
	rbc.Commit = ""
	_, ok := mr.branches[rbc]
	return ok
}

func (mr *monoRepo) addRepoBranch(rbc RepoBranchCommit) error {
	rbc.Commit = ""
	mr.branches[rbc] = struct{}{}
	log.Printf("cloning repo: %s, branch: %s", rbc.Repo, rbc.Branch)
	if rbc.Repo == "" || rbc.Branch == "" {
		panic("repo and branch are needed")
	}
	if _, err := mr.repo.CheckoutBranch(rbc.Repo, rbc.Branch); err != nil {
		return fmt.Errorf("failed to CheckoutBranch(repo %s, branch %s): %w",
			rbc.Repo, rbc.Branch, err)
	}
	return nil
}

func MakeMonoRepo(workdir string) fileVersProvider {
	rbcPath := workdir + "/repos/linux_kernels"
	mr := &monoRepo{
		branches: map[RepoBranchCommit]struct{}{},
	}
	var err error
	if mr.repo, err = vcs.NewRepo(targets.Linux, "none", rbcPath); err != nil {
		panic(fmt.Sprintf("failed to create/open repo at %s: %s", rbcPath, err.Error()))
	}
	return mr
}

func (mr *monoRepo) cloneBranches(rbcs []RepoBranchCommit) error {
	mr.mu.Lock()
	defer mr.mu.Unlock()
	for _, rbc := range rbcs {
		if mr.repoBranchPresent(rbc) {
			continue
		}
		if err := mr.addRepoBranch(rbc); err != nil {
			return err
		}
	}
	return nil
}
