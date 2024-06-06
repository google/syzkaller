// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package covermerger

import (
	"fmt"
	"log"

	"github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/sys/targets"
)

type fileVersion struct {
	content string
}

type fileVersions map[RepoBranchCommit]fileVersion

func getFileVersions(c *Config, targetFilePath string, rbcs []RepoBranchCommit,
) (fileVersions, error) {
	repos, err := cloneRepos(c, rbcs)
	if err != nil {
		return nil, fmt.Errorf("failed to clone repos: %w", err)
	}

	res := make(fileVersions)
	for _, rbc := range rbcs {
		fileBytes, err := repos[rbc].Object(targetFilePath, rbc.Commit)
		// It is ok if some file doesn't exist. It means we have repo FS diff.
		if err != nil {
			continue
		}
		res[rbc] = fileVersion{
			content: string(fileBytes),
		}
	}
	return res, nil
}

type repoCache struct {
	cache map[RepoBranchCommit]vcs.Repo
}

func (rc *repoCache) get(rbc RepoBranchCommit) vcs.Repo {
	rbc.Commit = ""
	if repo, ok := rc.cache[rbc]; ok {
		return repo
	}
	return nil
}

func (rc *repoCache) put(rbc RepoBranchCommit, repo vcs.Repo) {
	rbc.Commit = ""
	if rc.cache == nil {
		rc.cache = map[RepoBranchCommit]vcs.Repo{}
	}
	rc.cache[rbc] = repo
}

func cloneRepos(c *Config, rbcs []RepoBranchCommit) (map[RepoBranchCommit]vcs.Repo, error) {
	cache := &c.repoCache
	repos := make(map[RepoBranchCommit]vcs.Repo)
	for _, rbc := range rbcs {
		repos[rbc] = cache.get(rbc)
		if repos[rbc] != nil {
			continue
		}
		rbcPath := c.Workdir + "/repos/linux_kernels"
		repo, err := vcs.NewRepo(targets.Linux, "none", rbcPath)
		if err != nil {
			return nil, fmt.Errorf("failed to create/open repo at %s: %w", rbcPath, err)
		}
		repos[rbc] = repo
		cache.put(rbc, repo)
		if c.skipRepoClone {
			continue
		}
		log.Printf("cloning repo: %s, branch: %s", rbc.Repo, rbc.Branch)
		if rbc.Branch == "" {
			panic("repo and branch are needed")
		}
		if _, err = repo.CheckoutBranch(rbc.Repo, rbc.Branch); err != nil {
			return nil, fmt.Errorf("failed to CheckoutBranch(repo %s, branch %s): %w",
				rbc.Repo, rbc.Branch, err)
		}
	}
	return repos, nil
}
