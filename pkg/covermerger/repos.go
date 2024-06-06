// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package covermerger

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/sys/targets"
)

type fileVersion struct {
	content     string
	lastUpdated time.Time
}

type fileVersions map[RepoBranchCommit]fileVersion

func getFileVersions(c *Config, targetFilePath string, rbcs []RepoBranchCommit,
) (fileVersions, error) {
	repos, err := CloneRepos(c, rbcs)
	if err != nil {
		return nil, fmt.Errorf("failed to clone repos: %w", err)
	}

	res := make(fileVersions)
	for _, rbc := range rbcs {
		fileBytes, err := repos[rbc].FileVersion(targetFilePath, rbc.Commit)
		// It is ok if some file doesn't exist. It means we have repo FS diff.
		if err != nil {
			continue
		}
		var lastUpdated time.Time
		if c.BaseType == BaseLastUpdated {
			if lastUpdated, err = repos[rbc].FileEditTime(targetFilePath); err != nil {
				return nil, fmt.Errorf("failed to get file %s modification date: %w",
					targetFilePath, err)
			}
		}
		res[rbc] = fileVersion{
			content:     string(fileBytes),
			lastUpdated: lastUpdated,
		}
	}
	return res, nil
}

func CloneRepos(c *Config, rbcs []RepoBranchCommit) (map[RepoBranchCommit]vcs.Repo, error) {
	repos := make(map[RepoBranchCommit]vcs.Repo)
	for _, rbc := range rbcs {
		rbcPath := c.Workdir + "/repos/" + folderName(rbc)
		repo, err := vcs.NewRepo(targets.Linux, "none", rbcPath)
		if err != nil {
			return nil, fmt.Errorf("failed to create/open repo at %s: %w", rbcPath, err)
		}
		repos[rbc] = repo
		if _, err := os.Stat(rbcPath + "/virt"); err == nil || c.skipRepoClone {
			continue
		}
		log.Printf("cloning %s to init %s", rbc.Repo, rbcPath)
		if _, err = repo.Poll(rbc.Repo, rbc.Branch); err != nil {
			return nil, fmt.Errorf("failed to poll branch %s from repo %s to folder %s: %w",
				rbc.Branch, rbc.Repo, rbcPath, err)
		}
	}
	return repos, nil
}

func folderName(rbc RepoBranchCommit) string {
	name := rbc.Repo + "-" + rbc.Branch
	fName := ""
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !(c >= 'a' && c <= 'z' ||
			c >= 'A' && c <= 'Z' ||
			c >= '0' && c <= '9' || c == '.') {
			c = '-'
		}
		fName = fName + string(c)
	}
	return fName
}

func LatestRepoCommit(repoName string, repos map[RepoBranchCommit]vcs.Repo) string {
	var res string
	var resDate time.Time
	for rbc, repo := range repos {
		if rbc.Repo != repoName {
			continue
		}
		commit, err := repo.HeadCommit()
		if err != nil {
			panic(err)
		}
		if commit.CommitDate.After(resDate) {
			res = rbc.Commit
			resDate = commit.CommitDate
		}
	}
	return res
}
