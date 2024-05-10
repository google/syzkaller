// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package covermerger

import (
	"fmt"
	"os"

	"github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/sys/targets"
)

func getFileVersions(c *Config, targetFilePath string, rbcs []RepoBranchCommit,
) (map[RepoBranchCommit]string, error) {
	reposPath := c.Workdir + "/repos"
	for _, rbc := range rbcs {
		commitPath := reposPath + "/" + rbc.Commit
		if _, err := os.Stat(commitPath); err == nil || c.skipRepoClone {
			continue
		}
		repo, err := vcs.NewRepo(targets.Linux, "none", commitPath)
		if err != nil {
			return nil, fmt.Errorf("failed to create new repo at %s: %w", commitPath, err)
		}
		if _, err = repo.CheckoutCommit(rbc.Repo, rbc.Commit); err != nil {
			return nil, fmt.Errorf("failed to get commit %s from repo %s to folder %s: %w",
				rbc.Commit, rbc.Repo, commitPath, err)
		}
	}

	res := make(map[RepoBranchCommit]string)
	for _, rbc := range rbcs {
		filePath := reposPath + "/" + rbc.Commit + "/" + targetFilePath
		fileBytes, err := os.ReadFile(filePath)
		// It is ok if some file doesn't exist. It means we have repo FS diff.
		if err == nil {
			res[rbc] = string(fileBytes)
		}
	}

	return res, nil
}
