// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package lore

import (
	"fmt"

	"github.com/google/syzkaller/pkg/vcs"
)

type EmailReader struct {
	Extract func() ([]byte, error)
}

// ReadArchive queries the parsed messages from a single LKML message archive.
func ReadArchive(dir string, messages chan<- *EmailReader) error {
	repo := vcs.NewLKMLRepo(dir)
	commits, err := repo.ListCommitHashes("HEAD")
	if err != nil {
		return fmt.Errorf("failed to get recent commits: %w", err)
	}
	for _, iterCommit := range commits {
		commit := iterCommit
		messages <- &EmailReader{
			Extract: func() ([]byte, error) {
				return repo.Object("m", commit)
			},
		}
	}
	return nil
}
