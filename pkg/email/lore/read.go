// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package lore

import (
	"bytes"
	"fmt"
	"time"

	"github.com/google/syzkaller/pkg/email"
	"github.com/google/syzkaller/pkg/vcs"
)

type EmailReader struct {
	Read func() ([]byte, error)
}

// ReadArchive queries the parsed messages from a single LKML message archive.
func ReadArchive(repo vcs.Repo, fromTime time.Time) ([]EmailReader, error) {
	commits, err := repo.ListCommitHashes("HEAD", fromTime)
	if err != nil {
		return nil, fmt.Errorf("failed to get recent commits: %w", err)
	}
	var ret []EmailReader
	for _, iterCommit := range commits {
		commit := iterCommit
		ret = append(ret, EmailReader{
			Read: func() ([]byte, error) {
				return repo.Object("m", commit)
			},
		})
	}
	return ret, nil
}

func (er *EmailReader) Parse(emails, domains []string) (*email.Email, error) {
	body, err := er.Read()
	if err != nil {
		return nil, err
	}
	msg, err := email.Parse(bytes.NewReader(body), emails, nil, domains)
	if err != nil {
		return nil, err
	}
	// Keep memory consumption low.
	msg.Body = ""
	msg.Patch = ""
	// TODO: We definitely don't care about the patch here. Add an option to avoid extracting it?
	// TODO: If emails/domains are nil, we also don't need to parse the body at all.
	return msg, nil
}
