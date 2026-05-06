// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package lore

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/vcs"
	"github.com/stretchr/testify/assert"
)

type TestLoreArchive struct {
	Repo *vcs.TestRepo
}

func NewTestLoreArchive(t *testing.T, dir string) *TestLoreArchive {
	repo := vcs.MakeTestRepo(t, dir)
	repo.Git("checkout", "-B", "master")
	return &TestLoreArchive{
		Repo: repo,
	}
}

func (a *TestLoreArchive) SaveMessage(t *testing.T, raw string) {
	a.SaveMessageAt(t, raw, time.Now())
}

func (a *TestLoreArchive) SaveMessageAt(t *testing.T, raw string, date time.Time) {
	err := os.WriteFile(filepath.Join(a.Repo.Dir, "m"), []byte(raw), 0666)
	assert.NoError(t, err)
	a.Repo.Git("add", "m")
	a.Repo.CommitChangeAt("message", date)
}
