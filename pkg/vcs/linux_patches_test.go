// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vcs

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/pkg/osutil"
)

func TestFixBackport(t *testing.T) {
	baseDir := t.TempDir()
	repo := MakeTestRepo(t, baseDir)

	repo.Git("checkout", "-b", "main")
	repo.Git("commit", "--no-edit", "--allow-empty", "-m", "starting commit")

	// Let the fix stay in a separate branch.
	repo.Git("checkout", "-b", "branch-with-a-fix")
	filePath := filepath.Join(baseDir, "object.txt")
	if err := os.WriteFile(filePath, []byte("content"), 0644); err != nil {
		t.Fatal(err)
	}
	repo.Git("add", "object.txt")
	repo.Git("commit", "--no-edit", "-m", "fix title")
	fixCommit, _ := repo.repo.HeadCommit()

	// Return to the original branch.
	repo.Git("checkout", "main")

	// Check the test is sane.
	if osutil.IsExist(filePath) {
		t.Fatalf("we have switched the branch, object.txt should not be present")
	}

	// Verify that the fix gets backported.
	err := applyFixBackports(repo.repo, []BackportCommit{
		{
			FixHash:  fixCommit.Hash,
			FixTitle: `fix title`,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !osutil.IsExist(filePath) {
		t.Fatalf("the commit was not backported, but should have")
	}
}

func TestConditionalFixBackport(t *testing.T) {
	baseDir := t.TempDir()
	repo := MakeTestRepo(t, baseDir)

	repo.Git("checkout", "-b", "main")
	repo.Git("commit", "--no-edit", "--allow-empty", "-m", "starting commit")

	// Let the fix stay in a separate branch.
	repo.Git("checkout", "-b", "branch-with-fix")
	filePath := filepath.Join(baseDir, "object.txt")
	if err := os.WriteFile(filePath, []byte("content"), 0644); err != nil {
		t.Fatal(err)
	}
	repo.Git("add", "object.txt")
	repo.Git("commit", "--no-edit", "-m", "fix title")
	fixCommit, _ := repo.repo.HeadCommit()

	// Create a branch without a bug.
	repo.Git("checkout", "main")
	repo.Git("checkout", "-b", "branch-no-bug")
	repo.Git("commit", "--no-edit", "--allow-empty", "-m", "some commit")

	// Create a branch with a bug.
	repo.Git("checkout", "-b", "branch-with-bug")
	repo.Git("commit", "--no-edit", "--allow-empty", "-m", "bad commit")
	badCommit, _ := repo.repo.HeadCommit()
	repo.Git("commit", "--no-edit", "--allow-empty", "-m", "some other commit")

	// Ensure we do not cherry-pick the fix when there's no bug.
	repo.Git("checkout", "branch-no-bug")
	rules := []BackportCommit{
		{
			GuiltyHash: badCommit.Hash,
			FixHash:    fixCommit.Hash,
			FixTitle:   `fix title`,
		},
	}
	err := applyFixBackports(repo.repo, rules)
	if err != nil {
		t.Fatal(err)
	}
	if osutil.IsExist(filePath) {
		t.Fatalf("the commit was backported, but shouldn't have been")
	}

	// .. but we do cherry-pick otherwise.
	repo.Git("checkout", "branch-with-bug")
	err = applyFixBackports(repo.repo, rules)
	if err != nil {
		t.Fatal(err)
	}
	if !osutil.IsExist(filePath) {
		t.Fatalf("the commit was not backported, but should have been")
	}
}
