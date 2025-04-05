// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package triage

import (
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/stretchr/testify/assert"
)

func TestGitTreeOpsHead(t *testing.T) {
	baseDir := t.TempDir()
	repo := vcs.MakeTestRepo(t, baseDir)
	// Emulate the behavior of the kernel-disk machinery.
	osutil.WriteFile(filepath.Join(baseDir, "file.txt"), []byte("Some content"))
	repo.Git("add", "file.txt")
	head1 := repo.CommitChange("first head")
	repo.SetTag("mainline-head")
	osutil.WriteFile(filepath.Join(baseDir, "file.txt"), []byte("Another content"))
	repo.Git("add", "file.txt")
	head2 := repo.CommitChange("second head")
	repo.SetTag("second-head")
	// Verify that the right commits are queried.
	ops, err := NewGitTreeOps(baseDir, false)
	assert.NoError(t, err)
	commit, err := ops.HeadCommit(&api.Tree{Name: "mainline"})
	assert.NoError(t, err)
	assert.Equal(t, head1.Hash, commit.Hash)
	commit, err = ops.HeadCommit(&api.Tree{Name: "second"})
	assert.NoError(t, err)
	assert.Equal(t, head2.Hash, commit.Hash)
}

func TestGitTreeOpsApply(t *testing.T) {
	baseDir := t.TempDir()
	repo := vcs.MakeTestRepo(t, baseDir)
	osutil.WriteFile(filepath.Join(baseDir, "file.txt"), []byte("First\nSecond\nThird\n"))
	repo.Git("add", "file.txt")
	base := repo.CommitChange("base")

	ops, err := NewGitTreeOps(baseDir, false)
	assert.NoError(t, err)
	assert.Error(t, ops.ApplySeries(base.Hash, [][]byte{goodPatch, wontApply}))
	assert.NoError(t, ops.ApplySeries(base.Hash, [][]byte{goodPatch}))
}

var wontApply = []byte(`From dc2cf7bc4a9dbe170d47338d0fe6d2351c88c9d1 Mon Sep 17 00:00:00 2001
From: Test Syzkaller <test@syzkaller.com>
Date: Tue, 10 Dec 2024 17:58:20 +0100
Subject: [PATCH] change1

---
 file.txt | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/file.txt b/file.txt
index 0d39765..97c39a4 100644
--- a/file.txt
+++ b/file.txt
@@ -1,3 +1,3 @@
-1First
-1Second
-1Third
+First1
+Second
+Third1
--
2.47.1.545.g3c1d2e2a6a-goog
`)

var goodPatch = []byte(`From 708670e05c0462d3783f774cef82f9a3b3099f9a Mon Sep 17 00:00:00 2001
From: Test Syzkaller <test@syzkaller.com>
Date: Tue, 10 Dec 2024 17:57:37 +0100
Subject: [PATCH] change1

---
 file.txt | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/file.txt b/file.txt
index ab7c514..97c39a4 100644
--- a/file.txt
+++ b/file.txt
@@ -1,3 +1,3 @@
-First
+First1
 Second
-Third
+Third1
--
2.47.1.545.g3c1d2e2a6a-goog
`)
