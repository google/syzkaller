// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package gitlog

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/stretchr/testify/assert"
)

func TestGitShow(t *testing.T) {
	tmpDir := t.TempDir()
	repo := vcs.MakeTestRepo(t, filepath.Join(tmpDir, "repo", "linux"))
	c1 := repo.CommitChangeset("initial commit", vcs.FileContent{
		File: "foo.c",
		Content: `
void foo() {
	// BUG HERE
}
`,
	})

	// Test git-show.
	aflow.TestTool(t, ToolShow,
		state{},
		showArgs{Commit: c1.Hash},
		func(res showResult) {
			expected := fmt.Sprintf(`(?s)^commit %s
Author: Test Syzkaller <test@syzkaller\.com>
Date:   .*

    initial commit

diff --git a/foo\.c b/foo\.c
.*
\+void foo\(\) {
\+	// BUG HERE
\+}`, c1.Hash)
			assert.Regexp(t, expected, res.Output)
		},
		"", aflow.TestWorkdir(tmpDir))

	// Test git-show with non-existing commit.
	aflow.TestTool(t, ToolShow,
		state{},
		showArgs{Commit: "0123456789abcdef0123456789abcdef01234567"},
		showResult{},
		"git show failed: fatal: bad object 0123456789abcdef0123456789abcdef01234567", aflow.TestWorkdir(tmpDir))
}

func TestGitBlame(t *testing.T) {
	tmpDir := t.TempDir()
	repoDir := filepath.Join(tmpDir, "repo", "linux")
	repo := vcs.MakeTestRepo(t, repoDir)
	c1 := repo.CommitChangeset("initial commit", vcs.FileContent{
		File: "foo.c",
		Content: `
void foo() {
	// BUG HERE
}
`,
	})
	c2 := repo.CommitChangeset("third commit", vcs.FileContent{
		File: "foo.c",
		Content: `
void foo() {
	// BUG HERE
	// fixed!
}
`,
	})

	// Test git-blame.
	aflow.TestTool(t, ToolBlame,
		state{KernelCommit: "HEAD"},
		blameArgs{File: "foo.c", Start: 3, End: 4},
		func(res blameResult) {
			expected := fmt.Sprintf(`(?m)^\^%s.* 3\) 	// BUG HERE
%s.* 4\) 	// fixed!
$`, c1.Hash[:12], c2.Hash[:12])
			assert.Regexp(t, expected, res.Output)
		},
		"", aflow.TestWorkdir(tmpDir))

	// Test git-blame with non-existent file.
	aflow.TestTool(t, ToolBlame,
		state{KernelCommit: "HEAD"},
		blameArgs{File: "non_existing.c", Start: 1, End: 1},
		blameResult{},
		"git blame failed: fatal: no such path non_existing.c in HEAD",
		aflow.TestWorkdir(tmpDir))

	// Test git-blame out of bounds line range.
	aflow.TestTool(t, ToolBlame,
		state{KernelCommit: "HEAD"},
		blameArgs{File: "foo.c", Start: 1000, End: 1001},
		blameResult{},
		"git blame failed: fatal: file foo.c has only 5 lines",
		aflow.TestWorkdir(tmpDir))
}

func TestGitLog(t *testing.T) {
	tmpDir := t.TempDir()
	repoDir := filepath.Join(tmpDir, "repo", "linux")
	repo := vcs.MakeTestRepo(t, repoDir)
	c1 := repo.CommitChangeset("initial commit", vcs.FileContent{
		File: "foo.c",
		Content: `
void foo() {
	// BUG HERE
}
`,
	})
	c2 := repo.CommitChangeset("second commit", vcs.FileContent{
		File: "bar.c",
		Content: `
void bar() {
	foo();
}
`,
	})
	c3 := repo.CommitChangeset("third commit", vcs.FileContent{
		File: "foo.c",
		Content: `
void foo() {
	// BUG HERE
	// fixed!
}
`,
	})

	// Test git-log message search.
	aflow.TestTool(t, ToolLog,
		state{KernelCommit: "HEAD"},
		logArgs{MessageRegexps: []string{"commit"}},
		logResult{Output: fmt.Sprintf("%s third commit\n%s second commit\n%s initial commit\n",
			c3.Hash[:12], c2.Hash[:12], c1.Hash[:12])},
		"", aflow.TestWorkdir(tmpDir))

	// Test git-log multiple message regexps.
	aflow.TestTool(t, ToolLog,
		state{KernelCommit: "HEAD"},
		logArgs{MessageRegexps: []string{"third", "commit"}},
		logResult{Output: fmt.Sprintf("%s third commit\n", c3.Hash[:12])},
		"", aflow.TestWorkdir(tmpDir))

	// Test git-log message search case-insensitive.
	aflow.TestTool(t, ToolLog,
		state{KernelCommit: "HEAD"},
		logArgs{MessageRegexps: []string{"COMMIT"}},
		logResult{Output: fmt.Sprintf("%s third commit\n%s second commit\n%s initial commit\n",
			c3.Hash[:12], c2.Hash[:12], c1.Hash[:12])},
		"", aflow.TestWorkdir(tmpDir))

	// Test git-log code search (-G).
	aflow.TestTool(t, ToolLog,
		state{KernelCommit: "HEAD"},
		logArgs{CodeRegexp: "fixed"},
		logResult{Output: fmt.Sprintf("%s third commit\n", c3.Hash[:12])},
		"", aflow.TestWorkdir(tmpDir))

	// Test git-log symbol search (-L).
	aflow.TestTool(t, ToolLog,
		state{KernelCommit: "HEAD"},
		logArgs{SymbolName: "foo", SourcePath: "foo.c"},
		logResult{Output: fmt.Sprintf("%s third commit\n%s initial commit\n", c3.Hash[:12], c1.Hash[:12])},
		"", aflow.TestWorkdir(tmpDir))

	// Test git-log path prefix.
	aflow.TestTool(t, ToolLog,
		state{KernelCommit: "HEAD"},
		logArgs{PathPrefix: "foo.c"},
		logResult{Output: fmt.Sprintf("%s third commit\n%s initial commit\n", c3.Hash[:12], c1.Hash[:12])},
		"", aflow.TestWorkdir(tmpDir))

	// Test git-log no matches.
	aflow.TestTool(t, ToolLog,
		state{KernelCommit: "HEAD"},
		logArgs{MessageRegexps: []string{"non-existing"}},
		logResult{},
		"", aflow.TestWorkdir(tmpDir))

	// Test git-log code search (-G) no matches.
	aflow.TestTool(t, ToolLog,
		state{KernelCommit: "HEAD"},
		logArgs{CodeRegexp: "non-existing"},
		logResult{},
		"", aflow.TestWorkdir(tmpDir))

	// Test git-log error: missing SourcePath for symbol search.
	aflow.TestTool(t, ToolLog,
		state{KernelCommit: "HEAD"},
		logArgs{SymbolName: "foo"},
		logResult{},
		"SourcePath is required when SymbolName is set", aflow.TestWorkdir(tmpDir))

	// Test git-log error: SymbolName and PathPrefix conflict.
	aflow.TestTool(t, ToolLog,
		state{KernelCommit: "HEAD"},
		logArgs{SymbolName: "foo", SourcePath: "foo.c", PathPrefix: "foo.c"},
		logResult{},
		"SymbolName and PathPrefix cannot be used together", aflow.TestWorkdir(tmpDir))

	// Test git-log error: no filters provided.
	aflow.TestTool(t, ToolLog,
		state{KernelCommit: "HEAD"},
		logArgs{},
		logResult{},
		"at least one of CodeRegexp, SymbolName, MessageRegexps, or PathPrefix must be set",
		aflow.TestWorkdir(tmpDir))

	// Test git-log error: symbol not found.
	aflow.TestTool(t, ToolLog,
		state{KernelCommit: "HEAD"},
		logArgs{SymbolName: "non_existing_symbol", SourcePath: "foo.c"},
		logResult{},
		"git log failed: fatal: -L parameter 'non_existing_symbol' starting at line 1: no match",
		aflow.TestWorkdir(tmpDir))
}
