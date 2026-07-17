// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package crash

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/stretchr/testify/require"
)

func TestClangFormat(t *testing.T) {
	files, err := filepath.Glob("testdata/clang_format/*")
	require.NoError(t, err)
	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			content, err := os.ReadFile(file)
			require.NoError(t, err)

			parts := strings.Split(string(content), "======\n")
			require.Len(t, parts, 3, "invalid test file format: expected 3 parts")

			base := parts[0]
			diffBefore := strings.TrimSpace(parts[1])
			diffAfterExpected := strings.TrimSpace(parts[2])

			repo := vcs.MakeTestRepo(t, t.TempDir())
			filePath := filepath.Join(repo.Dir, "fuse.c")

			// Write base and commit.
			err = os.WriteFile(filePath, []byte(base), 0644)
			require.NoError(t, err)
			repo.Git("add", "fuse.c")
			repo.Git("commit", "-m", "base")

			if diffBefore != "" {
				cmd := osutil.Command("git", "apply", "--unidiff-zero")
				cmd.Dir = repo.Dir
				cmd.Stdin = strings.NewReader(diffBefore + "\n")
				_, err = osutil.Run(time.Minute, cmd)
				require.NoError(t, err, "git apply failed")
			}

			diff, err := currentDiff(repo.Dir)
			require.NoError(t, err)

			// Normalize diff output (git diff adds a trailing newline, test files might not have it)
			diffStr := strings.TrimSpace(diff)

			require.Equal(t, diffAfterExpected, diffStr, "formatting mismatch")
		})
	}
}
