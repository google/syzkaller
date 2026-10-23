// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package build

import (
	"embed"
	"io/fs"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/stretchr/testify/require"
)

//go:embed testdata/kernel
var testKernelFS embed.FS

const TestKernelPatch = "diff --git a/foo.c b/foo.c\n" +
	"--- a/foo.c\n" +
	"+++ b/foo.c\n" +
	"@@ -1,4 +1,4 @@\n" +
	" void foo(void)\n" +
	" {\n" +
	"-\t// old\n" +
	"+\t// patched\n" +
	" }\n"

// MakeTestKernelRepo creates a fake Linux kernel git repository for sandboxing tests
// and returns its HEAD commit. It supports both in-tree and out-of-tree (O=) builds.
// The kernel scripts and the build fail unless they run in osutil.Sandbox
// (as the syzkaller user, with a writable HOME, in a separate network namespace).
func MakeTestKernelRepo(t *testing.T, dir string) (*vcs.TestRepo, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	t.Setenv("SYZ_TEST_TCP_PORT", strconv.Itoa(ln.Addr().(*net.TCPAddr).Port))

	const prefix = "testdata/kernel"
	err = fs.WalkDir(testKernelFS, prefix, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel := strings.TrimPrefix(path, prefix)
		dst := filepath.Join(dir, rel)
		if d.IsDir() {
			if err := osutil.MkdirAll(dst); err != nil {
				return err
			}
			return osutil.SandboxChown(dst)
		}
		data, err := testKernelFS.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.HasPrefix(rel, "/scripts/") {
			if err := osutil.WriteExecFile(dst, data); err != nil {
				return err
			}
			return osutil.SandboxChown(dst)
		}
		return osutil.WriteSandboxFile(dst, data)
	})
	require.NoError(t, err)

	repo := vcs.MakeTestRepo(t, dir)
	repo.Git("checkout", "-b", "master")
	repo.Git("add", ".")
	return repo, repo.CommitChange("initial kernel commit").Hash
}
