// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package build

import (
	"fmt"
	"net"
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/stretchr/testify/require"
)

const TestKernelPatch = "diff --git a/foo.c b/foo.c\n" +
	"--- a/foo.c\n" +
	"+++ b/foo.c\n" +
	"@@ -1,3 +1,3 @@\n" +
	" void foo(void) {\n" +
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

	checkSandbox := fmt.Sprintf(`failed=0
fail() { echo "ERROR: sandbox check failed: $*" >&2; failed=1; }
[ "$(id -un)" = "syzkaller" ] || fail "user is $(id -un), want syzkaller"
[ -n "${HOME:-}" ] && [ -w "$HOME" ] || fail "HOME (${HOME:-}) is not writable"
if [ -n "${SYZ_TEST_FORBIDDEN:-}" ]; then
	! cat "$SYZ_TEST_FORBIDDEN" >/dev/null 2>&1 || fail "able to read $SYZ_TEST_FORBIDDEN"
	! touch "$SYZ_TEST_FORBIDDEN" 2>/dev/null || fail "able to write $SYZ_TEST_FORBIDDEN"
	dir="$(dirname "$SYZ_TEST_FORBIDDEN")"
	if touch "$dir/escape" 2>/dev/null; then
		rm -f "$dir/escape"
		fail "able to write to $dir"
	fi
fi
! (exec 3<>"/dev/tcp/127.0.0.1/%d") 2>/dev/null || fail "able to connect to local TCP port"
[ "$(wc -l < /proc/net/dev)" -le 3 ] || fail "unexpected network interfaces in /proc/net/dev"
exit $failed`,
		ln.Addr().(*net.TCPAddr).Port)

	files := map[string]string{
		"scripts/check-sandbox": checkSandbox,
		"scripts/config":        `"$(dirname "$0")/check-sandbox" && echo "$@" >> .config`,
		"scripts/checkpatch.pl": `"$(dirname "$0")/check-sandbox" && cat >/dev/null`,
		"scripts/get_maintainer.pl": `"$(dirname "$0")/check-sandbox" && cat >/dev/null &&
	echo "Foo Maintainer <foo@kernel.org> (maintainer:FOO)"`,
		"scripts/gcc-plugins/keep": "",
		"certs/keep":               "",
	}
	for name, body := range files {
		require.NoError(t, osutil.MkdirAll(filepath.Dir(filepath.Join(dir, name))))
		require.NoError(t, osutil.WriteExecFile(filepath.Join(dir, name), []byte("#!/bin/bash\nset -eu\n"+body+"\n")))
	}
	const makefile = `O ?= .

target:

oldconfig distclean:
	@./scripts/check-sandbox
	@echo "CONFIG_OLDCONFIG=y" >> .config

bzImage compile_commands.json &:
	@./scripts/check-sandbox
	@git status --porcelain >/dev/null
	@if [ "$(O)" = "." ]; then \
		touch .config certs/signing_key.pem scripts/gcc-plugins/randomize_layout_seed.h; \
	fi
	@mkdir -p "$(O)/arch/x86/boot" "$(O)/include/generated"
	@echo "image" > "$(O)/arch/x86/boot/bzImage"
	@cp /bin/true "$(O)/vmlinux"
	@echo '#define LINUX_COMPILER "fake compiler"' > "$(O)/include/generated/compile.h"
	@echo "[]" > "$(O)/compile_commands.json"
	@echo "obj" > "$(O)/intermediate.o"
`
	require.NoError(t, osutil.WriteFile(filepath.Join(dir, "Makefile"), []byte(makefile)))
	require.NoError(t, osutil.WriteFile(filepath.Join(dir, "foo.c"), []byte("void foo(void) {\n\t// old\n}\n")))
	repo := vcs.MakeTestRepo(t, dir)
	repo.Git("checkout", "-b", "master")
	repo.Git("add", ".")
	return repo, repo.CommitChange("initial kernel commit").Hash
}
