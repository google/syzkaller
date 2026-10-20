// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package osutil

import (
	"testing"
)

// WriteSandboxFile writes data to filename and chowns it to the sandbox user.
// It fails the test on error and is intended for test setup only.
// It does not guard against symlink traversal and must only be used in trusted
// directories, not directories already modified by sandboxed processes.
// Production code writing into sandbox-owned trees should use os.Root instead.
func WriteSandboxFile(t *testing.T, filename string, data []byte) {
	t.Helper()
	if err := WriteFile(filename, data); err != nil {
		t.Fatal(err)
	}
	if err := SandboxChown(filename); err != nil {
		t.Fatal(err)
	}
}
