// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package kernel

import (
	"os/exec"
	"strings"
	"testing"
)

func TestCompilerIdentity(t *testing.T) {
	compiler := "gcc"
	if _, err := exec.LookPath(compiler); err != nil {
		t.Skipf("compiler '%v' is not found: %v", compiler, err)
	}
	id, err := CompilerIdentity(compiler)
	if err != nil {
		t.Fatalf("failed: %v", err)
	}
	if len(id) == 0 {
		t.Fatalf("identity is empty")
	}
	if strings.Index(id, "\n") != -1 {
		t.Fatalf("identity contains a new line")
	}
	// We don't know what's the right answer,
	// so just print it for manual inspection.
	t.Logf("id: '%v'", id)
}
