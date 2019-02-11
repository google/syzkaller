// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package build

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"
)

func TestCompilerIdentity(t *testing.T) {
	t.Parallel()
	for _, compiler := range []string{"gcc", "clang", "bazel"} {
		compiler := compiler
		t.Run(compiler, func(t *testing.T) {
			t.Parallel()
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
			if strings.Contains(id, "\n") {
				t.Fatalf("identity contains a new line")
			}
			// We don't know what's the right answer,
			// so just print it for manual inspection.
			t.Logf("id: '%v'", id)
		})
	}
}

func TestExtractRootCause(t *testing.T) {
	for _, s := range []struct{ e, expect string }{
		{`
cc -g -Werror db_break.c
sys/dev/kcov.c:93:6: error: use of undeclared identifier 'kcov_cold123'; did you mean 'kcov_cold'?
        if (kcov_cold123)
            ^~~~~~~~~~~~
            kcov_cold
sys/dev/kcov.c:65:5: note: 'kcov_cold' declared here
int kcov_cold = 1;
    ^
1 error generated.
`,
			"sys/dev/kcov.c:93:6: error: use of undeclared identifier 'kcov_cold123'; did you mean 'kcov_cold'?",
		},
	} {
		got := extractCauseInner([]byte(s.e))
		if !bytes.Equal([]byte(s.expect), got) {
			t.Errorf("Expected %s, got %s", s.expect, got)
		}
	}
}
