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
	// nolint: lll
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
		{`
  CC       /tools/objtool/parse-options.o
In file included from ./scripts/gcc-plugins/gcc-common.h:119:0,
 from <stdin>:1:
/gcc-5.5.0/bin/../lib/gcc/x86_64-unknown-linux-gnu/5.5.0/plugin/include/builtins.h:23:17: fatal error: mpc.h: No such file or directory
compilation terminated.
Cannot use CONFIG_GCC_PLUGINS: your gcc installation does not support plugins, perhaps the necessary headers are missing?
scripts/Makefile.gcc-plugins:51: recipe for target 'gcc-plugins-check' failed
make: *** [gcc-plugins-check] Error 1
make: *** Waiting for unfinished jobs....
  UPD     include/config/kernel.release
`,
			"/gcc-5.5.0/bin/../lib/gcc/x86_64-unknown-linux-gnu/5.5.0/plugin/include/builtins.h:23:17: fatal error: mpc.h: No such file or directory",
		},
		{`
Starting local Bazel server and connecting to it...
Loading:
Loading: 0 packages loaded
Analyzing: target //runsc:runsc (1 packages loaded)
Analyzing: target //runsc:runsc (5 packages loaded)
Analyzing: target //runsc:runsc (15 packages loaded)
Analyzing: target //runsc:runsc (92 packages loaded)
Analyzing: target //runsc:runsc (99 packages loaded)
Analyzing: target //runsc:runsc (115 packages loaded)
ERROR: /syzkaller/managers/ptrace-direct-overlay-host/kernel/vdso/BUILD:13:1: no such target '@bazel_tools//tools/cpp:cc_flags': target 'cc_flags' not declared in package 'tools/cpp' defined by /syzkaller/home/.cache/bazel/_bazel_root/e1c9d86bae2b34f90e83d224bc900958/external/bazel_tools/tools/cpp/BUILD and referenced by '//vdso:vdso'
ERROR: Analysis of target '//runsc:runsc' failed; build aborted: Analysis failed
INFO: Elapsed time: 14.914s
INFO: 0 processes.
FAILED: Build did NOT complete successfully (189 packages loaded)
`,
			"ERROR: Analysis of target '//runsc:runsc' failed; build aborted: Analysis failed",
		},
	} {
		got := extractCauseInner([]byte(s.e))
		if !bytes.Equal([]byte(s.expect), got) {
			t.Errorf("Expected %s, got %s", s.expect, got)
		}
	}
}
