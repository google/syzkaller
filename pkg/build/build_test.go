// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package build

import (
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
  LINK     /home/dvyukov/src/linux2/tools/objtool/objtool
  MKELF   scripts/mod/elfconfig.h
  HOSTCC  scripts/mod/modpost.o
  HOSTCC  scripts/mod/sumversion.o
  HOSTCC  scripts/mod/file2alias.o
  HOSTLD  scripts/mod/modpost
  CC      kernel/bounds.s
  CALL    scripts/atomic/check-atomics.sh
  CC      arch/x86/kernel/asm-offsets.s
  UPD     include/generated/asm-offsets.h
  CALL    scripts/checksyscalls.sh
`, "",
		},
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
ERROR: /kernel/vdso/BUILD:13:1: no such target '@bazel_tools//tools/cpp:cc_flags': target 'cc_flags' not declared in package 'tools/cpp' defined by /syzkaller/home/.cache/bazel/_bazel_root/e1c9d86bae2b34f90e83d224bc900958/external/bazel_tools/tools/cpp/BUILD and referenced by '//vdso:vdso'
ERROR: Analysis of target '//runsc:runsc' failed; build aborted: Analysis failed
INFO: Elapsed time: 14.914s
INFO: 0 processes.
FAILED: Build did NOT complete successfully (189 packages loaded)
`,
			`ERROR: /kernel/vdso/BUILD:13:1: no such target '@bazel_tools//tools/cpp:cc_flags': target 'cc_flags' not declared in package 'tools/cpp' defined by /syzkaller/home/.cache/bazel/_bazel_root/e1c9d86bae2b34f90e83d224bc900958/external/bazel_tools/tools/cpp/BUILD and referenced by '//vdso:vdso'
ERROR: Analysis of target '//runsc:runsc' failed; build aborted: Analysis failed
FAILED: Build did NOT complete successfully (189 packages loaded)`,
		},
		{`
ld -T ld.script -X --warn-common -nopie -o bsd ${SYSTEM_HEAD} vers.o ${OBJS}
ld: error: undefined symbol: __stack_smash_handler
>>> referenced by bktr_card.c:0 (/kernel/sys/dev/pci/bktr/bktr_card.c:0)
>>>               bktr_card.o:(probeCard)

ld: error: undefined symbol: __stack_smash_handler
>>> referenced by vnd.c:0 (/kernel/sys/dev/vnd.c:0)
>>>               vnd.o:(vndencrypt)

ld: error: undefined symbol: __stack_smash_handler
>>> referenced by ihidev.c:0 (/kernel/sys/dev/i2c/ihidev.c:0)
>>>               ihidev.o:(ihidev_attach)

ld: error: too many errors emitted, stopping now (use -error-limit=0 to see all errors)
*** Error 1 in /kernel/sys/arch/amd64/compile/SYZKALLER (Makefile:991 'bsd': @echo ld -T ld.script -X --warn-commo...)
`,
			`ld: error: undefined symbol: __stack_smash_handler
ld: error: too many errors emitted, stopping now (use -error-limit=0 to see all errors)`,
		},
		{`
make: execvp: /gcc-5.5.0/bin/gcc: Permission denied
scripts/kconfig/conf  --silentoldconfig Kconfig
arch/x86/Makefile:123: stack-protector enabled but compiler support broken
arch/x86/Makefile:138: CONFIG_X86_X32 enabled but no binutils support
Makefile:652: Cannot use CONFIG_CC_STACKPROTECTOR_REGULAR: -fstack-protector not supported by compiler
make: execvp: /gcc-5.5.0/bin/gcc: Permission denied
  SYSTBL  arch/x86/entry/syscalls/../../include/generated/asm/syscalls_32.h
  SYSHDR  arch/x86/entry/syscalls/../../include/generated/uapi/asm/unistd_x32.h
scripts/xen-hypercalls.sh: line 7: /gcc-5.5.0/bin/gcc: Permission denied
  HOSTCC  scripts/mod/mk_elfconfig
/bin/sh: 1: /gcc-5.5.0/bin/gcc: Permission denied
scripts/Makefile.build:258: recipe for target 'scripts/mod/empty.o' failed
make[2]: *** [scripts/mod/empty.o] Error 126
make[2]: *** Waiting for unfinished jobs....
  CC      scripts/mod/devicetable-offsets.s
/bin/sh: 1: /gcc-5.5.0/bin/gcc: Permission denied
scripts/Makefile.build:153: recipe for target 'scripts/mod/devicetable-offsets.s' failed
make[2]: *** [scripts/mod/devicetable-offsets.s] Error 126
  HOSTCC  scripts/selinux/mdp/mdp
  HOSTCC  scripts/selinux/genheaders/genheaders
scripts/Makefile.build:403: recipe for target 'scripts/mod' failed
make[1]: *** [scripts/mod] Error 2
make[1]: *** Waiting for unfinished jobs....
  UPD     include/config/kernel.release
Makefile:545: recipe for target 'scripts' failed
make: *** [scripts] Error 2
make: *** Waiting for unfinished jobs....
  HOSTLD  arch/x86/tools/relocs
`,
			`make: execvp: /gcc-5.5.0/bin/gcc: Permission denied
scripts/xen-hypercalls.sh: line 7: /gcc-5.5.0/bin/gcc: Permission denied
/bin/sh: 1: /gcc-5.5.0/bin/gcc: Permission denied`,
		},
		{`
./arch/x86/include/asm/nospec-branch.h:360:1: warning: data definition has no type or storage class
  360 | DECLARE_STATIC_KEY_FALSE(mds_user_clear);
      | ^~~~~~~~~~~~~~~~~~~~~~~~
./arch/x86/include/asm/nospec-branch.h:360:1: error: type defaults to ‘int’ in declaration of ‘DECLARE_STATIC_KEY_FALSE’ [-Werror=implicit-int]
./arch/x86/include/asm/nospec-branch.h:360:1: warning: parameter names (without types) in function declaration
./arch/x86/include/asm/nospec-branch.h: In function ‘mds_user_clear_cpu_buffers’:
./arch/x86/include/asm/nospec-branch.h:394:6: error: implicit declaration of function ‘static_branch_likely’ [-Werror=implicit-function-declaration]
  394 |  if (static_branch_likely(&mds_user_clear))
      |      ^~~~~~~~~~~~~~~~~~~~
./arch/x86/include/asm/nospec-branch.h:394:28: error: ‘mds_user_clear’ undeclared (first use in this function)
  394 |  if (static_branch_likely(&mds_user_clear))
      |                            ^~~~~~~~~~~~~~
./arch/x86/include/asm/nospec-branch.h:394:28: note: each undeclared identifier is reported only once for each function it appears in
cc1: some warnings being treated as errors
Kbuild:57: recipe for target 'arch/x86/kernel/asm-offsets.s' failed
make[1]: *** [arch/x86/kernel/asm-offsets.s] Error 1
Makefile:1227: recipe for target 'prepare0' failed
make: *** [prepare0] Error 2
`, `./arch/x86/include/asm/nospec-branch.h:360:1: error: type defaults to 'int' in declaration of 'DECLARE_STATIC_KEY_FALSE' [-Werror=implicit-int]
./arch/x86/include/asm/nospec-branch.h:394:6: error: implicit declaration of function 'static_branch_likely' [-Werror=implicit-function-declaration]
./arch/x86/include/asm/nospec-branch.h:394:28: error: 'mds_user_clear' undeclared (first use in this function)`,
		},
	} {
		got := extractCauseInner([]byte(s.e))
		if s.expect != got {
			t.Errorf("Expected:\n%s\ngot:\n%s", s.expect, got)
		}
	}
}
