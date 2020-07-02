// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package build

import (
	"fmt"
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
			if id == "" {
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
	for i, test := range rootCauseTests {
		test := test
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			reason, file := extractCauseInner([]byte(test.e), test.src)
			if test.reason != string(reason) {
				t.Errorf("expected:\n%s\ngot:\n%s", test.reason, reason)
			}
			if test.file != file {
				t.Errorf("expected file: %q, got: %q", test.file, file)
			}
		})
	}
}

type RootCauseTest struct {
	e      string
	reason string
	src    string
	file   string
}

// nolint: lll
var rootCauseTests = []RootCauseTest{
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
`,
		"",
		"",
		"",
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
		"",
		"sys/dev/kcov.c",
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
		"",
		"",
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
		"",
		"",
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
		"",
		"",
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
		"",
		"",
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
		"/some/unrelated/path",
		"arch/x86/include/asm/nospec-branch.h",
	},
	{`
  CC      fs/notify/group.o
  CC      lib/zlib_deflate/deftree.o
  CC      net/ipv4/devinet.o
  CC      arch/x86/kernel/apic/apic_noop.o
  CC      arch/x86/kernel/crash_core_64.o
  CC      arch/x86/kernel/machine_kexec_64.o
In file included from kernel/rcu/update.c:562:
kernel/rcu/tasks.h: In function ‘show_rcu_tasks_gp_kthreads’:
kernel/rcu/tasks.h:1070:37: error: ‘rcu_tasks_rude’ undeclared (first use in this function); did you mean ‘rcu_tasks_qs’?
 1070 |  show_rcu_tasks_generic_gp_kthread(&rcu_tasks_rude, "");
      |                                     ^~~~~~~~~~~~~~
      |                                     rcu_tasks_qs
kernel/rcu/tasks.h:1070:37: note: each undeclared identifier is reported only once for each function it appears in
scripts/Makefile.build:267: recipe for target 'kernel/rcu/update.o' failed
make[2]: *** [kernel/rcu/update.o] Error 1
scripts/Makefile.build:505: recipe for target 'kernel/rcu' failed
make[1]: *** [kernel/rcu] Error 2
make[1]: *** Waiting for unfinished jobs....
  CC      net/ipv4/af_inet.o
  CC      crypto/blowfish_common.o
  CC      arch/x86/kernel/apic/ipi.o
  CC      sound/hda/hdac_controller.o
`,
		"kernel/rcu/tasks.h:1070:37: error: 'rcu_tasks_rude' undeclared (first use in this function); did you mean 'rcu_tasks_qs'?",
		"",
		"kernel/rcu/tasks.h",
	},
	{`
  CC      arch/x86/boot/compressed/kaslr.o
  AS      arch/x86/boot/compressed/mem_encrypt.o
  CC      arch/x86/boot/compressed/kaslr_64.o
  CC      arch/x86/boot/compressed/pgtable_64.o
  CC      arch/x86/boot/compressed/acpi.o
clang-10: /home/glider/llvm-project/llvm/lib/Target/X86/AsmParser/X86AsmParser.cpp:941: void {anonymous}::X86AsmParser::SwitchMode(unsigned int): Assertion 'FeatureBitset({mode}) == (STI.getFeatureBits() & AllModes)' failed.
Stack dump:
0.	Program arguments: /syzkaller/clang-kmsan/bin/clang-10 -cc1as -triple x86_64-unknown-linux-gnu -filetype obj -main-file-name head_64.S -target-cpu x86-64 -target-feature -mmx -target-feature -sse -I ./arch/x86/include -I ./arch/x86/include/generated -I ./include -I ./arch/x86/include/uapi -I ./arch/x86/include/generated/uapi -I ./include/uapi -I ./include/generated/uapi -fdebug-compilation-dir /syzkaller/managers/upstream-kmsan-gce/kernel -dwarf-debug-producer clang version 10.0.0 (/home/glider/llvm-project/clang c2443155a0fb245c8f17f2c1c72b6ea391e86e81) -I ./arch/x86/include -I ./arch/x86/include/generated -I ./include -I ./arch/x86/include/uapi -I ./arch/x86/include/generated/uapi -I ./include/uapi -I ./include/generated/uapi -dwarf-version=4 -mrelocation-model pic -o arch/x86/boot/compressed/head_64.o /tmp/head_64-984db4.s 
clang-10: /home/glider/llvm-project/llvm/lib/Target/X86/AsmParser/X86AsmParser.cpp:941: void {anonymous}::X86AsmParser::SwitchMode(unsigned int): Assertion 'FeatureBitset({mode}) == (STI.getFeatureBits() & AllModes)' failed.
Stack dump:
0.	Program arguments: /syzkaller/clang-kmsan/bin/clang-10 -cc1as -triple x86_64-unknown-linux-gnu -filetype obj -main-file-name mem_encrypt.S -target-cpu x86-64 -target-feature -mmx -target-feature -sse -I ./arch/x86/include -I ./arch/x86/include/generated -I ./include -I ./arch/x86/include/uapi -I ./arch/x86/include/generated/uapi -I ./include/uapi -I ./include/generated/uapi -fdebug-compilation-dir /syzkaller/managers/upstream-kmsan-gce/kernel -dwarf-debug-producer clang version 10.0.0 (/home/glider/llvm-project/clang c2443155a0fb245c8f17f2c1c72b6ea391e86e81) -I ./arch/x86/include -I ./arch/x86/include/generated -I ./include -I ./arch/x86/include/uapi -I ./arch/x86/include/generated/uapi -I ./include/uapi -I ./include/generated/uapi -dwarf-version=4 -mrelocation-model pic -o arch/x86/boot/compressed/mem_encrypt.o /tmp/mem_encrypt-3c62ac.s 
/syzkaller/clang-kmsan/bin/clang-10(_ZN4llvm3sys15PrintStackTraceERNS_11raw_ostreamE+0x1a)[0x285af4a]
/syzkaller/clang-kmsan/bin/clang-10(_ZN4llvm3sys15PrintStackTraceERNS_11raw_ostreamE+0x1a)[0x285af4a]
/syzkaller/clang-kmsan/bin/clang-10(_ZN4llvm3sys17RunSignalHandlersEv+0x3a)[0x2858c2a]
/syzkaller/clang-kmsan/bin/clang-10(_ZN4llvm3sys17RunSignalHandlersEv+0x3a)[0x2858c2a]
/syzkaller/clang-kmsan/bin/clang-10[0x2858d47]
/lib/x86_64-linux-gnu/libpthread.so.0(+0x11390)[0x14fcf8ccb390]
/syzkaller/clang-kmsan/bin/clang-10[0x2858d47]
/lib/x86_64-linux-gnu/libpthread.so.0(+0x11390)[0x14bb99841390]
/lib/x86_64-linux-gnu/libc.so.6(gsignal+0x38)[0x14fcf7a5e428]
/lib/x86_64-linux-gnu/libc.so.6(gsignal+0x38)[0x14bb985d4428]
/lib/x86_64-linux-gnu/libc.so.6(abort+0x16a)[0x14fcf7a6002a]
/lib/x86_64-linux-gnu/libc.so.6(abort+0x16a)[0x14bb985d602a]
/lib/x86_64-linux-gnu/libc.so.6(+0x2dbd7)[0x14fcf7a56bd7]
/lib/x86_64-linux-gnu/libc.so.6(+0x2dc82)[0x14fcf7a56c82]
/lib/x86_64-linux-gnu/libc.so.6(+0x2dbd7)[0x14bb985ccbd7]
/lib/x86_64-linux-gnu/libc.so.6(+0x2dc82)[0x14bb985ccc82]
/syzkaller/clang-kmsan/bin/clang-10[0x9aa6d8]
/syzkaller/clang-kmsan/bin/clang-10[0x9aa6d8]
/syzkaller/clang-kmsan/bin/clang-10[0x1b094da]
/syzkaller/clang-kmsan/bin/clang-10[0x1b094da]
/syzkaller/clang-kmsan/bin/clang-10[0x1b0d3a1]
/syzkaller/clang-kmsan/bin/clang-10[0x1b0d3a1]
/syzkaller/clang-kmsan/bin/clang-10[0x257bc55]
/syzkaller/clang-kmsan/bin/clang-10[0x257bc55]
/syzkaller/clang-kmsan/bin/clang-10[0x257f274]
/syzkaller/clang-kmsan/bin/clang-10[0xb86f8e]
/syzkaller/clang-kmsan/bin/clang-10(_Z10cc1as_mainN4llvm8ArrayRefIPKcEES2_Pv+0xc3f)[0xb8ac3f]
/syzkaller/clang-kmsan/bin/clang-10(main+0x18e3)[0xaeb2d3]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf0)[0x14fcf7a49830]
/syzkaller/clang-kmsan/bin/clang-10[0x257f274]
/syzkaller/clang-kmsan/bin/clang-10[0xb7f5d9]
/syzkaller/clang-kmsan/bin/clang-10[0xb86f8e]
/syzkaller/clang-kmsan/bin/clang-10(_Z10cc1as_mainN4llvm8ArrayRefIPKcEES2_Pv+0xc3f)[0xb8ac3f]
/syzkaller/clang-kmsan/bin/clang-10(main+0x18e3)[0xaeb2d3]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf0)[0x14bb985bf830]
/syzkaller/clang-kmsan/bin/clang-10[0xb7f5d9]
clang-10: error: unable to execute command: Aborted (core dumped)
clang-10: error: clang integrated assembler command failed due to signal (use -v to see invocation)
clang version 10.0.0 (/home/glider/llvm-project/clang c2443155a0fb245c8f17f2c1c72b6ea391e86e81)
Target: x86_64-unknown-linux-gnu
Thread model: posix
InstalledDir: /syzkaller/clang/bin
clang-10: note: diagnostic msg: PLEASE submit a bug report to https://bugs.llvm.org/ and include the crash backtrace, preprocessed source, and associated run script.
clang-10: error: unable to execute command: Aborted (core dumped)
clang-10: error: clang integrated assembler command failed due to signal (use -v to see invocation)
clang version 10.0.0 (/home/glider/llvm-project/clang c2443155a0fb245c8f17f2c1c72b6ea391e86e81)
Target: x86_64-unknown-linux-gnu
Thread model: posix
InstalledDir: /syzkaller/clang/bin
clang-10: note: diagnostic msg: PLEASE submit a bug report to https://bugs.llvm.org/ and include the crash backtrace, preprocessed source, and associated run script.
clang-10: note: diagnostic msg: 
********************

PLEASE ATTACH THE FOLLOWING FILES TO THE BUG REPORT:
Preprocessed source(s) and associated run script(s) are located at:
clang-10: note: diagnostic msg: /tmp/mem_encrypt-2af6ae.S
clang-10: note: diagnostic msg: /tmp/mem_encrypt-2af6ae.sh
clang-10: note: diagnostic msg: 

********************
scripts/Makefile.build:348: recipe for target 'arch/x86/boot/compressed/mem_encrypt.o' failed
make[2]: *** [arch/x86/boot/compressed/mem_encrypt.o] Error 254
make[2]: *** Waiting for unfinished jobs....
clang-10: note: diagnostic msg: 
********************

PLEASE ATTACH THE FOLLOWING FILES TO THE BUG REPORT:
Preprocessed source(s) and associated run script(s) are located at:
clang-10: note: diagnostic msg: /tmp/head_64-96b27a.S
clang-10: note: diagnostic msg: /tmp/head_64-96b27a.sh
clang-10: note: diagnostic msg: 

********************
scripts/Makefile.build:348: recipe for target 'arch/x86/boot/compressed/head_64.o' failed
make[2]: *** [arch/x86/boot/compressed/head_64.o] Error 254
arch/x86/boot/Makefile:115: recipe for target 'arch/x86/boot/compressed/vmlinux' failed
make[1]: *** [arch/x86/boot/compressed/vmlinux] Error 2
arch/x86/Makefile:284: recipe for target 'bzImage' failed
make: *** [bzImage] Error 2
`,
		`clang-10: error: unable to execute command: Aborted (core dumped)
clang-10: error: clang integrated assembler command failed due to signal (use -v to see invocation)`,
		"",
		"",
	},
	{`
scripts/kconfig/conf  --syncconfig Kconfig
  DESCEND  objtool
  CALL    scripts/atomic/check-atomics.sh
  CALL    scripts/checksyscalls.sh
  CHK     include/generated/compile.h
  GZIP    kernel/config_data.gz
  CC      kernel/configs.o
  AR      kernel/built-in.a
  GEN     .version
  LD      vmlinux.o
  MODPOST vmlinux.o
  MODINFO modules.builtin.modinfo
  GEN     modules.builtin
  LD      .tmp_vmlinux1
arch/x86/platform/efi/efi_64.o: In function 'efi_thunk_set_virtual_address_map':
/syzkaller/managers/upstream-linux-next-kasan-gce-root/kernel/arch/x86/platform/efi/efi_64.c:560: undefined reference to '__efi64_thunk'
arch/x86/platform/efi/efi_64.o: In function 'efi_set_virtual_address_map':
/syzkaller/managers/upstream-linux-next-kasan-gce-root/kernel/arch/x86/platform/efi/efi_64.c:902: undefined reference to 'efi_uv1_memmap_phys_prolog'
/syzkaller/managers/upstream-linux-next-kasan-gce-root/kernel/arch/x86/platform/efi/efi_64.c:921: undefined reference to 'efi_uv1_memmap_phys_epilog'
Makefile:1078: recipe for target 'vmlinux' failed
make: *** [vmlinux] Error 1
`,
		`arch/x86/platform/efi/efi_64.c:560: undefined reference to '__efi64_thunk'
arch/x86/platform/efi/efi_64.c:902: undefined reference to 'efi_uv1_memmap_phys_prolog'
arch/x86/platform/efi/efi_64.c:921: undefined reference to 'efi_uv1_memmap_phys_epilog'`,
		"/syzkaller/managers/upstream-linux-next-kasan-gce-root/kernel",
		"arch/x86/platform/efi/efi_64.c",
	},
	{`
/syzkaller/managers/upstream-linux-next-kasan-gce-root/kernel/arch/x86/platform/efi/efi_64.c:560: undefined reference to '__efi64_thunk'
`,
		`arch/x86/platform/efi/efi_64.c:560: undefined reference to '__efi64_thunk'`,
		"/syzkaller/managers/upstream-linux-next-kasan-gce-root/kernel/",
		"arch/x86/platform/efi/efi_64.c",
	},
	{`
  CC      net/ipv6/ip6_output.o
  CC      security/selinux/ss/policydb.o
  CC      net/ipv4/route.o
In file included from security/smack/smack_netfilter.c:18:
./include/linux/netfilter_ipv6.h: In function ‘nf_ipv6_br_defrag’:
./include/linux/netfilter_ipv6.h:110:9: error: implicit declaration of function ‘nf_ct_frag6_gather’ [-Werror=implicit-function-declaration]
  110 |  return nf_ct_frag6_gather(net, skb, user);
      |         ^~~~~~~~~~~~~~~~~~
In file included from security/apparmor/lsm.c:27:
./include/linux/netfilter_ipv6.h: In function ‘nf_ipv6_br_defrag’:
./include/linux/netfilter_ipv6.h:110:9: error: implicit declaration of function ‘nf_ct_frag6_gather’ [-Werror=implicit-function-declaration]
  110 |  return nf_ct_frag6_gather(net, skb, user);
      |         ^~~~~~~~~~~~~~~~~~
In file included from net/bridge/br_netfilter_ipv6.c:30:
./include/linux/netfilter_ipv6.h: In function ‘nf_ipv6_br_defrag’:
./include/linux/netfilter_ipv6.h:110:9: error: implicit declaration of function ‘nf_ct_frag6_gather’ [-Werror=implicit-function-declaration]
  110 |  return nf_ct_frag6_gather(net, skb, user);
      |         ^~~~~~~~~~~~~~~~~~
In file included from net/bridge/br_netfilter_hooks.c:31:
./include/linux/netfilter_ipv6.h: In function ‘nf_ipv6_br_defrag’:
./include/linux/netfilter_ipv6.h:110:9: error: implicit declaration of function ‘nf_ct_frag6_gather’ [-Werror=implicit-function-declaration]
  110 |  return nf_ct_frag6_gather(net, skb, user);
      |         ^~~~~~~~~~~~~~~~~~
  CC      net/openvswitch/datapath.o
  CC      net/llc/llc_output.o
  CC      net/ieee802154/core.o
cc1: some warnings being treated as errors
scripts/Makefile.build:278: recipe for target 'security/smack/smack_netfilter.o' failed
make[2]: *** [security/smack/smack_netfilter.o] Error 1
scripts/Makefile.build:489: recipe for target 'security/smack' failed
make[1]: *** [security/smack] Error 2
make[1]: *** Waiting for unfinished jobs....
  CC      net/lapb/lapb_iface.o
  CC      net/netlabel/netlabel_domainhash.o
  CC      net/netlabel/netlabel_addrlist.o
`,
		"./include/linux/netfilter_ipv6.h:110:9: error: implicit declaration of function 'nf_ct_frag6_gather' [-Werror=implicit-function-declaration]",
		"",
		"include/linux/netfilter_ipv6.h",
	},
	{`
ld: mm/slub.o: in function '__kmem_cache_create':
slub.c:(.text+0x6260): multiple definition of '__kmem_cache_create'; mm/page_alloc.o:page_alloc.c:(.text+0x1970): first defined here
make: *** [Makefile:1139: vmlinux] Error 1
`,
		"slub.c:(.text+0x6260): multiple definition of '__kmem_cache_create'; mm/page_alloc.o:page_alloc.c:(.text+0x1970): first defined here",
		"",
		"mm/page_alloc.c",
	},
	{`
ld: mm/slub.o:(.bss+0x0): multiple definition of 'foobar'; mm/page_alloc.o:(.bss+0x34): first defined here
make: *** [Makefile:1139: vmlinux] Error 1
`,
		"ld: mm/slub.o:(.bss+0x0): multiple definition of 'foobar'; mm/page_alloc.o:(.bss+0x34): first defined here",
		"",
		"mm/slub.c",
	},
	{`
ld.lld: error: duplicate symbol: __kmem_cache_create
>>> defined at page_alloc.c
>>>            page_alloc.o:(__kmem_cache_create) in archive mm/built-in.a
>>> defined at slub.c
>>>            slub.o:(.text+0x6260) in archive mm/built-in.a
make: *** [Makefile:1139: vmlinux] Error 1
`,
		"ld.lld: error: duplicate symbol: __kmem_cache_create",
		"",
		"", // ld.lld makes it very hard to extract the file name
	},
	{`
ld.lld: error: duplicate symbol: foobar
>>> defined at page_alloc.c
>>>            page_alloc.o:(foobar) in archive mm/built-in.a
>>> defined at slub.c
>>>            slub.o:(.bss+0x0) in archive mm/built-in.a
make: *** [Makefile:1139: vmlinux] Error 1
`,
		"ld.lld: error: duplicate symbol: foobar",
		"",
		"", // ld.lld makes it very hard to extract the file name
	},
	{`
mm/page_alloc.o:(.data+0x1a40): multiple definition of '__kmem_cache_create'
mm/slub.o:(.data+0x7a0): first defined here
Makefile:1160: recipe for target 'vmlinux' failed
make: *** [vmlinux] Error 1
`,
		"mm/page_alloc.o:(.data+0x1a40): multiple definition of '__kmem_cache_create'",
		"",
		"mm/page_alloc.c",
	},
}
