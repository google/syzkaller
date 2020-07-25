# Pseudo-syscalls

Besides regular system calls, a [syscall
description](syscall_descriptions.md) file can also contain
pseudo-syscalls. These are C functions defined in the
executor. When a test program uses a pseudo-syscall, the executor
will generate the pseudo-syscall function code in the resulting C program. 

This allows a test program to have specific code blocks to perform
certain actions, they may also be used as more test-friendly wrappers
for primitive syscalls.

Use of pseudo-syscalls is generally **discouraged** because they ruin all
advantages of the declarative descriptions (declarativeness, conciseness,
fuzzer control over all aspects, possibility of global improvements to
the logic, static checking, fewer bugs, etc), increase maintenance burden,
are non-reusable and make C reproducers longer. However, syzlang is not
expressive enough to cover all possible cases, so use of pseudo-syscalls
needs to be considered on a case-by-cases basis (additional benefit,
amount of code, possibility of extending syzlang to cover this case, etc).

## How to add a pseudo-syscall to the executor

First, think about the scope of the pseudo-syscall and which systems and
subsystems it will be related to. The executor includes a fixed set of C
header files containing the code of the pseudo-syscalls. Check if the
new one can fit in one of the existing files before creating a new
one. These header files are defined in [gen.go](../pkg/csource/gen.go):

    executorFilenames := []string{
            "common_linux.h",
            "common_akaros.h",
            "common_bsd.h",
            "common_fuchsia.h",
            "common_windows.h",
            "common_test.h",
            "common_kvm_amd64.h",
            "common_kvm_arm64.h",
            "common_usb_linux.h",
            "common_usb_netbsd.h",
            "common_usb.h",
            "android/android_seccomp.h",
            "kvm.h",
            "kvm.S.h",
    }

For instance, if our new pseudo-syscall is Linux-specific, then
[common_linux.h](../executor/common_linux.h) would be the place to put it.

The actual pseudo-syscall function may look something like this:

    #if SYZ_EXECUTOR || __NR_syz_mycall
    /* Add all the necessary #include and #define headers */

    static long syz_mycall(volatile long a0, volatile long a1)
    {
            /* Function body */
    }
    #endif

Make sure that all the function requirements are met and that it can
be compiled. Note that the function name must start with "syz_". It may
also take a different number of arguments. Type of arguments must be
`volatile long`, return type - `long`. `long` is required to avoid
potential calling convention issues because it is casted to a function
pointer that accepts `long`'s. The reason for `volatile` is interesting:
lots of libc functions are annotated with various argument constraints
(e.g. this argument should not be `NULL`, or that argument must be a
valid file descriptor); C reproducers may call these functions with
constant arguments and compiler may see that some of these constraints
are violated (e.g. passing `NULL` to a `non-NULL` argument, or passing
`-1` as file descriptor) and produce errors/warnings. `volatile` prevents
that.

Now, to handle the pseudo-syscall properly we have to update the
`isSupportedSyzkall` in
[syscalls_linux.go](../pkg/host/syscalls_linux.go) and add a particular
case for this syscall, enabling it when necessary. If we want to enable
it unconditionally we can simply make `isSupportedSyzkall` return `true,
""` for it:

    func isSupportedSyzkall(sandbox string, c *prog.Syscall) (bool, string) {
            switch c.CallName {
            ...
            case "syz_mycall":
                    return true, ""

Finally, run `make generate`. Now you can use it in a syscall
description file as if it was a regular system call:

    syz_mycall(arg0 pid, arg1 const[0])

<div id="dependencies"/>

## External Dependencies

The implementation must not use any external libraries nor external headers,
except for the most basic and standard ones (like `<unistd.h>` and
`<sys/mman.h>`). In particular, it must not depend on libraries/headers
installed by additional packages nor on headers for recently added kernel
subsystems. External dependencies have proved to be brittle and easily cause
build breakage because all dependencies will be required for any build/run on
the fuzzer and any C reproducer. For example, packages/headers may be missing
on some distros, named differently, be of a wrong version, broken, or conflict
with other headers. Unfortunately, there is no way to reliably specify such
dependencies and requirements for C programs. Therefore, if the pseudo-syscall
requires definitions of some structures, constants, or helper functions, these
should be described in the executor code itself as minimally as possible (they
will be part of C reproducers).

## Testing

Each new pseudo-syscall should have at least one test in `sys/OS/test`.
See [Linux tests](/sys/linux/test) for an example. A tests is just a program
with checked syscall return values. There should be at least one test
that contains "the main successful scenario" of using the pseudo-syscall.
See [io_uring test](/sys/linux/test/io_uring) as a good example.
Such tests are important because they ensure that the pseudo-syscall code
does not contain "stupid" bugs (e.g. crash on NULL-deref each time),
that it is possible for the fuzzer to come up with the successful scenario
(as a combination of the pseudo-syscall and the surrounding descriptions)
and that it will continue to work in future.
See [Testing of descriptions](syscall_descriptions.md#testing)
for details about the tests.
