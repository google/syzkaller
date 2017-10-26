# syzkaller - kernel fuzzer

[![Build Status](https://travis-ci.org/google/syzkaller.svg?branch=master)](https://travis-ci.org/google/syzkaller)

`syzkaller` is an unsupervised coverage-guided kernel fuzzer. `Linux` kernel fuzzing has the most support, `akaros`, `freebsd`, `fuchsia`, `netbsd` and `windows` are supported to varying degrees.

The project mailing list is [syzkaller@googlegroups.com](https://groups.google.com/forum/#!forum/syzkaller).
You can subscribe to it with a google account or by sending an email to syzkaller+subscribe@googlegroups.com.

[List of found bugs](docs/found_bugs.md).

## Documentation

Initially syzkaller was developed with Linux kernel fuzzing in mind, but now it's being extended to support other OS kernels as well.
Most of the documentation at this moment is related to the Linux kernel.
For other OS kernels check: [Akaros](docs/akaros.md), [FreeBSD](docs/freebsd.md), [Fuchsia](docs/fuchsia.md), [NetBSD](docs/netbsd.md), [Windows](docs/windows.md).

- [How to install syzkaller](docs/setup.md)
- [How to use syzkaller](docs/usage.md)
- [How syzkaller works](docs/internals.md)
- [How to contribute to syzkaller](docs/contributing.md)
- [How to report Linux kernel bugs](docs/linux/reporting_kernel_bugs.md)

## External Articles

 - [Kernel QA with syzkaller and qemu](https://github.com/hardenedlinux/Debian-GNU-Linux-Profiles/blob/master/docs/harbian_qa/fuzz_testing/syzkaller_general.md) (tutorial on how to setup syzkaller with qemu)
 - [Syzkaller crash DEMO](https://github.com/hardenedlinux/Debian-GNU-Linux-Profiles/blob/master/docs/harbian_qa/fuzz_testing/syzkaller_crash_demo.md) (tutorial on how to extend syzkaller with new syscalls)
 - [Coverage-guided kernel fuzzing with syzkaller](https://lwn.net/Articles/677764/) (by David Drysdale)
 - [ubsan, kasan, syzkaller und co](http://www.strlen.de/talks/debug-w-syzkaller.pdf) ([video](https://www.youtube.com/watch?v=Acp0A9X1254)) (by Florian Westphal)
 - [Debugging a kernel crash found by syzkaller](http://vegardno.blogspot.de/2016/08/sync-debug.html) (by Quentin Casasnovas)
 - [Linux Plumbers 2016 talk slides](https://docs.google.com/presentation/d/1iAuTvzt_xvDzS2misXwlYko_VDvpvCmDevMOq2rXIcA/edit?usp=sharing)
 - [syzkaller: the next gen kernel fuzzer](https://www.slideshare.net/DmitryVyukov/syzkaller-the-next-gen-kernel-fuzzer) (basics of operations, tutorial on how to run syzkaller and how to extend it to fuzz new drivers)

## Disclaimer

This is not an official Google product.
