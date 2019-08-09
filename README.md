# syzkaller - kernel fuzzer

[![Build Status](https://travis-ci.org/google/syzkaller.svg?branch=master)](https://travis-ci.org/google/syzkaller)
[![fuzzit](https://app.fuzzit.dev/badge?org_id=syzkaller=master)](https://fuzzit.dev)
[![Go Report Card](https://goreportcard.com/badge/github.com/google/syzkaller)](https://goreportcard.com/report/github.com/google/syzkaller)
[![Coverage Status](https://codecov.io/gh/google/syzkaller/graph/badge.svg)](https://codecov.io/gh/google/syzkaller)
[![GoDoc](https://godoc.org/github.com/google/syzkaller?status.svg)](https://godoc.org/github.com/google/syzkaller)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

`syzkaller` is an unsupervised coverage-guided kernel fuzzer.\
Supported OSes: `Akaros`, `FreeBSD`, `Fuchsia`, `gVisor`, `Linux`, `NetBSD`, `OpenBSD`, `Windows`.

Mailing list: [syzkaller@googlegroups.com](https://groups.google.com/forum/#!forum/syzkaller) (join on [web](https://groups.google.com/forum/#!forum/syzkaller) or by [email](mailto:syzkaller+subscribe@googlegroups.com)).

Found bugs: [Akaros](docs/akaros/found_bugs.md), [Darwin/XNU](docs/darwin/README.md), [FreeBSD](docs/freebsd/found_bugs.md), [Linux](docs/linux/found_bugs.md), [NetBSD](docs/netbsd/found_bugs.md), [OpenBSD](docs/openbsd/found_bugs.md), [Windows](docs/windows/README.md).

## Documentation

Initially, syzkaller was developed with Linux kernel fuzzing in mind, but now
it's being extended to support other OS kernels as well.
Most of the documentation at this moment is related to the [Linux](docs/linux/setup.md) kernel.
For other OS kernels check:
[Akaros](docs/akaros/README.md),
[Darwin/XNU](docs/darwin/README.md),
[FreeBSD](docs/freebsd/README.md),
[Fuchsia](docs/fuchsia/README.md),
[NetBSD](docs/netbsd/README.md),
[OpenBSD](docs/openbsd/setup.md),
[Windows](docs/windows/README.md),
[gVisor](docs/gvisor/README.md).

- [How to install syzkaller](docs/setup.md)
- [How to use syzkaller](docs/usage.md)
- [How syzkaller works](docs/internals.md)
- [How to contribute to syzkaller](docs/contributing.md)
- [How to report Linux kernel bugs](docs/linux/reporting_kernel_bugs.md)

## External Articles

 - [Research work based on syzkaller](docs/research.md)
 - From [HardenedLinux](https://github.com/hardenedlinux) project:
   - [Kernel QA with syzkaller and qemu](https://github.com/hardenedlinux/Debian-GNU-Linux-Profiles/blob/master/docs/harbian_qa/fuzz_testing/syzkaller_general.md) (tutorial on how to setup syzkaller with qemu)
   - [Syzkaller crash DEMO](https://github.com/hardenedlinux/Debian-GNU-Linux-Profiles/blob/master/docs/harbian_qa/fuzz_testing/syzkaller_crash_demo.md) (tutorial on how to extend syzkaller with new syscalls)
   - [Kernel debug tool with syzkaller](https://github.com/hardenedlinux/Debian-GNU-Linux-Profiles/blob/master/docs/harbian_qa/fuzz_testing/syz_debug.md) (debugging qemu VM created by syz-manager with gdb)
   - [Explanation of some syzkaller internals](https://github.com/hardenedlinux/Debian-GNU-Linux-Profiles/blob/master/docs/harbian_qa/fuzz_testing/syz_analysis.md)
   - [A example of fuzzing the ceph filesystem](https://github.com/hardenedlinux/Debian-GNU-Linux-Profiles/tree/master/docs/harbian_qa/fuzz_testing/syz_for_ceph)
 - [Coverage-guided kernel fuzzing with syzkaller](https://lwn.net/Articles/677764/) (by David Drysdale)
 - [ubsan, kasan, syzkaller und co](http://www.strlen.de/talks/debug-w-syzkaller.pdf) ([video](https://www.youtube.com/watch?v=Acp0A9X1254)) (by Florian Westphal)
 - [Debugging a kernel crash found by syzkaller](http://vegardno.blogspot.de/2016/08/sync-debug.html) (by Quentin Casasnovas)
 - [Linux Plumbers 2016 talk slides](https://docs.google.com/presentation/d/1iAuTvzt_xvDzS2misXwlYko_VDvpvCmDevMOq2rXIcA/edit?usp=sharing)
 - [syzkaller: the next gen kernel fuzzer](https://www.slideshare.net/DmitryVyukov/syzkaller-the-next-gen-kernel-fuzzer) (basics of operations, tutorial on how to run syzkaller and how to extend it to fuzz new drivers)
 - [syzbot and the tale of thousand kernel bugs](https://events.linuxfoundation.org/wp-content/uploads/2017/11/Syzbot-and-the-Tale-of-Thousand-Kernel-Bugs-Dmitry-Vyukov-Google.pdf) [[video](https://www.youtube.com/watch?v=qrBVXxZDVQY)]

## Disclaimer

This is not an official Google product.
