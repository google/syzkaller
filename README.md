# syzkaller - linux kernel fuzzer

[![Build Status](https://travis-ci.org/google/syzkaller.svg?branch=master)](https://travis-ci.org/google/syzkaller)

`syzkaller` is an unsupervised coverage-guided Linux kernel fuzzer.

The project mailing list is [syzkaller@googlegroups.com](https://groups.google.com/forum/#!forum/syzkaller).
You can subscribe to it with a google account or by sending an email to syzkaller+subscribe@googlegroups.com.

[List of found bugs](docs/found_bugs.md).

## Documentation

- [How to install syzkaller](docs/setup.md)
- [How to use syzkaller](docs/usage.md)
- [How syzkaller works](docs/internals.md)
- [How to contribute to syzkaller](docs/contributing.md)
- [How to report Linux kernel bugs](docs/linux_kernel_reporting_bugs.md)

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
