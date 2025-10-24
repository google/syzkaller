# syzkaller - kernel fuzzer (Linux amd64 fork)

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

`syzkaller` (`[siːzˈkɔːlə]`) is an unsupervised coverage-guided kernel fuzzer.

**This is a simplified fork that only supports Linux on amd64 (x86_64) architecture.**

All syscall definitions have been removed and must be written from scratch. This fork eliminates support for:
- Other operating systems (FreeBSD, NetBSD, OpenBSD, Darwin, Windows, Fuchsia, etc.)
- Other architectures (arm, arm64, ppc64le, s390x, riscv64, mips64le, 386)
- 32-bit support
- Big-endian support

## Documentation

This fork focuses exclusively on Linux kernel fuzzing on amd64 architecture.

- [How to install syzkaller](docs/setup.md)
- [How to use syzkaller](docs/usage.md)
- [How syzkaller works](docs/internals.md)
- [Linux kernel setup](docs/linux/setup.md)
- [How to report Linux kernel bugs](docs/linux/reporting_kernel_bugs.md)
- [Linux kernel found bugs](docs/linux/found_bugs.md)

## Disclaimer

This is not an official Google product.
