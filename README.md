# syzkaller - kernel fuzzer

[![CI Status](https://github.com/google/syzkaller/workflows/ci/badge.svg)](https://github.com/google/syzkaller/actions?query=workflow/ci)
[![fuzzit](https://app.fuzzit.dev/badge?org_id=syzkaller=master)](https://fuzzit.dev)
[![OSS-Fuzz](https://oss-fuzz-build-logs.storage.googleapis.com/badges/syzkaller.svg)](https://bugs.chromium.org/p/oss-fuzz/issues/list?q=label:Proj-syzkaller)
[![Go Report Card](https://goreportcard.com/badge/github.com/google/syzkaller)](https://goreportcard.com/report/github.com/google/syzkaller)
[![Coverage Status](https://codecov.io/gh/google/syzkaller/graph/badge.svg)](https://codecov.io/gh/google/syzkaller)
[![GoDoc](https://godoc.org/github.com/google/syzkaller?status.svg)](https://godoc.org/github.com/google/syzkaller)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

`syzkaller` (`[siːzˈkɔːlə]`) is an unsupervised coverage-guided kernel fuzzer.\
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
- [Tech talks and articles](docs/talks.md)
- [Research work based on syzkaller](docs/research.md)

## Disclaimer

This is not an official Google product.
