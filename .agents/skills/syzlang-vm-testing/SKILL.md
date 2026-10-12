---
name: syzlang-vm-testing
description: >-
  Verify syzkaller syscall descriptions (sys/linux/*.txt) and seed programs (sys/linux/test/*)
  inside a QEMU VM using syz-manager -mode run-tests, syzbot buildroot images, and kernel
  dynamic_debug/tracing.
---

# Syzlang & Seed Program QEMU VM Verification

Use this skill to verify new or updated Linux syscall descriptions (`sys/linux/*.txt`), executor
setup (`executor/common_linux.h`), and seed programs (`sys/linux/test/*`) inside a QEMU VM.

For general syzlang description and seed authoring rules (and host-side parsing tests), see
[`sys/GEMINI.md`](../../../sys/GEMINI.md).

## 1. Obtaining the VM Disk Image and Kernel

1. **Userspace Disk Image (Buildroot)**:
   If no disk image is available locally, download and decompress the standard syzkaller buildroot
   image from `https://storage.googleapis.com/syzkaller/images/buildroot-amd64-2025.05.gz`.

2. **Kernel Image (`bzImage` and `vmlinux`)**:
   - If the user provided a Linux kernel build directory or `bzImage` path, use it.
   - Otherwise, visit `https://syzkaller.appspot.com/upstream/manager/ci-qemu-upstream`, download
     the latest `kernel image` (`bzImage`) and `vmlinux` (if needed for coverage symbolization),
     and decompress them.

## 2. Running Seed Programs via `syz-manager -mode run-tests`

Build `syz-manager` and `syz-executor`:
```bash
CI=true ./tools/syz-env make manager executor
```

Create a minimal `syz-manager` config (e.g., `/tmp/runtest.cfg`):
```json
{
	"name": "runtest",
	"target": "linux/amd64",
	"http": "127.0.0.1:0",
	"workdir": "/tmp/syz-runtest-workdir",
	"image": "/tmp/buildroot-amd64.img",
	"syzkaller": ".",
	"sandbox": "none",
	"procs": 1,
	"type": "qemu",
	"vm": {
		"count": 1,
		"kernel": "/tmp/bzImage",
		"cmdline": "root=/dev/sda1",
		"cpu": 2,
		"mem": 2048
	}
}
```
- **KVM vs TCG**: By default on `linux/amd64`, syzkaller passes
  `-enable-kvm -cpu host,migratable=off` to QEMU. If KVM (`/dev/kvm`) is available on the host,
  always use it. If KVM is not available, configure TCG in `vm.qemu_args` (e.g.,
  `"qemu_args": "-machine q35 -accel tcg -cpu max"`) and be very patient, as booting an
  instrumented kernel under software emulation takes several minutes.
- **Sandbox**: If the seed program targets syscalls fuzzed under `"sandbox": "namespace"` in
  production, also test with `"sandbox": "namespace"` to verify that devices or sockets created in
  `init_net` work from child network namespaces.

Run the specific seed test(s) with `-mode run-tests` and `-tests <prefix>`:
```bash
./bin/syz-manager -config /tmp/runtest.cfg -mode run-tests -tests <seed_name>
```
`syz-manager -mode run-tests` boots the QEMU VM, runs the machine check, and executes matching
`sys/linux/test/<seed_name>` programs via both `syz-executor` (verifying KCOV coverage and that
every call returns the expected errno, `0` by default) and `pkg/csource` C binaries. Pass `-debug`
to dump full VM console and executor output.

## 3. Debugging What the Program Actually Does in the Kernel

A seed test passing with `errno=0` on every syscall is necessary, but for subsystems with
asynchronous workqueues, tasklets, softirqs, or shared `mmap` rings (e.g., RDMA `rxe`, `io_uring`,
`vhost`), the kicking syscall can return `0` even when the asynchronous worker immediately aborts
on a bad struct layout, ring offset, or key.

When you need to verify where execution actually went inside the kernel:

1. **Collect Coverage with `syz-execprog` and Symbolize with `addr2line`**:
   Build `syz-execprog` (`CI=true ./tools/syz-env make execprog`) and run the seed program inside
   the VM with `-coverfile` (e.g., `syz-execprog -executor ./syz-executor -coverfile /tmp/cover
   -repeat 1 <seed_file>`) to dump the covered PCs for each call. Then pass the PCs from
   `/tmp/cover` to `addr2line -f -e /path/to/vmlinux` on the host to see the exact kernel functions
   and source lines executed.
2. **Enable Kernel `dynamic_debug` on the Console**:
   Add `dyndbg="file *<subsystem>* +pflt"` to `vm.cmdline` in the manager config and pass `-debug`
   to `syz-manager` so kernel `pr_debug` / `dev_dbg` state transitions are printed during the test
   run.
3. **Inspect Generated C Code (`syz-prog2c`)**:
   As another debugging option, convert the seed program to standalone C with `./bin/syz-prog2c
   -prog ./sys/linux/test/<seed_name> -trace` to inspect the exact memory offsets, struct layouts,
   and setup calls (`setup_sysctl`, `initialize_netdevices_init`, etc.) or inspect `mmap` ring
   state after a short `usleep`.
4. **Clean Up**:
   Remove temporary configs, workdirs, and downloaded artifacts in `/tmp/` when done.
