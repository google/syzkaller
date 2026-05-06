# OpenBSD Syscall Descriptions — Maintenance Guide

This document captures **OpenBSD-specific** lessons learned, conventions,
and procedures.  It deliberately avoids restating information already in
the upstream docs:

- [docs/syscall_descriptions.md](/docs/syscall_descriptions.md) — general
  workflow for adding descriptions, naming conventions, declaration order,
  description compilation internals, testing
- [docs/syscall_descriptions_syntax.md](/docs/syscall_descriptions_syntax.md)
  — full syzlang grammar and type reference
- [docs/openbsd/setup.md](/docs/openbsd/setup.md) — building syzkaller,
  compiling an OpenBSD kernel, creating VMs, running syz-manager
- [sys/GEMINI.md](/sys/GEMINI.md) — Linux-focused description-writing
  guidance (some advice on padding, flags, and field types applies
  universally)

Read those first.  Everything below is either OpenBSD-specific or records
pitfalls we hit that aren't covered upstream.

---

## 1. Repository Layout

```
sys/openbsd/
  *.txt           — syzlang description files
  *.txt.const     — extracted constants (generated, checked in)
  init.go         — neutralization logic (dangerous ioctls, sysctl, etc.)
  verify/         — C programs for struct-size verification on real OpenBSD
```

File naming follows the project-wide conventions in
`docs/syscall_descriptions.md` § "Describing new system calls", step 2.

## 2. Kernel Source Reference

Keep a checkout of `github.com/openbsd/src` (shallow clone is fine) and
reference it as `$OPENBSD_SRC`.

Key source locations (OpenBSD-specific paths):

| What | Where |
|------|-------|
| Syscall table | `sys/kern/syscalls.master` |
| Syscall implementations | `sys/kern/sys_*.c`, `sys/kern/kern_*.c`, `sys/kern/vfs_syscalls.c` |
| Ioctl structs & commands | `sys/sys/*.h` (e.g. `audioio.h`, `pfvar.h`) |
| Device drivers | `sys/dev/*.c` (e.g. `audio.c`, `video.c`) |
| Network stack | `sys/net/*.c`, `sys/netinet/*.c`, `sys/netinet6/*.c` |
| DRM/GPU | `sys/dev/pci/drm/include/uapi/drm/*.h` |
| Architecture-specific | `sys/arch/amd64/include/` |

## 3. Extraction & Verification

### 3.1 Environment

Go ≥1.26 is required (see `go.mod`).  If the system Go is older:

```sh
export PATH="/usr/local/go/bin:$PATH"
```

### 3.2 OpenBSD-Specific Extractor Behaviour

The extractor ([sys/syz-extract/openbsd.go](/sys/syz-extract/openbsd.go))
passes these **non-obvious** flags to `cc`:

- `-U__linux__` — prevents `#ifdef __linux__` code paths in shared
  headers (critical for DRM, see § 4.3)
- `-D_KERNEL` — exposes kernel-internal definitions
- `-D__BSD_VISIBLE=1` — exposes BSD extensions

Some syscall numbers use a `SYS___` prefix (e.g. `SYS___tfork`).  The
extractor has a `syscallsQuirks` map that handles this automatically;
if you add a syscall whose kernel symbol uses the `__` prefix, add it
to that map.

### 3.3 Verification Sequence

The standard workflow from `docs/syscall_descriptions.md` applies.  For
OpenBSD the concrete commands are:

```sh
# 1. Extract (single file)
bin/syz-extract -build -os=openbsd -sourcedir=$OPENBSD_SRC -arch=amd64 sys/openbsd/<file>.txt

# …or extract everything:
make extract TARGETOS=openbsd SOURCEDIR=$OPENBSD_SRC

# 2. Spot-check the const diff
git diff sys/openbsd/*.const

# 3–6. Standard build + test
make descriptions
make format
go test -short -count=1 ./sys/openbsd/
go test -short -count=1 ./prog/...
```

**Tip:** if `make descriptions` fails with a confusing error, run
`make format` first — some failures are caused by formatting drift.

### 3.4 Struct Size Verification on Real OpenBSD

Some struct sizes cannot be verified on a Linux cross-compilation host
(padding, alignment, or type-width differences).  For critical structs,
write a `_Static_assert` test program and run it on real OpenBSD.

Example pattern (see `sys/openbsd/verify/pf_struct_sizes.c`):

```c
#include <net/pfvar.h>
_Static_assert(sizeof(struct pfioc_rule) == 3424, "pfioc_rule size");
```

Provide a BSD `Makefile` so the user can simply `make && ./test` on an
OpenBSD machine.

On the Linux host you can do quick smoke-tests by adding `_Static_assert`
lines directly into the extraction include block, but be aware that
`sizeof(long)`, padding, and some typedefs may differ between hosts.

## 4. OpenBSD vs Linux: Struct & Type Differences

This section documents differences that have caused real bugs in our
descriptions.  None of this is covered in the upstream docs.

### 4.1 Struct Layout

**BSD sockaddr has a `len` field.**  All `sockaddr_*` structs on OpenBSD
begin with a 1-byte `len` and 1-byte `family`, not a 2-byte `family`:

```syzlang
# OpenBSD (from sys/openbsd/socket_inet.txt)
sockaddr_in {
    len     const[16, int8]
    family  const[AF_INET, int8]
    port    sock_port
    addr    int32be
    pad     array[const[0, int8], 8]
}
```

**IPC structs differ.**  `ipc_perm` on OpenBSD has field order
`cuid, cgid, uid, gid, mode, seq, key` — different from Linux.
Always verify against `sys/sys/ipc.h`.

**`struct stat` differs significantly.**  OpenBSD uses `dev_t` =
`int32_t` (not `unsigned int` / `dev_t` on Linux) and a different
field ordering.  Always verify against `sys/sys/stat.h`.

### 4.2 Ioctl Encoding

OpenBSD uses `sys/ioccom.h` (same as other BSDs).  When verifying ioctl
directions, check the actual macro usage in the header (`_IOR` vs
`_IOWR` etc.) — the kernel source is authoritative, not the ioctl number
alone.

### 4.3 DRM Headers

OpenBSD ships DRM headers at `sys/dev/pci/drm/include/uapi/drm/`.
These headers have `#ifdef __linux__` guards that select between Linux
and BSD types:

- **Linux path**: `typedef unsigned int drm_handle_t;` (4 bytes)
- **BSD path**: `typedef unsigned long drm_handle_t;` (8 bytes on amd64)

The `-U__linux__` flag in the extractor ensures the BSD code path is
used.  If you see DRM struct size mismatches, check this first.

### 4.4 Network Packet Structures

Some network struct fields use different byte-order conventions or
widths compared to Linux:

- IPv4 Router Alert option: `int16be`, not `int32be`
- IPv6 Pad1 option: 1 byte, not 3
- ICMPv6 Neighbor Solicitation has a 4-byte `reserved` field
- ICMP mask request/reply includes `id` and `seq_num` fields

Always verify against the OpenBSD `<netinet/*.h>` headers and RFCs.

## 5. Syzlang Pitfalls (OpenBSD-Specific)

These are problems we actually hit.  Generic syzlang advice lives in
`docs/syscall_descriptions.md` § "Description tips and FAQ".

### 5.1 Reserved Field Names

`parent` and `syscall` are reserved in syzlang (used in `len[]` path
expressions).  If the kernel struct uses one of these as a field name,
rename and comment:

```syzlang
    parent_name  string[filename, 64]  # kernel field: "parent"
```

### 5.2 Interface Names Use `filename`

For fields that hold interface names (e.g. `ifname`), table names, or
label strings, use `string[filename, SIZE]`.  There is no `devname`
type.  This follows the convention in `dev_bpf.txt`.

### 5.3 `bytesize` Requires a Field Reference

`bytesize` takes an argument/field name, not a type name.  If you need
a fixed byte width for an element-size field, use the concrete int type
directly (e.g. `int32`).

### 5.4 `define` Cannot Override Existing Macros

The syzlang `define` directive wraps its output in `#ifndef`/`#endif`,
so it cannot override compiler builtins or previously-defined macros.
To *undefine* something, add a flag in
[sys/syz-extract/openbsd.go](/sys/syz-extract/openbsd.go) (as we did
with `-U__linux__`).

### 5.5 Opaque / Oversized Structs

When a kernel struct is very large and impractical to describe fully,
use an opaque byte array:

```syzlang
type pf_rule_data array[int8, 1360]
```

Document the real size and offset in a comment, and verify that the
total container size matches the kernel.

### 5.6 OpenBSD Header Include Order

OpenBSD headers have interdependencies that differ from Linux:

- `<sys/mbuf.h>` is needed before many `netinet/*.h` headers (it
  defines `struct mbuf` used under `_KERNEL`)
- `<sys/param.h>` should come early (defines `MAXPATHLEN`, etc.)
- `<sys/types.h>` must be first in most files

## 6. Neutralization (init.go)

Some operations can crash the VM or kill the SSH connection.  These must
be **neutralized** in [sys/openbsd/init.go](/sys/openbsd/init.go).

Current neutralizations:

| Syscall | What's blocked | Why |
|---------|---------------|-----|
| `ioctl` | `DIOCCLRSTATES`, `DIOCKILLSTATES` | Kills PF state table; drops SSH |
| `chflags`/`fchflags`/`chflagsat` | `UF_IMMUTABLE`, `UF_APPEND`, `SF_IMMUTABLE`, `SF_APPEND` | Can lock tty/pty devices |
| `clock_settime` | `CLOCK_REALTIME` | Time skew causes "no output" reports |
| `mknod`/`mknodat` | `S_IFMT` = `VBAD`; executor fd range; sd0b/sd0c | Kernel assertions; executor interference; disk corruption |
| `sysctl` | `kern.maxclusters`, `kern.maxproc`, `kern.maxfiles`, `kern.maxthread`, `kern.witness` | Resource exhaustion; crashes |
| `setrlimit` | `RLIMIT_DATA` < 1536MB; `RLIMIT_STACK` > 1MB | OOM for executor |
| `mlockall` | `MCL_FUTURE` | OOM |

When adding a new device file, check whether any ioctls can disrupt the
VM.  If so, add neutralization in `init.go` **and** list the blocked
constants in the `.txt` file with an `_ =` directive so extraction still
pulls them:

```syzlang
# Restricted in neutralize(), see init.go.
_ = DIOCCLRSTATES, DIOCKILLSTATES
```

## 7. Choosing What to Describe Next

Prioritize interfaces that are:
1. **Unprivileged** — reachable without `suser()` checks
2. **Complex** — state machines, unions, buffer management, concurrency
3. **Large** — more kernel code = more attack surface
4. **Recently modified** — active code has fresh bugs

To find uncovered syscalls:

```sh
# Kernel syscalls
grep 'STD' $OPENBSD_SRC/sys/kern/syscalls.master | \
    sed 's/.*sys_//;s/(.*//' | sort -u > /tmp/kern.txt

# Already described
grep -h '^[a-z]' sys/openbsd/*.txt | grep '(' | \
    sed 's/\$.*//;s/(.*//' | sort -u > /tmp/desc.txt

comm -23 /tmp/kern.txt /tmp/desc.txt
```

## 8. Device Ioctl File Template

```syzlang
# Copyright YYYY syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

include <sys/types.h>
include <sys/fcntl.h>
include <sys/ioctl.h>
include <sys/device-specific-header.h>

resource fd_devname[fd]

openat$devname(fd const[AT_FDCWD], file ptr[in, string["/dev/devname"]], flags flags[open_flags], mode const[0]) fd_devname

# --- Ioctls ---
ioctl$IOCTL_NAME(fd fd_devname, cmd const[IOCTL_NAME], arg ptr[in, struct_name])

# --- Structs ---
struct_name {
    field0  type0
    field1  type1
}

# --- Flag sets ---
flag_name = CONST1, CONST2, CONST3
```

## 9. Workflow Checklist

The standard workflow is in `docs/syscall_descriptions.md`.  This
checklist adds **OpenBSD-specific** steps (marked with ★):

- [ ] Read the kernel source for the interface (header + implementation)
- [ ] Identify all ioctl commands / syscall variants and their structs
- [ ] ★ Check for privilege requirements (`suser()`, `securelevel`)
- [ ] Write the `.txt` file following § 8 template
- [ ] Run `syz-extract` — fix include/define errors until it succeeds
- [ ] ★ Spot-check `.const` values against the OpenBSD header
- [ ] Run `make descriptions` → `make format` → `go test` (§ 3.3)
- [ ] ★ For complex structs: write `_Static_assert` verification (§ 3.4)
- [ ] ★ Check if any operations need neutralization in `init.go` (§ 6)
- [ ] Commit `.txt` and `.txt.const` together

## 10. Common Extraction Errors (OpenBSD-Specific)

| Error | Likely cause | Fix |
|-------|-------------|-----|
| `unknown type name 'struct mbuf'` | Missing transitive include | Add `include <sys/mbuf.h>` before network headers |
| DRM struct size wrong | `__linux__` guard active | Verify `-U__linux__` is in `openbsd.go` |
| `'SYS_foo' undeclared` | Syscall uses `SYS___foo` prefix | Add to `syscallsQuirks` map in `openbsd.go` |
| `.const` value differs from header | Cross-compilation type mismatch | Verify on real OpenBSD with `_Static_assert` |
| `'FOO' undeclared` | Constant behind `#ifdef` | Check `_KERNEL`, `__BSD_VISIBLE`, or feature guards |

For generic extraction issues (missing include, typos), see
`docs/syscall_descriptions.md` § "Description compilation internals".

## 11. Current Coverage

| File | Interface | Ioctl count |
|------|-----------|-------------|
| `sys.txt` | General syscalls | — (165 syscall variants) |
| `dev_pf.txt` | Packet Filter | 53 |
| `dev_dri.txt` | DRM/GPU | 53 |
| `wscons.txt` | Console/keyboard/display | 69 |
| `dev_bpf.txt` | BPF | 24 |
| `dev_vmm.txt` | VMM hypervisor | 7 |
| `dev_diskmap.txt` | Disk mapper | — |
| `dev_klog.txt` | Kernel log | — |
| `dev_pci.txt` | PCI access | — |
| `dev_speaker.txt` | PC speaker | — |
| `dev_vnd.txt` | Vnode disk | — |
| `socket*.txt` | Sockets (inet, inet6, unix) | — |
| `sysctl.txt` | sysctl | — |
| `kqueue.txt` | kqueue/kevent | — |
| `vnet.txt` | Virtual ethernet | — |
| `ipc.txt` | SysV IPC | — |
| `fs.txt` | Filesystem ops | — |
| `ktrace.txt` | Kernel tracing | — |
| `mm.txt` | Memory management | — |
| `tty.txt` | TTY/PTY | — |

The OpenBSD syscall table has ~224 `STD` entries.  Major gaps: `futex`,
`ptrace`, `mount`/`unmount`, audio, video, routing sockets (`AF_ROUTE`),
signals, threading primitives (`__tfork`, `__thrsleep`, `__thrwakeup`).
