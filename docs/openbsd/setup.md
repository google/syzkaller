# Setup

Instructions for fuzzing an `amd64` OpenBSD kernel from either an OpenBSD `-current` host (via `vmd`) or an `amd64` Linux host (via QEMU or GCE).

## Linux Host Setup

On an `amd64` Linux host, you can cross-compile OpenBSD userspace binaries (`syz-executor`, C reproducers) and build OpenBSD `amd64` kernels inside an isolated QEMU VM without needing a separate OpenBSD machine.

Prerequisites on Debian/Ubuntu: `clang`, `lld`, `llvm`, `cpp`, `qemu-system-x86`, `openssh-client`, `expect`, `curl`, and `/dev/kvm` access.

1. Prepare an OpenBSD artifact bundle (`userspace/{image,key,key.pub}`, keyless QEMU `builder.raw`, and userspace `sysroot/`) from official OpenBSD snapshots:

   ```sh
   $ ./tools/create-openbsd-image.sh -o ~/openbsd-env
   ```

   By default, this downloads the snapshot once, extracts `sysroot/`, and builds both the minimal target `userspace/image` and the toolchain-equipped `builder.raw` in parallel. Pass `-U`, `-B`, or `-S` to skip building `userspace/`, `builder.raw`, or `sysroot/` respectively (see `-h` for sizing and `OPENBSD_CACHE_DIR` options).

2. Build host binaries (`syz-manager`, `syz-repro`, etc.) and cross-compile OpenBSD target binaries (`syz-execprog`, `syz-executor`) using the extracted sysroot (`SOURCEDIR_OPENBSD` or `SOURCEDIR`):

   ```sh
   $ export SOURCEDIR_OPENBSD=~/openbsd-env/sysroot
   $ make host target TARGETOS=openbsd TARGETARCH=amd64
   ```

3. Build a `SYZKALLER` OpenBSD kernel inside an isolated ephemeral QEMU VM using `builder.raw`:

   ```sh
   $ git clone --depth=1 https://github.com/openbsd/src.git ~/openbsd-src
   $ make syz-build
   $ mkdir -p ~/openbsd-build && cd ~/openbsd-build
   $ /path/to/syzkaller/bin/syz-build \
       -os openbsd -arch amd64 -vm qemu \
       -kernel_src ~/openbsd-src \
       -userspace ~/openbsd-env/userspace \
       -builder_image ~/openbsd-env/builder.raw \
       -trace
   ```

   This produces `~/openbsd-build/image` (with the new kernel installed as `/bsd`), `~/openbsd-build/key` (if present in `userspace`), `~/openbsd-build/kernel.config` (when `-config` is omitted), and `~/openbsd-build/obj/bsd.gdb` (used by `syz-manager` via `"kernel_obj": "~/openbsd-build/obj"` and `"kernel_src": "~/openbsd-src"`).

4. For `syz-ci` on a Linux host, sync `~/openbsd-env/` to the host (e.g. `rsync -azS --delete ~/openbsd-env/ syz-ci:/syzkaller/openbsd/`) and set `"userspace": "/syzkaller/openbsd/userspace"` and `"kernel_builder_image": "/syzkaller/openbsd/builder.raw"` in the manager config. Requirements for the `syz-ci` host itself:

   - `clang`, `lld`, `llvm`, `cpp` and `qemu-system-x86` must be installed, and the `syz-ci` process must have access to `/dev/kvm` (the kernel is built inside a local KVM-accelerated QEMU VM requiring 8 GiB of available RAM and up to 12 vCPUs; `syz-ci` runs one kernel build at a time).
   - `SOURCEDIR_OPENBSD=/syzkaller/openbsd/sysroot` must be set in the environment of the `syz-ci` process (e.g. in its systemd unit), otherwise `syz-ci` refuses to start since it cannot build `syz-executor` for the target.
   - Infrastructure failures of the build VM (QEMU/KVM/SSH problems, a builder image without a compiler, disk setup, packaging of the results) are classified as `build.InfraError` and are not reported to the dashboard as kernel build errors; only failures of the kernel config/build steps inside the VM are.

   **Warning:** `builder.raw` has an empty root password and must only be used as a local QEMU `kernel_builder_image` (where the VM has no network access). Never use it as a fuzzing `userspace/image` on GCE or any other network-reachable VM.

## OpenBSD Host Setup

Variables used throughout the OpenBSD host instructions:

- `$KERNEL` - Custom built kernel, see [Compile Kernel](#compile-kernel).
              Defaults to `/sys/arch/amd64/compile/SYZKALLER/obj/bsd` if the
              instructions are honored.
- `$SSHKEY` - SSH key ***without a passphrase*** used to connect to the VMs,
              it's advised to use a dedicated key.
- `$USER`   - The name of the user intended to run syzkaller.
- `$VMIMG`  - VM disk image.
- `$VMID`   - The numeric ID of last started VM.

## Install syzkaller

1. Install dependencies:

   ```sh
   # pkg_add git gmake go
   ```

   In order for reproducers to work, GCC from ports is also required:

   ```sh
   # pkg_add gcc
   ```

2. Clone repository:

   ```sh
   $ git clone https://github.com/google/syzkaller
   $ cd syzkaller
   $ gmake all
   ```

## Compile Kernel

A `GENERIC` kernel must be compiled with
[kcov(4)](https://man.openbsd.org/kcov.4)
enabled:

```sh
$ cd /sys/arch/amd64
$ cat <<EOF >conf/SYZKALLER
include "arch/amd64/conf/GENERIC"
pseudo-device kcov 1
EOF
$ cp -R compile/GENERIC compile/SYZKALLER
$ make -C compile/SYZKALLER obj
$ make -C compile/SYZKALLER config
$ make -C compile/SYZKALLER
```

## Create VM

1. [vmd(8)](https://man.openbsd.org/vmd.8)
   must be configured to allow non-root users to create VMs since it removes the
   need to run syzkaller as root:

   ```sh
   $ cat /etc/vm.conf
   vm "syzkaller" {
     disable
     disk "/dev/null"
     local interface
     owner $USER
     allow instance { boot, disk, memory }
   }
   ```

2. Create disk image:

   ```sh
   $ vmctl create -s 4G "qcow2:$VMIMG"
   ```

3. Install VM:

   ```sh
   $ vmctl start -c -t syzkaller -b /bsd.rd -d "$VMIMG" syzkaller-1
   ```

   Answers to questions that deviates from the defaults:

   ```
   Password for root account? ******
   Allow root ssh login? yes
   ```

4. Restart the newly created VM and copy the SSH-key:

   ```sh
   $ vmctl stop -w syzkaller-1
   $ vmctl start -c -t syzkaller -d "$VMIMG" syzkaller-1
   $ ssh "root@100.64.${VMID}.3" 'cat >~/.ssh/authorized_keys' <$SSHKEY.pub
   ```

5. Optionally, library ASLR can be disabled in order to improve boot time:

   ```sh
   $ ssh "root@100.64.${VMID}.3" 'echo library_aslr=NO >>/etc/rc.conf.local'
   ```

6. Finally, stop the VM:

   ```sh
   $ vmctl stop -w syzkaller-1
   ```

## Configure and run syzkaller

```sh
$ pwd
~/go/src/github.com/google/syzkaller
$ cat openbsd.cfg
{
  "name": "openbsd",
  "target": "openbsd/amd64",
  "http": ":10000",
  "workdir": "$HOME/go/src/github.com/google/syzkaller/workdir",
  "kernel_obj": "/sys/arch/amd64/compile/SYZKALLER/obj",
  "kernel_src": "/",
  "syzkaller": "$HOME/go/src/github.com/google/syzkaller",
  "image": "$VMIMG",
  "sshkey": "$SSHKEY",
  "sandbox": "none",
  "procs": 2,
  "type": "vmm",
  "vm": {
    "count": 4,
    "mem": 512,
    "kernel": "$KERNEL",
    "template": "syzkaller"
  }
}
$ ./bin/syz-manager -config openbsd.cfg
```
