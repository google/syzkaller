## Reproduce a bug with syzbot's downloadable assets

As a part of every bug report, syzbot shares downloadable assets -- that is,
disk images and kernel binaries on which the bug was originally found.

This document serves as a guide on how to use those assets to reproce such bugs
locally.

### A sample report

To be more specific, let's take this syzbot report: [[syzbot] [hfs?] kernel BUG
in hfsplus_bnode_put](https://lore.kernel.org/all/000000000000efee7905fe4c9a46@google.com/).

```
syzbot has found a reproducer for the following issue on:

HEAD commit:    40f71e7cd3c6 Merge tag 'net-6.4-rc7' of git://git.kernel.o..
git tree:       upstream
console+strace: https://syzkaller.appspot.com/x/log.txt?x=10482ae3280000
kernel config:  https://syzkaller.appspot.com/x/.config?x=7ff8f87c7ab0e04e
dashboard link: https://syzkaller.appspot.com/bug?extid=005d2a9ecd9fbf525f6a
compiler:       Debian clang version 15.0.7, GNU ld (GNU Binutils for Debian) 2.35.2
syz repro:      https://syzkaller.appspot.com/x/repro.syz?x=142e7287280000
C reproducer:   https://syzkaller.appspot.com/x/repro.c?x=13fd185b280000

Downloadable assets:
disk image: https://storage.googleapis.com/syzbot-assets/073eea957569/disk-40f71e7c.raw.xz
vmlinux: https://storage.googleapis.com/syzbot-assets/c8a97aaa4cdc/vmlinux-40f71e7c.xz
kernel image: https://storage.googleapis.com/syzbot-assets/f536015eacbd/bzImage-40f71e7c.xz
mounted in repro: https://storage.googleapis.com/syzbot-assets/b5f1764cd64d/mount_0.gz
```

There are 4 linked assets:
* The bootable VM disk image on which the bug was found: `https://storage.googleapis.com/syzbot-assets/073eea957569/disk-40f71e7c.raw.xz`
  * **The image is suitable both for GCE and for qemu**.
* The `vmlinux` file that can be used e.g. for report symbolization or for `gdb`-based debugging: `https://storage.googleapis.com/syzbot-assets/c8a97aaa4cdc/vmlinux-40f71e7c.xz`
* The separate `bzImage` file (it is already included in the disk image): `https://storage.googleapis.com/syzbot-assets/f536015eacbd/bzImage-40f71e7c.xz`
* The filesystem image that is mounted in the reproducer: `https://storage.googleapis.com/syzbot-assets/b5f1764cd64d/mount_0.gz`

All these links are also reachable from the web dashboard.

#### Run a C reproducer

Boot a VM:
```
$ wget 'https://storage.googleapis.com/syzbot-assets/073eea957569/disk-40f71e7c.raw.xz'
$ unxz disk-40f71e7c.raw.xz
$ qemu-system-x86_64 -m 2G -smp 2,sockets=2,cores=1 -drive file=./disk-40f71e7c.raw,format=raw -net nic,model=e1000 -net user,host=10.0.2.10,hostfwd=tcp::10022-:22 -enable-kvm -nographic -snapshot -machine pc-q35-7.1
```

Build and run the C reproducer:
```
$ wget -O 'repro.c' 'https://syzkaller.appspot.com/x/repro.c?x=13fd185b280000'
$ gcc repro.c -lpthread -static -o repro
$ scp -P 10022 -o UserKnownHostsFile=/dev/null  -o StrictHostKeyChecking=no -o IdentitiesOnly=yes ./repro root@127.0.0.1:/root/
$ ssh -p 10022 -o UserKnownHostsFile=/dev/null  -o StrictHostKeyChecking=no -o IdentitiesOnly=yes root@127.0.0.1 'chmod +x ./repro && ./repro'
```

Wait a minute and notice a crash report in the qemu's serial output:

```
[   91.956238][   T81] ------------[ cut here ]------------
[   91.957508][   T81] kernel BUG at fs/hfsplus/bnode.c:618!
[   91.958645][   T81] invalid opcode: 0000 [#1] PREEMPT SMP KASAN
[   91.959861][   T81] CPU: 0 PID: 81 Comm: kworker/u5:3 Not tainted 6.4.0-rc6-syzkaller-00195-g40f71e7cd3c6 #0
```

#### Run a syz reproducer directly

For some bugs, there's either no C reproducer or it's not reliable enough. In
that case, `syz` reproducers might be useful.

You'll need to [check out and build](/docs/linux/setup.md#go-and-syzkaller)
syzkaller first. The fastest way to do it is as follows (assuming Docker is
installed and configured on your machine):

```
$ git clone https://github.com/google/syzkaller.git
$ cd syzkaller
$ ./tools/syz-env make
```

Then boot a VM exactly like in the previous section.

Download and run the syz reproducer:

```
$ wget -O 'repro.syz' 'https://syzkaller.appspot.com/x/repro.syz?x=142e7287280000'
$ scp -P 10022 -o UserKnownHostsFile=/dev/null  -o StrictHostKeyChecking=no -o IdentitiesOnly=yes ./bin/linux_amd64/* ./repro.syz root@127.0.0.1:/root/
$ ssh -p 10022 -o UserKnownHostsFile=/dev/null  -o StrictHostKeyChecking=no -o IdentitiesOnly=yes root@127.0.0.1 './syz-execprog -enable=all -repeat=0 -procs=6 ./repro.syz'
```

In some time, you'll see the same bug report in the VM's serial output.

The commands above execute the `./syz-execprog -enable=all -repeat=0 -procs=6 ./repro.syz`
command inside the VM. For more details see [this document](/docs/executing_syzkaller_programs.md).

#### Use the `tools/syz-crush` tool

The `syz-crush` automatizes the steps above: it sets up and boots a pool of VMs
and runs the given `C` or `syz` reproducer in them.

First, download the disk image and reproducers (see instructions above).

Then, go to the syzkaller checkout and build the `syz-crush` tool:
```
$ make crush
```

Prepare a config file (let it be `config.json`):

```
{
    "name": "test",
    "http": "0.0.0.0:0",
    "target": "linux/amd64",
    "image": "/tmp/disk-40f71e7c.raw",
    "syzkaller": "/tmp/syzkaller",
    "workdir": "/tmp/syzkaller/workdir",
    "type": "qemu",
    "procs": 6,
    "vm": {
      "count": 5,
      "cmdline": "root=/dev/sda1",
      "cpu": 2,
      "mem": 2048,
      "qemu_args": "-machine pc-q35-7.1 -enable-kvm"
    }
}
```

You need to replace `/tmp/syzkaller` with the location of your syzkaller
checkout and `/tmp/disk-40f71e7c.raw` with the location of the bootable disk
image.

Run the tool:
```
$ mkdir workdir
$ ./bin/syz-crush -config config.json repro.syz
```


### Problems

#### The bug doesn't reproduce

If the `C` reproder did not work, try to run the `syz` reproducer.

If there's still no success, it might be that relatively rare case when the
execution environment becomes important. Syzbot fuzzes kernels on GCE VMs, which
might have a different instruction set / execution speed than locally run qemu
VMs. These changes might be critical for the generated reproducer.

There's unfortunately no universal solution.

Note that you can always ask syzbot to
[apply your git patch and re-run the reproducer](/docs/syzbot.md#testing-patches).
It will be run in the same GCE environment where the bug was originally found.

See also [this document](/docs/syzbot.md#crash-does-not-reproduce).

#### Assets are not downloadable

The downloadable assets are not stored infinitely. Syzbot keeps them until the
bug is fixed or marked as invalid + 30 days after that.

So if you cannot download the assets using the links from the email, this might
be a sign that the bug is actually no longer worth looking at.

#### Qemu doesn't boot

A [recent qemu problem](https://lore.kernel.org/qemu-devel/da39abab9785aea2a2e7652ed6403b6268aeb31f.camel@linux.ibm.com/)
may prevent it from booting large kernel images. Add `-machine pc-q35-7.1` to
the qemu args to make it work.
