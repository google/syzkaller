# How to reproduce syzkaller crashes

## Using a C reproducer

If the bug was reported by syzbot, you first need to build the kernel used by
the tool. Syzbot provides the necessary information in its report:

```
Hello,

syzbot found the following issue on:

HEAD commit:    ae58226b89ac Add linux-next specific files for 20241118
git tree:       linux-next
console+strace: https://syzkaller.appspot.com/x/log.txt?x=14a67378580000
kernel config:  https://syzkaller.appspot.com/x/.config?x=45719eec4c74e6ba
dashboard link: https://syzkaller.appspot.com/bug?extid=2159cbb522b02847c053
compiler:       Debian clang version 15.0.6, GNU ld (GNU Binutils for Debian) 2.40
syz repro:      https://syzkaller.appspot.com/x/repro.syz?x=137beac0580000
C reproducer:   https://syzkaller.appspot.com/x/repro.c?x=177beac0580000
```

In this case, you would run:
```
$ git checkout ae58226b89ac
$ wget -O '.config' 'https://syzkaller.appspot.com/x/.config?x=45719eec4c74e6ba`
$ make CC=clang LD=ld.lld olddefconfig
$ make CC=clang LD=ld.lld -j$(nproc)
```

You also need a bootable disk image. Syzbot currently uses small Buildroot-based
images that you can either [build locally](/tools/create-buildroot-image.sh) or
[download](https://storage.googleapis.com/syzkaller/images/buildroot_amd64_2024.09.gz).

Download and build the reproducer:
```
$ wget -O 'repro.c' 'https://syzkaller.appspot.com/x/repro.c?x=177beac0580000'
$ gcc repro.c -lpthread -static -o repro
```

Run the VM:
```
$ export DISK_IMAGE='buildroot_amd64_2024.09'
$ qemu-system-x86_64 -m 2G -smp 2,sockets=2,cores=1 -drive file=$DISK_IMAGE,format=raw -net nic,model=e1000 -net user,host=10.0.2.10,hostfwd=tcp::10022-:22 -enable-kvm -nographic -snapshot -machine pc-q35-7.1
```

Run the reproducer:
```
$ scp -P 10022 -o UserKnownHostsFile=/dev/null  -o StrictHostKeyChecking=no -o IdentitiesOnly=yes ./repro root@127.0.0.1:/root/
$ ssh -p 10022 -o UserKnownHostsFile=/dev/null  -o StrictHostKeyChecking=no -o IdentitiesOnly=yes root@127.0.0.1 'chmod +x ./repro && ./repro'
```


## Using a Syz reproducer

Syzkaller always generates a "Syz" reproducer first (in [Syzkaller
DSL](/docs/program_syntax.md)). Afterwards, syzkaller attempts to convert the
Syz reproducer into C code. The process does not always succeed due to the
differences between the `syz-executor` environment and the environment emulated
in the C reproducer. Therefore, in some cases, only the Syz version is
available.

To run a Syz reproducer locally, the required actions are mostly similar to
those in the previous section.

Download and [build](/docs/linux/setup.md#go-and-syzkaller) syzkaller. If you
have Docker installed, the instructions are simpler:
```
$ git clone https://github.com/google/syzkaller.git
$ cd syzkaller
$ ./tools/syz-env make
```

Build the kernel and boot the VM as described in the section above.

Download the reproducer:
```
$ wget -O 'repro.syz' 'https://syzkaller.appspot.com/x/repro.syz?x=137beac0580000'
```

Copy the reproducer and the syzkaller binaries to the test machine:
```
$ export SYZKALLER_PATH="~/syzkaller"
$ scp -P 10022 -o UserKnownHostsFile=/dev/null  -o StrictHostKeyChecking=no -o IdentitiesOnly=yes $SYZKALLER_PATH/bin/linux_amd64/* ./repro.syz root@127.0.0.1:/root/
```

Now you can use the `syz-execprog` tool to actually execute the program.

```
$ ssh -p 10022 -o UserKnownHostsFile=/dev/null  -o StrictHostKeyChecking=no -o IdentitiesOnly=yes root@127.0.0.1 './syz-execprog -enable=all -repeat=0 -procs=6 ./repro.syz'
```

Several useful `syz-execprog` flags:
```
  -procs int
    	number of parallel processes to execute programs (default 1)
  -repeat int
    	repeat execution that many times (0 for infinite loop) (default 1)
  -sandbox string
    	sandbox for fuzzing (none/setuid/namespace) (default "setuid")
  -threaded
    	use threaded mode in executor (default true)
```

If you pass `-threaded=0`, all syscalls will be executed in the same thread.
`-threaded=1` forces execution of each syscall in a separate thread, so that
execution can proceed over blocking syscalls.

Before 2021, `syz-execprog` also supported the following flag:
```
  -collide
    	collide syscalls to provoke data races (default true)
```
`-collide=1` forced second round of execution of syscalls when pairs of syscalls
are executed concurrently.

Starting from the revision
[fd8caa54](https://github.com/google/syzkaller/commit/fd8caa5462e64f37cb9eebd75ffca1737dde447d),
the behavior is controlled [directly in syzlang](/docs/program_syntax.md#async).
If you are running older reproducers, you might still need to set the `-collide=1` flag.


If you are replaying a reproducer program that contains a header along the
following lines:
```
# {Threaded:true Repeat:true RepeatTimes:0 Procs:8 Slowdown:1 Sandbox:none Leak:false NetInjection:true NetDevices:true NetReset:true Cgroups:true BinfmtMisc:true CloseFDs:true KCSAN:false DevlinkPCI:false USB:true VhciInjection:true Wifi:true IEEE802154:true Sysctl:true UseTmpDir:true HandleSegv:true Repro:false Trace:false LegacyOptions:{Collide:false Fault:false FaultCall:0 FaultNth:0}}
```
then you need to adjust `syz-execprog` flags based on the values in the
header. Namely, `Threaded`/`Procs`/`Sandbox` directly relate to
`-threaded`/`-procs`/`-sandbox` flags. If `Repeat` is set to `true`, add
`-repeat=0` flag to `syz-execprog`.

## Using ktest

[ktest](https://evilpiepirate.org/git/ktest.git/tree/README.md) is a collection
of tests for Linux and an infrastructure that simplifies running them locally.

Ktest includes a special `syzbot-repro.ktest` test that automates building the
kernel, booting the VM, fetching syzbot bug report details and running the
reproducer.

**Installation instructions:**
```
$ git clone git://evilpiepirate.org/ktest.git
$ cd ktest
$ export KTEST_PATH=$(pwd)
$ sudo ./root_image init
$ sudo ./root_image create
$ cargo install --path $KTEST_PATH
```

**Instructions to reproduce a syzbot bug:**
```
$ cd ~/linux
$ git checkout <kernel-commit>
$ $KTEST_PATH/build-test-kernel run $KTEST_PATH/tests/syzbot-repro.ktest <bug-id>
```

`<bug-id>` can be taken from syzbot bug reports:

```
dashboard link: https://syzkaller.appspot.com/bug?extid=2159cbb522b02847c053
```

In this case, `bug-id` is `2159cbb522b02847c053`.


## Using downloadable assets

In each report, syzbot shares the exact disk image, kernel image and the vmlinux
file that were used to find it.

See [the corresponding documentation](/docs/syzbot_assets.md) on how you can
use those files to reproduce bugs locally.

## From execution logs

The process of creating reproducer programs for syzkaller bugs is automated, but
it's not perfect. In some cases, the tool cannot narrow down the kernel crash to
a single program.

### Obtaining execution logs
* **A local syzkaller instance** \
Crash logs created in manager `workdir/crashes` dir contain programs executed
just before a crash. In parallel execution mode (when `procs` parameter in
manager config is set to value larger than 1), program that caused the crash
does not necessary immediately precedes it; the guilty program can be somewhere
before.

* **Syzbot** shares execution logs in its reports:
```
console output: https://syzkaller.appspot.com/x/log.txt?x=148914c0580000
```

### Crafting reproducers manually

There are two tools that can help you identify and minimize the program that
causes a crash: `syz-execprog` and `syz-prog2c`. You can build them with `make
execprog` and `make prog2c`, respectively.

`syz-execprog` executes a single syzkaller program or a set of programs in
various modes (once or loop indefinitely; in threaded/collide mode (see below),
with or without coverage collection).

You can start by running all programs in the crash log in a loop to check that
at least one of them indeed crashes kernel:

```
./syz-execprog -executor=./syz-executor -repeat=0 -procs=8 -cover=0 crash-log-file.txt
```
**Note: `syz-execprog` executes programs locally. So you need to copy
`syz-execprog` and `syz-executor` into a VM with the test kernel and run it
there.** See the [Using a Syz reproducer](#Using-a-Syz-reproducer) section.

To identify the single program that causes the crash, you can cut out individual
programs from `crash-log-file.txt` and run `syz-execprog` separately.

Once you have a single program that causes the crash, you can try to minimize it by:
* Removing individual syscalls from the program (you can comment out single lines
with `#` at the beginning of line)
* By removing unnecessary data (e.g. replacing `&(0x7f0000001000)="73656c6600"`
syscall argument with `&(0x7f0000001000)=nil`).
* You can also try to coalesce all mmap calls into a single mmap call that maps
whole required area.

Don't forget to test minimization results with the `syz-execprog` tool.

Now that you have a minimized program, check if the crash still reproduces with
`./syz-execprog -threaded=0 -collide=0` flags. If not, then you will need to do
some additional work later.

Now, run the `syz-prog2c` tool on the program. It will give you an executable C
source code. If the crash reproduces with `-threaded/collide=0` flags, then this C
program should cause the crash as well.

If the crash is not reproducible with `-threaded/collide=0` flags, then you need
this last step. You can think of threaded mode as if each syscall is
executed in its own thread. To model such execution mode, move individual
syscalls into separate threads. You can see an example here:
https://groups.google.com/d/msg/syzkaller/fHZ42YrQM-Y/Z4Xf-BbUDgAJ.

This process is automated to some degree in the `syz-repro` utility. You need to
give it your manager config and a crash report file. And you can refer to the
[example config file](/pkg/mgrconfig/testdata/qemu.cfg).
```
./syz-repro -config my.cfg crash-qemu-1-1455745459265726910
```
It will try to find the offending program and minimize it. But since there are
lots of factors that can affect reproducibility, it does not always work.
