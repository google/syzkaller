# syzbot

`syzbot` system continuously fuzzes main Linux kernel branches and automatically
reports found bugs to kernel mailing lists.
[syzbot dashboard](https://syzkaller.appspot.com) shows current statuses of
bugs. All `syzbot`-reported bugs are also CCed to
[syzkaller-bugs mailing list](https://groups.google.com/forum/#!forum/syzkaller-bugs).
Direct all questions to `syzkaller@googlegroups.com`.

## Bug status tracking

`syzbot` needs to know when a bug is fixed in order to (1) verify that it is
in fact fixed and (2) be able to report other similarly-looking crashes
(while a bug is considered open all similarly-looking crashes are merged into
the existing bug). To understand when a bug is fixed `syzbot` needs to know
what commit fixes the bug; once `syzbot` knows the commit it will track when
the commit reaches all kernel builds on all tracked branches. Only when the
commit reaches all builds, the bug is considered closed (new similarly-looking
crashes create a new bug).

## Communication with syzbot

If you fix a bug reported by `syzbot`, please add the provided `Reported-by`
tag to the commit. You can also communicate with `syzbot` by replying to its
emails. The commands are:

- to attach a fixing commit to the bug (if you forgot to add `Reported-by` tag):
```
#syz fix: exact-commit-title
````
It's enough that the commit is merged into any tree or you are reasonably sure
about its final title, in particular, you don't need to wait for the commit to
be merged into upstream tree. `syzbot` only needs to know the title by which
it will appear in tested trees. In case of an error or a title change, you can
override the commit simply by sending another `#syz fix` command.
- to mark the bug as a duplicate of another `syzbot` bug:
```
#syz dup: exact-subject-of-another-report
```
- to undo a previous dup command and turn it into an independent bug again:
```
#syz undup
```
- to mark the bug as a one-off invalid report (e.g. induced by a previous memory corruption):
```
#syz invalid
```
**Note**: if the crash happens again, it will cause creation of a new bug report.

**Note**: all commands must start from beginning of the line.

**Note**: please keep `syzkaller-bugs@googlegroups.com` mailing list in CC.
It serves as a history of what happened with each bug report.

## Testing patches

`syzbot` can test patches for bugs *with reproducers*. This can be used for
testing of fix patches, or just for debugging (i.e. adding additional checks to
code and testing with them), or to check if the bug still happens. To test on
a particular git tree and branch reply with:
```
#syz test: git://repo/address.git branch
```
or alternatively, to test on exact commit reply with:
```
#syz test: git://repo/address.git commit-hash
```
If you also provide a patch with the email, `syzbot` will apply it on top of the
tree before testing. The patch can be provided either inline in email text or as
a text attachment (which is more reliable if your email client messes with
whitespaces).

If you don't provide a patch, `syzbot` will test the tree as is.
This is useful if this is your own tree which already contains the patch,
or to check if the bug is already fixed by some recent commit.

After sending an email you should get a reply email with results within an hour.

Note: you may send the request only to `syzbot` email address, as patches sent
to some mailing lists (e.g. netdev, netfilter-devel) will trigger patchwork.

## syzkaller reproducers

`syzbot` aims at providing stand-alone C reproducers for all reported bugs.
However, sometimes it can't extract a reproducer at all, or can only extract a
syzkaller reproducer. syzkaller reproducers are programs in a special syzkaller
notation and they can be executed on the target system with a little bit more
effort. See [this](https://github.com/google/syzkaller/blob/master/docs/executing_syzkaller_programs.md)
for instructions.

A syskaller program can also give you an idea as to what syscalls with what
arguments were executed (note that some calls can actually be executed in
parallel).

A syzkaller program can be converted to an almost equivalent C source using `syz-prog2c` utility. `syz-prog2c` has lots of flags in common with [syz-execprog](https://github.com/google/syzkaller/blob/master/docs/executing_syzkaller_programs.md), e.g. `-threaded`/`-collide` which control if the syscalls are executed sequentially or in parallel. An example invocation:

```
syz-prog2c -prog repro.syz.txt -threaded -collide -repeat -procs=8 -sandbox=namespace -tun -tmpdir -waitrepeat
```

However, note that if `syzbot` did not provide a C reproducer, it wasn't able to trigger the bug using the C program (though, it can be just because the bug is triggered by a subtle race condition).

## Crash does not reproduce?

If the provided reproducer does not work for you, most likely it is related to the
fact that you have slightly different setup than `syzbot`. `syzbot` has obtained
the provided crash report on the provided reproducer on a freshly-booted
machine, so the reproducer worked for it somehow.

`syzbot` uses GCE VMs for testing, but *usually* it is not important.

If the reproducer exits quickly, try to run it several times, or in a loop.
There can be some races involved.

Exact compilers used by `syzbot` can be found here:
- [gcc 7.1.1 20170620](https://storage.googleapis.com/syzkaller/gcc-7.tar.gz) (245MB)
- [gcc 8.0.1 20180301](https://storage.googleapis.com/syzkaller/gcc-8.0.1-20180301.tar.gz) (286MB)
- [gcc 8.0.1 20180412](https://storage.googleapis.com/syzkaller/gcc-8.0.1-20180412.tar.gz) (33MB)
- [clang 7.0.0 (trunk 329060)](https://storage.googleapis.com/syzkaller/clang-kmsan-329060.tar.gz) (44MB)
- [clang 7.0.0 (trunk 334104)](https://storage.googleapis.com/syzkaller/clang-kmsan-334104.tar.gz) (44MB)

A qemu-suitable Debian/wheezy image can be found [here](https://storage.googleapis.com/syzkaller/wheezy.img) (1GB, compression somehow breaks it), root ssh key for it is [here](https://storage.googleapis.com/syzkaller/wheezy.img.key).
A reference `qemu` command line to run it is as follows:
```
qemu-system-x86_64 -hda wheezy.img -net user,hostfwd=tcp::10022-:22 \
    -net nic -nographic -enable-kvm -m 2G -smp 4 -cpu host \
    -kernel arch/x86/boot/bzImage \
    -append "root=/dev/sda console=ttyS0 earlyprintk=serial rodata=n \
      oops=panic panic_on_warn=1 panic=86400 kvm-intel.nested=1"
```
And then you can ssh into it using:
```
ssh -p 10022 -i wheezy.id_rsa root@localhost
```

## No reproducer at all?

Reproducers are best-effort. `syzbot` always tries to create reproducers, and
once it has one it adds it to the bug. If there is no reproducer referenced in a
bug, a reproducer does not exist. There are multiple reasons why `syzbot` can
fail to create a reproducer: some crashes are caused by subtle races and are
very hard to reproduce in general; some crashes are caused by global accumulated
state in kernel (e.g. lockdep reports); some crashes are caused by
non-reproducible coincidences (e.g. an integer `0x12345` happened to reference an
existing IPC object) and there is long tail of other reasons.

## Moderation queue

Bugs with reproducers are automatically reported to kernel mailing lists.
Bugs without reproducers are first staged in moderation queue to filter out
invalid, unactionable or duplicate reports. Staged bugs are shown on dashboard
in [moderation](https://syzkaller.appspot.com/#upstream-moderation2) section
and mailed to
[syzkaller-upstream-moderation](https://groups.google.com/forum/#!forum/syzkaller-upstream-moderation)
mailing list. Staged bugs accept all commands supported for reported bugs
(`fix`, `dup`, `invalid`) with a restriction that reported and staged bugs
can't be `dup`-ed onto each other in any direction. Additionally, staged bugs
accept upstream command:
```
#syz upstream
```
which sends the bug to kernel mailing lists.

## KMSAN bugs

`KMSAN` is a dynamic, compiler-based tool (similar to `KASAN`) that detects
uses of uninitialized values. As compared to (now deleted) `KMEMCHECK` which
simply detected loads of non-stored-to memory, `KMSAN` tracks precise
propagation of uninitialized values through memory and registers and only flags
actual eventual uses of uninitialized values. For example, `KMSAN` will detect
a branch on or a `copy_to_user()` of values that transitively come from
uninitialized memory created by heap/stack allocations. This ensures
/theoretical/ absense of both false positives and false negatives (with some
implementation limitations of course).

`KMSAN` is not upstream yet, though, we want to upstream it later. For now,
it lives in [github.com/google/kmsan](https://github.com/google/kmsan) and is
based on a reasonably fresh upstream tree. As the result, any patch testing
requests for `KMSAN` bugs need to go to `KMSAN` tree
(`https://github.com/google/kmsan.git` repo, `master` branch). Also note that
`KMSAN` requires `clang` compiler.

Report explanation. The first call trace points to the `use` of the uninit value
(which is usually a branching or copying it to userspace). Then there are 0 or
more "Uninit was stored to memory at:" stacks which denote how the unint value
travelled through memory. Finally there is a "Uninit was created at:"
section which points either to a heap allocation or a stack variable which
is the original source of uninitialized-ness.

## No custom patches

While `syzbot` can test patches that fix bugs, it does not support applying
custom patches during fuzzing. It always tests vanilla unmodified git trees.
There are several reasons for this:

- custom patches may not apply tomorrow
- custom patches may not apply to all of the tested git trees
- it's hard to communicate exact state of the code with bug reports (not just hash anymore)
- line numbers won't match in reports (which always brings suspecion as to the quality of reports)
- custom patches can also introduce bugs, and even if they don't a developer may (rightfully)
  question validity of and may not want to spend time on reports obtained
  with a number of out-of-tree patches
- order of patch application generatelly matters, and at some point patches
  need to be removed, there is nobody to manage this

We've experimented with application of custom patches in the past and it lead
to unrecoverable mess. If you want `syzbot` to pick up patches sooner,
ask tree maintainers for priority handling.

## Kernel configs

Kernel configs, sysctls and command line arguments that `syzbot` uses are available in [/dashboard/config](/dashboard/config).

## Is syzbot code available?

Yes, it is [here](https://github.com/google/syzkaller/tree/master/dashboard/app).
