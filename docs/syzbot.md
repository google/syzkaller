# syzbot

`syzbot` system continuously fuzzes main Linux kernel branches and automatically
reports all found bugs. Direct all questions to syzkaller@googlegroups.com.

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

You can communicate with `syzbot` by replying to its emails.
The commands are:

- to attach a fixing commit to the bug:
```
#syz fix: exact-commit-title
````
- to mark the bug as a duplicate of another `syzbot` bug:
```
#syz dup: exact-subject-of-another-report
```
- to mark the bug as a one-off invalid report (e.g. induced by a previous memory corruption):
```
#syz invalid
```
Note: if the crash happens again, it will cause creation of a new bug report.

Note: all commands must start from beginning of the line.

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

## Crash does not reproduce?

Sometimes the provided reproducers do not work. Most likely it is related to the
fact that you have slightly different setup than `syzbot`. `syzbot` has obtained
the provided crash report on the provided reproducer on a freshly-booted
machine, so the reproducer worked for it somehow.

If the reproducer exits quickly, try to run it several times, or in a loop.
There can be some races involved.

Exact compiler used by `syzbot` can be found [here](https://storage.googleapis.com/syzkaller/gcc-7.tar.gz) (245MB).

A qemu-suitable Debian/wheezy image can be found [here](https://storage.googleapis.com/syzkaller/wheezy.img) (1GB, compression somehow breaks it), root ssh key for it is [here](https://storage.googleapis.com/syzkaller/wheezy.img.key).

## No reproducer at all?

Reproducers are best-effort. `syzbot` always tries to create reproducers, and
once it has one it adds it to the bug. If there is no reproducer referenced in a
bug, a reproducer does not exist. There are multiple reasons why `syzbot` can
fail to create a reproducer: some crashes are caused by subtle races and are
very hard to reproduce in general; some crashes are caused by global accumulated
state in kernel (e.g. lockdep reports); some crashes are caused by
non-reproducible coincidences (e.g. an integer `0x12345` happened to reference an
existing IPC object) and there is long tail of other reasons.

## Is syzbot code available?

Yes, it is [here](https://github.com/google/syzkaller/tree/master/dashboard/app).
