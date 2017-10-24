# syzbot

`syzbot` system continuously fuzzes main Linux kernel branches and automatically
reports all found bugs. Direct all questions to syzkaller@googlegroups.com.

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

## No reproducer at all?

Reproducers are best-effort. `syzbot` always tries to create reproducers, and
once it has one it adds it to the bug. If there is no reproducer referenced in a
bug, a reproducer does not exist. There are multiple reasons why `syzbot` can
fail to create a reproducer: some crashes are caused by subtle races and are
very hard to reproduce in general; some crashes are caused by global accumulated
state in kernel (e.g. lockdep reports); some crashes are caused by
non-reproducible coincidences (e.g. an integer `0x12345` happened to reference an
existing IPC object) and there is long tail of other reasons.
