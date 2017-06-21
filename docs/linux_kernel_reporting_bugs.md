# Reporting Linux kernel bugs

Before reporting a bug make sure nobody else already reported it. The easiest way to do this is to search through the [syzkaller mailing list](https://groups.google.com/forum/#!forum/syzkaller) for key frames present in the kernel stack traces.

Please report found bugs to the Linux kernel maintainers.
To find out the list of maintainers responsible for a particular kernel subsystem, use the [get_maintainer.pl](https://github.com/torvalds/linux/blob/master/scripts/get_maintainer.pl) script: `./scripts/get_maintainer.pl -f guilty_file.c`.
Please also add `syzkaller@googlegroups.com` to the CC list.

Bugs without reproducers are way less likely to be triaged and fixed.
If the bug is reproducible, include the reproducer (C source if possible, otherwise a syzkaller program) and the `.config` you used for your kernel.
If the reprocucer is available only in the form of a syzkaller program, please link [the instructions on how to execute them](executing_syzkaller_programs.md) in your report.
Check that the reproducer works if you run it manually.

Make sure to also mention the exact kernel branch and revision.

Many kernel mailing lists reject HTML formatted messages, so use the plain text mode when sending the report.

If you believe that a found bug poses potential security threat, consider reporting it directly to `security@kernel.org`.
