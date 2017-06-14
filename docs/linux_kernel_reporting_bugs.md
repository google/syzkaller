## Reporting Linux kernel bugs

Before reporting a bug make sure nobody else already reported it. The easiest way to do this is to search through the [syzkaller mailing list](https://groups.google.com/forum/#!forum/syzkaller) for key frames present in the kernel stack traces.

Please report found bugs to the Linux kernel maintainers.
To find out the list of maintainers responsible for a particular kernel subsystem, use the [get_maintainer.pl](https://github.com/torvalds/linux/blob/master/scripts/get_maintainer.pl) script: `./scripts/get_maintainer.pl -f guilty_file.c`.
Please also add `syzkaller@googlegroups.com` to the CC list.

If the bug is reproducible, include the reproducer (C source if possible, otherwise a syzkaller program) and `.config` you used for your kernel.
Bugs without reproducers are way less likely to be triaged and fixed.
Make sure to also mention the exact kernel branch and revision.

Many kernel mailing lists reject HTML formatted messages, so use the plain text mode when sending the report.

If you believe that a found bug poses potential security threat, consider reporting it directly to `security@kernel.org`.
