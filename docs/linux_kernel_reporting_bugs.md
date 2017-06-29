# Reporting Linux kernel bugs

Before reporting a bug make sure nobody else already reported it. The easiest way to do this is to search through the [syzkaller mailing list](https://groups.google.com/forum/#!forum/syzkaller) for key frames present in the kernel stack traces.

Please report found bugs to the Linux kernel maintainers.
To find out the list of maintainers responsible for a particular kernel subsystem, use the [get_maintainer.pl](https://github.com/torvalds/linux/blob/master/scripts/get_maintainer.pl) script: `./scripts/get_maintainer.pl -f guilty_file.c`. Please add `syzkaller@googlegroups.com` to the CC list.
Make sure to mention the exact kernel branch and revision where the bug occured.
Many kernel mailing lists reject HTML formatted messages, so use the plain text mode when sending the report.

Bugs without reproducers are way less likely to be triaged and fixed.
If the bug is reproducible, include the reproducer (C source if possible, otherwise a syzkaller program) and the `.config` you used for your kernel.
If the reprocucer is available only in the form of a syzkaller program, please link [the instructions on how to execute them](executing_syzkaller_programs.md) in your report.
Check that the reproducer works if you run it manually.
Syzkaller tries to simplify the reproducer, but the result might not be ideal.
You can try to simplify or annotate the reproducer manually, that greatly helps kernel developers to figure out why the bug occurs.

If you want to get extra credit, you can try to undestand the bug and develop a fix yourself.
If you can't figure out the right fix, but have some understanding of the bug, please add your thoughts and conclusions to the report, that will save some time for kernel developers.

## Reporting security bugs

If you believe that a found bug poses potential security threat, consider following the instructions below.
Note, that these instructions are a work-in-progress and based on my current undestanding of the disclosure proccess.

The three main mailing lists for reporting and disclosing Linux kernel security issues are `security@kernel.org`, `linux-distros@vs.openwall.org` and `oss-security@lists.openwall.com`.
The guidelines for these lists can be found here:

1. `security@kernel.org` - https://www.kernel.org/doc/html/latest/admin-guide/security-bugs.html
2. `linux-distros@vs.openwall.org` - http://oss-security.openwall.org/wiki/mailing-lists/distros
3. `oss-security@lists.openwall.com` - http://oss-security.openwall.org/wiki/mailing-lists/oss-security

### Reporting minor security bugs

To report minor security bugs (such as local DOS or local info leak):

1. Report the bug publicly to kernel developers as described above and wait until a fix is committed. Alternatively, you can develop and send a fix yourself.
2. Request a CVE from MITRE through [the web form](https://cveform.mitre.org/). Describe the bug details and add a link to the fix (from `patchwork.kernel.org`, `git.kernel.org` or `github.com`) in the request.
3. Once a CVE is assigned, send the bug details, the CVE number and a link to the fix to `oss-security@lists.openwall.com`.

### Reporting major security bugs

To report major security bugs (such as LPE, remote DOS, remote info leak or RCE):

1. Understand the bug and develop a patch with a fix if possible. Optionally develop a proof-of-concept exploit.
2. Notify `security@kernel.org`:
    * Describe vulnerability details, include the proposed patch and the exploit.
    * Ask for 7 days of embargo (actually 7 days + whatever time it takes to develop a proper patch).
    * Work on the patch together with the `security@kernel.org` members.
3. Notify `linux-distros@vs.openwall.org`:
    * Describe vulnerability details, include the proposed patch and the exploit.
    * Ask them to assign a CVE number.
    * Ask for 7 days of embargo.
4. Wait 7 days for linux distros to apply the patch.
5. Send the fix upstream:
    * Mention the CVE number in the commit message.
    * Mention syzkaller in the commit message.
6. Wait 3 days for the patch to be committed to mainline and backported to stable kernels.
7. Ask `linux-distros@vs.openwall.org` to make the CVE description public.
8. Notify `oss-security@lists.openwall.com`:
    * Describe vulnerability details, include a link to the committed patch.
9. Wait 1-3 days for people to update their kernels.
10. Publish the exploit on `oss-security@lists.openwall.com`.

A good example of an LPE announcement on `oss-security@lists.openwall.com` can be found [here](http://seclists.org/oss-sec/2016/q4/607).
