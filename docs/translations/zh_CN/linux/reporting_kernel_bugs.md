> [!WARNING]
>
> **请注意，这是社区驱动的官方 syzkaller 文档翻译。当前文档的最新版本（英文版）可在 [docs/linux/reporting_kernel_bugs.md](/docs/linux/reporting_kernel_bugs.md) 中找到。**

# 报告 Linux 内核错误

在报告错误之前，请确保没有其他人已经重复报告过它. 最简单的方法是在 [syzkaller 邮件列表](https://groups.google.com/forum/#!forum/syzkaller), [syzkaller-bugs 邮件列表](https://groups.google.com/forum/#!forum/syzkaller-bugs) 和 [syzbot dashboard](https://syzkaller.appspot.com/upstream) 中搜索内核栈跟踪中存在的关键栈帧。

请将发现的错误报告给 Linux 内核维护人员。要找出负责特定内核子系统的维护者列表，请使用 [get_maintainer.pl](https://github.com/torvalds/linux/blob/master/scripts/get_maintainer.pl) 脚本：`./scripts/get_maintainer.pl -f guilty_file.c`。请将 `syzkaller@googlegroups.com` 添加到抄送列表。确保在报告中明确指出发生错误的确切内核分支和版本号。因为许多内核邮件列表不接受 HTML 格式的邮件，所以在发送报告时请使用纯文本模式。

在提交报告前需要字斟句酌。如今，Linux 维护者被日益增加的 bug 报告所淹没，因此仅仅增加报告的提交量无助于解决内核错误本身。因此，您的报告越详细越具有可操作性，解决它的可能性就越大。请注意，人们更关心内核崩溃，如释放后使用（use-after-frees）或严重错误（panics）而非仅仅是 INFO 错误信息或者类似的信息，除非从报告中清楚地指出了到底在哪里出现了什么具体问题。如果有停顿（stalls）或挂起异常（hangs），只有在它们发生得足够频繁或能够定位错误原因时才报告它们。

总体而言，没有重现用例 (reproducers) 的错误不太可能被分类和修复。如果内核错误是可复现的，请提交包括重现用例（如果可能的话，使用 C 源代码，否则使用 syzkaller 程序）和编译内核使用的 `.config` 文件。如果重现用例仅以 syzkaller 程序的形式提供，请在您的报告中给出链接说明[如何执行它们](/docs/executing_syzkaller_programs.md)。如果您手动运行，请检查重现用例是否正常工作。Syzkaller 试图简化复制器，但结果可能并不理想。您可以尝试手动简化或注释重现用例，这极大地帮助内核开发人员找出错误发生的原因。

如果您想进一步做出贡献，您可以尝试了解错误并尝试自行修复内核程序。如果您无法找到正确的修复方法，但对错误有一定的了解，也请在报告中添加您的想法和结论，这将为内核开发人员节省时间。

## 报告安全漏洞

如果您确信发现的内核错误会带来潜在的安全威胁，请考虑按照以下说明进行操作。请注意，这些说明是基于我正在进行的工作和对当前过程的理解。 现在 [这里](http://seclists.org/oss-sec/2017/q3/242).正在讨论这个说明。

如果您不想陷入这个复杂的披露过程，您可以：

1. 私下将错误报告给 `security@kernel.org`. 在这种情况下，它应该在上游内核中修复，但不能保证错误修复会传播到稳定版或发行版内核。此清单上的最长禁止公开披露期限为 7 天。
2. 私下向例如 Red Hat (`secalert@redhat.com`) 或者 SUSE (`security@suse.com`) 等供应商报告错误. 他们会修复错误，分配 CVE，并通知其他供应商。这些名单上的最长禁运期限 embargo 为 5 周。
3. 将该错误公开报告给 `oss-security@lists.openwall.com`。

如果您想自己处理披露，请阅读下文。

用于报告和披露 Linux 内核安全问题的三个主要邮件列表是 `security@kernel.org`, `linux-distros@vs.openwall.org` 和 `oss-security@lists.openwall.com`.
这些列表的指南链接如下，在向这些列表发送任何内容之前，请仔细阅读它们。

1. `security@kernel.org` - https://www.kernel.org/doc/html/latest/admin-guide/security-bugs.html
2. `linux-distros@vs.openwall.org` - http://oss-security.openwall.org/wiki/mailing-lists/distros
3. `oss-security@lists.openwall.com` - http://oss-security.openwall.org/wiki/mailing-lists/oss-security

### 报告次要安全漏洞

要报告次要安全漏洞（例如本地拒绝服务（DOS）或本地信息泄漏），您应当：

1. 如上所述，向内核开发人员公开报告错误，并等待错误修复被提交。或者，您可以自己开发并发送修复程序。
2. 通过[网页表单](https://cveform.mitre.org/)向 MITRE 请求 CVE。描述内核错误的详细信息，并在请求中添加指向修复的链接 (`patchwork.kernel.org`, `git.kernel.org` 或者 `github.com`).
3. 分配 CVE 后，将内核错误详细信息、CVE 编号和修复链接发送到 `oss-security@lists.openwall.com`.

### 报告主要安全漏洞

要报告主要安全漏洞（例如本地提权（LPE）、远程拒绝服务、远程信息泄漏或远程代码执行（RCE）），您应当：

1. 理解错误原因，如果可能，请开发修复漏洞的补丁。（可选）开发漏洞 PoC（proof-of-concept）。
2. 通知 `security@kernel.org`：
    * 描述漏洞详细信息，包括建议的补丁和漏洞利用（可选）。
    * 要求 7 天的 embargo。
    * 与 `security@kernel.org` 的成员一起处理补丁.
3. 通知 `linux-distros@vs.openwall.org`：
    * 描述漏洞详细信息，包括建议的补丁和漏洞利用（可选）。
    * 要求他们分配一个 CVE 编号。
    * 要求 7 天的 embargo。
4. 等待 7 天，让 linux 发行版应用补丁。
5. 要求 `linux-distros@vs.openwall.org` 公开 CVE 描述并推出更新的内核.
6. 将漏洞修复发送到上游：
    * 在提交消息中提及 CVE 编号。
    * 在提交消息中提及 syzkaller。
7. 通知 `oss-security@lists.openwall.com`：
    * 描述漏洞详细信息，包括指向已提交补丁的链接。
8. 等待 1-3 天，让大众更新系统内核。
9. （可选）在 `oss-security@lists.openwall.com` 上发布漏洞利用方法。

几点说明：

* 理想情况下，应当同时向 `security@kernel.org` 和 `linux-distros@vs.openwall.org` 报告。
* 在与 `security@kernel.org` 成员和上游维护者一起开发补丁时，请让 linux-distros 了解进度。
* 理想情况下，CVE 描述发布、发行版更新、上游提交和向 `oss-security@lists.openwall.com` 发布通知应该同时完成。最差情况下，这些操作都应该在同一天完成。
* 一旦问题被公开（如向上游提交补丁、发布 CVE 描述等），必须立即向 `oss-security@lists.openwall.com` 报告。

[点击此处](http://seclists.org/oss-sec/2016/q4/607)可查看 `oss-security@lists.openwall.com` 上的一个本地提权公告样例，但是时间线看起来并不正确。公开的公告应该在补丁提交给 netdev 后立即发出。
