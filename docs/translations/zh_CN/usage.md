# 如何使用 syzkaller

## 运行方式

启动 `syz-manager` 命令如下：
```
./bin/syz-manager -config my.cfg
```

`syz-manager` 进程将启动虚拟机并在其中进行模糊测试。
`-config` 命令行选项给出了配置文件的位置，并于[此处](/docs/configuration.md)给出详细描述。
Syzkaller 发现的崩溃、统计信息和其他信息都暴露在管理器配置中所指定的 HTTP 网址。

## 崩溃

一旦 syzkaller 在某个 VM 中检测到内核崩溃，它将自动开始重现该崩溃全过程（除非你在配置中指定 `"reproduce": false`）。
默认情况下，它将使用 4 个 VM 来重现内核崩溃，并缩小引起内核崩溃的程序。
这可能会停止模糊测试，因为所有的 VM 可能都在忙于重现检测到的内核崩溃。

重现一个内核崩溃的过程可能需要几分钟到一个小时不等，这取决于内核崩溃是否容易重现或根本不可重现。
由于这个过程并不完美，有一种尝试手动重现崩溃的方法，详见[此处](/docs/reproducing_crashes.md)描述。

如果成功找到复现程序，它将以 syzkaller 程序或 C 程序 进行呈现。
Syzkaller 总是尝试生成更用户友好的 C 语言复现程序，但有时因为各种原因失败（例如轻微不同的执行时序）。
如果 syzkaller 仅生成 syzkaller 程序，你可以通过[一种方式](/docs/reproducing_crashes.md)执行这些程序来手动重现和调试内核崩溃。

## Hub

如果你正在运行多个 `syz-manager` 实例，有一种方法可以将它们连接起来并允许交换执行程序和复现程序，详见[这里](/docs/hub.md)。

## 报告错误

查看[此处](/docs/linux/reporting_kernel_bugs.md)说明，了解如何报告 Linux 内核错误。
