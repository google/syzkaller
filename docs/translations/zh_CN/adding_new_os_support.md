> [!WARNING]
>
> **请注意，这是社区驱动的官方 syzkaller 文档翻译。当前文档的最新版本（英文版）可在 [docs/adding_new_os_support.md](/docs/adding_new_os_support.md) 中找到。**

# 添加新的操作系统支持

为了让 syzkaller 支持一个新的操作系统内核，以下是需要编辑的 syzkaller 的共同部分。然而，特定内核可能还需要一些特定的更改（例如，从给定内核收集代码覆盖率，或者一些可能弹出并给出调整提示的错误信息）。

## syz-executor

每个操作系统都有一个 `executor/executor_GOOS.h` 文件，其中 GOOS 为操作系统名字，例如 `executor/executor_linux.h`。该文件包含两个重要函数：

- `os_init` 负责为调用进程映射虚拟地址空间，
- `execute_syscall` 负责为特定操作系统内核执行系统调用。

这两个函数在 `executor/executor.cc` 中被调用，主要负责执行系统调用程序，并管理程序运行的线程。

`executor_GOOS.h` 还包含与该操作系统相关的函数，例如允许它收集覆盖率信息、检测位宽等的函数（例如：[executor_linux.h](/executor/executor_linux.h)）。

目标内核将根据 `executor/executor.cc` 文件中定义的宏调用预期的函数。

## 构建文件 `pkg/`

- 在 `pkg/build/build.go` 中添加操作系统名称及其支持的架构
- 在 `pkg/build/` 下创建一个构建目标内核镜像的文件。这个文件包含配置和构建可启动镜像构建的函数以及生成 SSH 密钥的函数，这些密钥将由 Syzkaller 用于访问虚拟机。每个由 Syzkaller 支持的操作系统都有一个名为 `GOOS.go` 的文件。
- 将给定目标添加到 `s/makefile/Makefile/`。

## 报告文件 `pkg/report/`

在 `pkg/report/` 下为目标内核创建一个报告构建错误的文件。每个由 Syzkaller 支持的操作系统都有一个名为 `GOOS.go` 的文件。

## 编辑 `pkg/host/`

- 实现 `isSupported` 函数，该函数对于支持的系统调用返回 true，同时它位于 `pkg/host/GOOS` 目录中。

## 在 `sys/GOOS/` 下创建文件

在 `sys/GOOS/` 下为目标内核创建一个 `init.go` 文件，其中包含初始化目标和不同支持架构的 `initTarget` 函数。

## 编辑 `sys/syz-extract`

将新内核名称添加到已支持的内核列表中，并更新到文件 `sys/syz-extract/extract.go` 中。

## 编辑 `sys/targets`

将新内核名称添加到已支持的内核列表中，并更新到文件 `sys/targets/targets.go` 中。

## 编辑 `vm/qemu`

将新内核名称添加到已支持内核的列表中，并更新到文件 `vm/qemu/qemu.go` 中。

## Syzkaller 描述与伪系统调用

查看 [描述](/docs/syscall_descriptions.md) 与 [伪系统调用](/docs/pseudo_syscalls.md).
