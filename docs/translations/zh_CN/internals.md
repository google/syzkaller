# Syzkaller 的工作原理

有关 Syzkaller 工作原理的通用描述[如下](internals.md#概述).

关于 Linux 内核特有的内部机制可以在[此处](/docs/linux/internals.md)找到。

## 概述

Syzkaller 系统的进程结构如下图所示，其中红色标签表示对应的配置选项。

![Process structure for syzkaller](/docs/process_structure.png?raw=true)

`syz-manager` 进程负责启动、监视以及重启虚拟机实例，并在每个虚拟机内部启动一个 `syz-fuzzer` 进程。`syz-manager` 还负责管理持久性语料库和崩溃时的存储数据。
它运行在具有稳定内核的主机上，不受白噪声模糊测试器负载的影响。

`syz-fuzzer` 进程运行在可能不稳定的虚拟机内。
`syz-fuzzer` 引导模糊化过程（输入生成、变异、最小化等），并通过 RPC 将触发新覆盖率（coverage）的输入发送回 `syz-manager` 进程。
它还启动临时的 `syz-executor` 进程。

每个 `syz-executor` 进程执行单个输入（一系列系统调用）。
它从 `syz-fuzzer` 进程接收内核输入，并将执行结果发送回去。
它被设计得尽可能简单（不干扰模糊测试过程），用 C++ 编写，编译为静态二进制，并使用共享内存进行通信。

## 系统调用描述

`syz-fuzzer` 进程根据[系统调用描述](/docs/syscall_descriptions.md)生成由 `syz-executor` 执行的程序。

## 覆盖率

Syzkaller 是一种覆盖率导向的模糊测试器。有关覆盖率收集的详细信息，请参见[此处](/docs/coverage.md)。

## 崩溃报告

当 `syzkaller` 找到一个崩溃程序时，它将信息保存在 `workdir/crashes` 目录中。
该目录对于每种不同的崩溃类型有一个单独的子目录。
每个子目录包含一个 `description` 文件，包含用于识别崩溃的唯一字符串（用于漏洞识别和去重）；
以及最多100对 `logN` 和 `reportN` 文件，每一个测试机器的崩溃对应一对文件：
```
 - crashes/
   - 6e512290efa36515a7a27e53623304d20d1c3e
     - description
     - log0
     - report0
     - log1
     - report1
     ...
   - 77c578906abe311d06227b9dc3bffa4c52676f
     - description
     - log0
     - report0
     ...
```

崩溃报告描述可以通过一组[正则表达式](/pkg/report/)提取。
如果使用不同的内核架构或看到以前未见过的内核错误消息，则可能需要扩展此正则表达式集合。

`logN` 文件包含原始的 `syzkaller` 日志，包括内核控制台输出以及崩溃前执行的程序。
这些日志可以提供给 `syz-repro` 工具进行[崩溃定位和最小化](/docs/reproducing_crashes.md)，或者提供给 `syz-execprog` 工具进行[手动定位](/docs/executing_syzkaller_programs.md)。
`reportN` 文件包含经过处理和符号化的内核崩溃报告（例如，KASAN 报告）。
我们通常只需要这一对文件（如 `log0` 和 `report0`）中的一个，因为它们可能描述相同的内核错误。然而，`syzkaller` 最多保存100对这样的文件，以防崩溃难以重现或者您只是想通过查看一组崩溃报告来推断一些相似之处或不同之处的情况。

有3种特殊的崩溃类型：
- `no output from test machine` ：测试机器根本没有输出
- `lost connection to test machine` ：与机器的 SSH 连接意外关闭
- `test machine is not executing programs` ：机器看起来是活着的，但在很长一段时间内未执行任何测试程序

遇到这几种崩溃时，你大概率看不到 `reportN` 文件（例如，如果测试机器没有输出，就没有东西可放入报告中）。
有时这些崩溃表明 `syzkaller` 本身存在错误（特别是如果在日志中看到 Go 的应急消息）。
然而，大部分情况下这些崩溃表明内核死机或类似的严重问题（以下是通过这种方式发现的一些漏洞示例：[1](https://groups.google.com/d/msg/syzkaller/zfuHHRXL7Zg/Tc5rK8bdCAAJ)，[2](https://groups.google.com/d/msg/syzkaller/kY_ml6TCm9A/wDd5fYFXBQAJ)，[3](https://groups.google.com/d/msg/syzkaller/OM7CXieBCoY/etzvFPX3AQAJ)）。