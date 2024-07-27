> [!WARNING]
>
> **请注意，这是社区驱动的官方 syzkaller 文档翻译。当前文档的最新版本（英文版）可在 [docs/executing_syzkaller_programs.md](/docs/executing_syzkaller_programs.md) 找到。**

# 运行 syzkaller 程序

本文描述了如何执行现有的 syzkaller 程序用以复现 bug。通过这种方式，你可以重放一个单独的程序或一个包含多个程序的完整执行日志。

1. 安装 Go 工具链（要求 Go 的版本不低于1.16）：
从[官网](https://golang.org/dl/)下载最新的 Go 发行版，并将其解压到 `$HOME/goroot`。

``` bash
export GOROOT=$HOME/goroot
export GOPATH=$HOME/gopath
```

2. 下载 syzkaller 源码:

``` bash
git clone https://github.com/google/syzkaller
```

请注意，你的 syzkaller 版本必须和生成待执行程序的 syzkaller 版本一致。

3. 构建需要的 syzkaller 二进制文件:

``` bash
cd syzkaller
make
```

4. 将构建好的二进制文件和程序复制到待测试机器上（根据待测试机器，替换命令中的 `linux_amd64`）

``` bash
scp -P 10022 -i bullseye.img.key bin/linux_amd64/syz-execprog bin/linux_amd64/syz-executor program root@localhost:
```

5. 在待测试机器上运行程序

``` bash
./syz-execprog -repeat=0 -procs=8 program
```

下面是几个实用的 `syz-execprog` 参数：

```
  -procs int
      执行程序的并发进程数（默认值为 1）
  -repeat int
      重复执行的次数（0 代表无限执行）（默认值为 1）
  -sandbox string
      模糊测试的沙盒模式（none/setuid/namespace）（默认为 "setuid" 模式）
  -threaded
      是否使用线程模式（默认为 是）
```

`-threaded=0` 参数将会使程序作为一个简单的单线程系统调用序列来执行；
而 `-threaded=1` 强制每个系统调用使用单独的线程，这样就可以在阻塞的系统调用上继续执行。

而较老版本的 syzkaller 还有如下参数：

```
  -collide
      是否使用冲突系统调用以引发数据竞争（默认为是）
```

`-collide=1` 参数的作用是当很多系统调用并发执行时，强制执行第二轮系统调用。
当你使用较老版本的复现程序时，可能需要用到这个参数。

如果想要重放一个开头包含如下内容的复现程序：

```
# {Threaded:true Repeat:true RepeatTimes:0 Procs:8 Slowdown:1 Sandbox:none Leak:false NetInjection:true NetDevices:true NetReset:true Cgroups:true BinfmtMisc:true CloseFDs:true KCSAN:false DevlinkPCI:false USB:true VhciInjection:true Wifi:true IEEE802154:true Sysctl:true UseTmpDir:true HandleSegv:true Repro:false Trace:false LegacyOptions:{Collide:false Fault:false FaultCall:0 FaultNth:0}}
```

你需要基于文件头中的值调整对应的参数。其中，`Threaded`/`Procs`/`Sandbox` 与 `-threaded`/`-procs`/`-sandbox` 参数对应。如果 `Repeat` 的值为 `true`，则在 `syz-execprog` 的参数中添加 `-repeat=0`。
