> [!WARNING]
>
> **请注意，这是社区驱动的官方 syzkaller 文档翻译。当前文档的最新版本（英文版）可在 [docs/syz_testbed.md](/docs/syz_testbed.md) 中找到。**

# syz-testbed

syz-testbed 是一个用于简化对不同 syzkaller 版本（或配置）进行性能对比评估的流程的工具。该工具会自动检出 syzkaller 仓库、构建它们、运行 syz-manager，并收集/汇总其结果。

## 配置 syz-testbed

syz-testbed 需要一个 JSON 配置文件。示例：

```json
{
  "workdir": "/tmp/syz-testbed-workdir/",
  "corpus": "/tmp/corpus.db",
  "target": "syz-manager",
  "max_instances": 5,
  "run_time": "24h",
  "http": "0.0.0.0:50000",
  "checkouts": [
    {
      "name": "first",
      "repo": "https://github.com/google/syzkaller.git",
    },
    {
      "name": "second",
      "repo": "https://github.com/google/syzkaller.git",
      "branch": "some-dev-branch",
    }
  ],
  "manager_config": {
	  "target": "linux/amd64",
	  "kernel_obj": "/tmp/linux-stable",
	  "image": "/tmp/kernel-image/trixie.img",
	  "sshkey": "/tmp/kernel-image/trixie.id_rsa",
	  "procs": 8,
	  "type": "qemu",
	  "vm": {
          "count": 2,
          "kernel": "/tmp/linux-stable/arch/x86/boot/bzImage",
          "cpu": 2,
          "mem": 2048
	  }
  }
}
```

给定上述配置文件，syz-testbed 将执行以下操作：
1. 将 https://github.com/google/syzkaller.git 的 master 分支检出到 `/tmp/syz-testbed-workdir/checkouts/first/` 并进行构建。
2. 将 https://github.com/google/syzkaller.git 的 `some-dev-branch` 分支检出到 `/tmp/syz-testbed-workdir/checkouts/second/` 并进行构建。
3. 启动 3 个 `first` 实例和 2 个 `second` 实例（因为 `max_instances = 5`）。

目录结构如下：
```
/tmp/syz-testbed-workdir/
└── checkouts
    ├── first
    │   ├── run-first-0
    │   │   ├── log.txt
    │   │   ├── manager.cfg
    │   │   └── workdir
    │   ├── run-first-1
    │   │   ├── log.txt
    │   │   ├── manager.cfg
    │   │   └── workdir
    │   └── run-first-4
    │   │   ├── log.txt
    │   │   ├── manager.cfg
    │   │   └── workdir
    └── second
        ├── run-second-2
        │   ├── log.txt
        │   ├── manager.cfg
        │   └── workdir
        └── run-second-3
            ├── log.txt
            ├── manager.cfg
            └── workdir
```
4. 在 24 小时后（因为 `run_hours` 为 24），停止这 5 个实例。
5. 创建并运行 2 个 `first` 实例和 3 个 `second` 实例。
6. 不断重复上述步骤。

该工具在收到 SIGINT（例如 Ctrl+C）或 SIGTERM 信号后会停止。此外，如果任意一个实例由于错误退出，也会导致整个实验停止。

## Web 界面

该工具带有一个简单的 Web 界面，用于展示实验的当前信息（活动与已完成实例数量、距离实例停止的剩余时间等）以及从各个 syz-manager 收集到的最新统计数据。

如果 `benchmp` 参数指向 `syz-benchcmp` 可执行文件，则 Web 界面还可以生成随时间或执行次数变化的各项参数图表。

要启用该界面，请将 `http` 参数设置为 syz-testbed 绑定的 IP 地址与端口。例如 `"http": "0.0.0.0:50000"`。

## 统计

syz-testbed 提供两种统计“视图”：
1. `complete` —— 仅包含已完成实例的数据（即运行满 `run_hours` 的实例）。
2. `all` —— 还包括当前正在运行的实例的数据。来自已完成实例的统计会回退（对齐）到与活动实例当前运行时长一致的时间点。

因此，统计数据的布局如下：

```bash
$ tree -L 2 /tmp/syz-testbed-workdir/
/tmp/syz-testbed-workdir/
├── stats_all
│   ├── benches
│   │   ├── avg_first.txt
│   │   ├── avg_second.txt
│   ├── bugs.csv
│   ├── checkout_stats.csv
│   └── instance_stats.csv
├── stats_completed
│   ├── benches
│   │   ├── avg_first.txt
│   │   ├── avg_second.txt
│   ├── bugs.csv
│   ├── checkout_stats.csv
│   └── instance_stats.csv
└── testbed.csv
```

1. `bugs.csv` 包含所有运行实例发现的所有 bug。若某个 checkout 启动了多个实例（即 `count` > 1），syz-testbed 会对它们发现的 bug 取并集。其目的在于尽可能收集该 syzkaller 版本可以发现的全部 bug。
2. 各个 syz-manager 生成的统计会写入 `instance_stats.csv`。同时，这些数据还会在属于同一 checkout 的实例之间取平均，并保存到 `checkout_stats.csv`。
3. 将属于同一 checkout 的所有 syz-manager 的 bench 文件（参见 `tools/syz-benchcmp`）进行平均，并保存到对应的 `benches` 目录中的文件里。

统计数据每 90 秒更新一次。

## 运行 syz-testbed

首先，检出 syzkaller 的最新版本：

```bash
$ git clone https://github.com/google/syzkaller.git
```

然后构建 syz-testbed：

```bash
$ cd syzkaller/tools/syz-testbed/
$ go build
```

编写并保存配置文件（例如保存到 `config.json`文件中）。随后，可以使用以下命令运行 syz-testbed：

```bash
$ ./syz-testbed -config config.json
```

停止 syz-testbed 进程会同时停止所有 syzkaller 实例。

## 测试 syz-repro

syz-testbed 也可用于测试 syzkaller 的 bug 复现能力。为此，请在 syz-testbed 的配置文件中将 `target` 属性设置为 `syz-repro`。

还可以指定崩溃日志文件的来源。来源要么是一个文件夹（其中的文件将按崩溃日志处理），要么是一个 syzkaller 的 workdir。`input_logs` 必须指向崩溃日志所在的文件夹——syz-testbed 会遍历该目录并将其中的每个文件作为输入；否则必须使用 `input_workdir`。

例如：
```json
  "repro_config": {
    "input_workdir": "/tmp/some-syzkaller-workdir",
    "crashes_per_bug": 2,
    "skip_bugs": ["SYZFAIL", "no output", "corrupted", "lost connection"]
  },
```

在这种情况下，syz-testbed 会遍历该 syzkaller 发现的所有 bug，跳过匹配 "SYZFAIL"、"no output"、"corrupted" 或 "lost connection" 的条目，然后为每个剩余的 bug 随机选取 2 份崩溃日志进行后续处理。

syz-testbed 会检出并编译指定的 syzkaller 实例，并在选取的每份崩溃日志上持续执行其 syz-repro，直到工具被停止。
