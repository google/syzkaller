> [!WARNING]
>
> **请注意，这是社区驱动的官方 syzkaller 文档翻译。当前文档的最新版本（英文版）可在 [docs/strace.md](/docs/strace.md) 中找到。**

# Strace

Syzkaller 可以配置为在 [strace](https://strace.io/) 监控下执行程序并捕获输出。

若 `strace_bin` 被设置为 `strace` 二进制文件，syzkaller 将自动使用该 `strace` 二进制文件运行所有成功获取的重现用例。
* 若 syz-manager 已关联至某个“仪表盘”，当生成的重现用例仍能触发相同崩溃时，syzkaller 会将 strace 输出作为普通日志文件上传。
* 若未关联至“仪表盘”，strace 的输出将被保存至独立文件，并可通过 syz-manager 网页访问。

## 如何编译 strace 二进制文件

为避免因模糊测试所用内核镜像中的 libc 版本不匹配导致问题，建议将 `strace` 编译为静态链接二进制文件。

```
git clone https://github.com/strace/strace.git
cd strace
./bootstrap
./configure --enable-mpers=no LDFLAGS='-static -pthread'
make -j`nproc`
```

编译生成的二进制文件位于 `src/strace` 路径下。

## syz-crush

指导 `syz-crush` 在 strace 监控下运行附加复现程序是可能的。要做到这一点，
请确保 syz-manager 配置文件已指定 `strace_bin` 参数，并在命令行参数中额外添加 `-strace` 参数。

## syz-repro

若在 `syz-repro` 的参数后追加 `-strace file-name.log`，该工具将在 strace 下运行生成的重现用例（若成功生成），并保存其输出。
