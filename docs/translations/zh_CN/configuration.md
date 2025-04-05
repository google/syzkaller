> [!WARNING]
>
> **请注意，这是社区驱动的官方 syzkaller 文档翻译。当前文档的最新版本（英文版）可在 [docs/configuration.md](/docs/configuration.md) 中找到。**

# 配置

Syzkaller 系统中的 `syz-manager` 进程操作由一个配置文件控制，该文件在调用时通过 `-config` 选项传递。
这个配置可基于[示例](/pkg/mgrconfig/testdata/qemu.cfg)进行编写。
文件为 JSON 格式，包含[多个参数](/pkg/mgrconfig/config.go)。