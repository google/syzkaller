> [!WARNING]
>
> **请注意，这是社区驱动的官方 syzkaller 文档翻译。当前文档的最新版本（英文版）可在 [docs/db.md](/docs/db.md) 中找到。**

# syz-db

`syz-db` 程序可用于操作由 syz-manager 使用的 corpus.db 数据库。

## 构建

使用 `make db` 构建 `syz-db`，或切换到 `tools/syz-db` 目录并运行 `go build`。

## 选项

`syz-db` 目前提供以下通用参数：

```shell
  -arch string
    	目标架构
  -os string
    	目标操作系统
  -version uint
    	数据库版本
  -vv int
    	详细程度
```

这些参数可用于以下命令：

```
  syz-db pack dir corpus.db
```

用于打包数据库

```
  syz-db unpack corpus.db dir
```

用于解包数据库。将返回一个包含执行过的系统调用的文件。

```
  syz-db merge dst-corpus.db add-corpus.db* add-prog*
```

用于合并数据库。不会创建额外的文件：第一个文件将被合并后的结果替换。

```
  syz-db bench corpus.db
```

用于运行反序列化基准测试。例如：

```
syz-db -os=linux -arch=amd64 bench corpus.db
```

可能会输出类似以下内容：

```
allocs 123 MB (123 M)，下次GC 123 MB，系统堆 123 MB，活动分配 123 MB (123 M)，时间 324s。
```
