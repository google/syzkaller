> [!WARNING]
>
> **请注意，这是社区驱动的官方 syzkaller 文档翻译。当前文档的最新版本（英文版）可在 [docs/bisect.md](/docs/bisect.md) 中找到。**

# Syz-bisect

`syz-bisect` 程序可用于对由 syzkaller 发现的崩溃进行查找责任提交（culprit commit）和修复提交（fix commit）。
它还可以识别触发崩溃的配置选项。

## 使用方法

使用 `make bisect` 构建 `syz-bisect`。

在进行二分查找时，根据内核版本的不同，会使用不同的编译器。这些编译器可以在
[这里](https://storage.googleapis.com/syzkaller/bisect_bin.tar.gz)下载。

安装 ccache 以加速二分查找过程中的内核编译。

使用 [create-image.sh](/tools/create-image.sh) 创建用户空间 (chroot)。

根据您的环境调整以下内容并创建配置文件：

```
{
	"bin_dir": "/home/syzkaller/bisect_bin",
	"ccache": "/usr/bin/ccache",
	"kernel_repo": "git://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git",
	"kernel_branch": "master",
	"syzkaller_repo": "https://github.com/google/syzkaller",
	"userspace": "/home/syzkaller/image/chroot",
	"kernel_config": "/home/syzkaller/go/src/github.com/google/syzkaller/dashboard/config/linux/upstream-apparmor-kasan.config",
	"kernel_baseline_config": "/home/syzkaller/go/src/github.com/google/syzkaller/dashboard/config/linux/upstream-apparmor-kasan-base.config",
	"syzctl": /home/syzkaller/go/src/github.com/google/syzkaller/dashboard/config/linux/upstream.sysctl,
	"cmdline": /home/syzkaller/go/src/github.com/google/syzkaller/dashboard/config/linux/upstream.cmdline,
	"manager":
	{
		"name" : "bisect",
		"target": "linux/amd64",
		"http": "127.0.0.1:56741",
		"workdir": "/home/syzkaller/workdir",
		"kernel_obj": "/home/syzkaller/linux",
		"image": "/home/syzkaller/workdir/image/image",
		"sshkey": "/home/syzkaller/workdir/image/key",
		"syzkaller": "/home/syzkaller/go/src/github.com/google/syzkaller_bisect",
		"procs": 8,
		"type": "qemu",
		"kernel_src": "/syzkaller/linux",
		"vm": {
		      "count": 4,
		      "kernel": "/home/syzkaller/linux/arch/x86/boot/bzImage",
		      "cpu": 2,
		      "mem": 2048,
		      "cmdline": "root=/dev/sda1 rw console=ttyS0 kaslr crashkernel=512M minnowboard_1:eth0::: security=none"
		}
	}
}
```

使用 `bin/syz-bisect -config vm_bisect.cfg -crash /syzkaller/workdir/crashes/03ee30ae11dfd0ddd062af26566c34a8c853698d` 进行二分查找。

`syz-bisect` 需要在指定的崩溃目录中找到 repro.cprog 或 repro.prog 文件。
它也会利用 repro.opts 文件，但这不是必需的。

## 额外参数

`-syzkaller_commit` 如果您想使用特定版本的 syzkaller，请使用此参数。

`-kernel_commit` 已知可以重现崩溃的内核提交。在查找修复提交时，您会需要使用此参数。

`-fix` 如果您想对修复提交进行二分查找，请使用此参数。

## 输出

`syz-bisect` 需要一些时间运行，但完成后会将结果输出到控制台。它还会将结果存储在指定崩溃目录的文件中：

`cause.commit` 被识别为导致崩溃的提交或文本“该崩溃已在最旧的测试版本上发生”

`fix.commit` 被识别为修复崩溃的提交或文本“该崩溃仍在 HEAD 上发生”

`cause.config` 被识别为触发崩溃的配置选项

`original.config, baseline.config, minimized.config` 在配置二分查找中使用的配置文件
