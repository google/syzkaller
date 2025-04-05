> [!WARNING]
>
> **请注意，这是社区驱动的官方 syzkaller 文档翻译。当前文档的最新版本（英文版）可在 [docs/linux/setup_linux-host_qemu-vm_arm64-kernel.md](/docs/linux/setup_linux-host_qemu-vm_arm64-kernel.md) 中找到。**

# 设置：Linux 主机，QEMU 虚拟机，arm64 内核

这份文档将详细说明如何设置 Syzkaller 实例，以便对你选择的任何 ARM64 Linux 内核进行模糊测试。

## 创建一个磁盘映像

我们将使用 buildroot 来创建磁盘映像。
你可以从 [这里](https://buildroot.uclibc.org/download.html) 获取 buildroot。
解压压缩包，并在其中执行 `make menuconfig`，
选择以下选项。

    Target options
	    Target Architecture - Aarch64 (little endian)
    Toolchain type
	    External toolchain - Linaro AArch64
    System Configuration
    [*] Enable root login with password
            ( ) Root password = set your password using this option
    [*] Run a getty (login prompt) after boot  --->
	    TTY port - ttyAMA0
    Target packages
	    [*]   Show packages that are also provided by busybox
	    Networking applications
	        [*] dhcpcd
	        [*] iproute2
	        [*] openssh
    Filesystem images
	    [*] ext2/3/4 root filesystem
	        ext2/3/4 variant - ext3
	        exact size in blocks - 6000000
	    [*] tar the root filesystem

运行 `make`。编译完成后，确认 `output/images/rootfs.ext3` 文件是否存在。

如果在 x86 上运行 arm64 qemu 时遇到 ssh 启动时间非常慢的问题，很可能是熵不足的问题，可以通过安装 `haveged` 来 “解决” 这个问题。你可以在 buildroot 的 `menuconfig` 中找到该选项：

```
    Target packages
	    Miscellaneous
	        [*] haveged
```

## 从 Linaro 获取 ARM64 工具链

你需要一个支持 gcc 插件的 ARM64 内核。
如果没有，请从 Linaro 获取 ARM64 工具链。
从 [这里](https://releases.linaro.org/components/toolchain/binaries/6.1-2016.08/aarch64-linux-gnu/) 获取 `gcc-linaro-6.1.1-2016.08-x86_64_aarch64-linux-gnu.tar.xz`。
解压缩并将其 `bin/` 添加到你的 `PATH` 中。
如果你的电脑上已经安装了其他 ARM64 工具链，请确保新下载的工具链被优先使用。

## 编译内核

获取你想要进行模糊测试的 Linux 内核版本的源代码，并执行以下操作。

    $ ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- make defconfig
    $ vim .config

更改以下选项：
```
    CONFIG_KCOV=y
    CONFIG_KASAN=y
    CONFIG_DEBUG_INFO=y
    CONFIG_CMDLINE="console=ttyAMA0"
    CONFIG_KCOV_INSTRUMENT_ALL=y
    CONFIG_DEBUG_FS=y
    CONFIG_NET_9P=y
    CONFIG_NET_9P_VIRTIO=y
    CONFIG_CROSS_COMPILE="aarch64-linux-gnu-"
```
```
    $ ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- make -j40
```

如果编译成功，应该会有一个 `arch/arm64/boot/Image` 文件。

## 获取用于 ARM64 的 QEMU

从 git 或最新发布的源代码中获取 QEMU 源代码。

    $ ./configure
    $ make -j40

如果编译成功，应该会有一个 `aarch64-softmmu/qemu-system-aarch64` 二进制文件。

## 手动启动

按照以下步骤启动内核。

    $ /path/to/aarch64-softmmu/qemu-system-aarch64 \
      -machine virt \
      -cpu cortex-a57 \
      -nographic -smp 1 \
      -hda /path/to/rootfs.ext3 \
      -kernel /path/to/arch/arm64/boot/Image \
      -append "console=ttyAMA0 root=/dev/vda oops=panic panic_on_warn=1 panic=-1 ftrace_dump_on_oops=orig_cpu debug earlyprintk=serial slub_debug=UZ" \
      -m 2048 \
      -net user,hostfwd=tcp::10023-:22 -net nic

此时，你应该能够看到一个登录提示符。

## 设置 QEMU 磁盘

现在我们已经有了一个 shell，接着我们向现有的初始化脚本添加几行代码，这样每次 Syzkaller 启动虚拟机时都会执行这些脚本。

在 /etc/init.d/S50sshd 的顶部添加以下行：

    ifconfig eth0 up
    dhcpcd
    mount -t debugfs none /sys/kernel/debug
    chmod 777 /sys/kernel/debug/kcov

将该行注释掉

    /usr/bin/ssh-keygen -A


接下来我们要设置 ssh。在本地生成一个 ssh 密钥对，然后将公钥复制到 `/` 目录下的 `/authorized_keys` 文件中。在生成密钥时，请不要设置密码。

打开 `/etc/ssh/sshd_config` 文件，并按照下面所示修改以下行。

    PermitRootLogin yes
    PubkeyAuthentication yes
    AuthorizedKeysFile      /authorized_keys
    PasswordAuthentication yes

重新启动计算机，并确保你可以从主机 ssh 连接到虚拟机。

    $ ssh -i /path/to/id_rsa root@localhost -p 10023

## 编译 syzkaller

按照 [这里](/docs/linux/setup.md#go-and-syzkaller) 的描述编译 Syzkaller，目标为 `arm64`。

```
CC=gcc-linaro-6.3.1-2017.05-x86_64_aarch64-linux-gnu/bin/aarch64-linux-gnu-g++
make TARGETARCH=arm64
```


## 修改你的配置文件并启动 Syzkaller

以下是一个示例配置文件，包含了所需的选项。根据你的需求进行修改。

```
{
    "name": "QEMU-aarch64",
    "target": "linux/arm64",
    "http": ":56700",
    "workdir": "/path/to/a/dir/to/store/syzkaller/corpus",
    "kernel_obj": "/path/to/linux/build/dir",
    "syzkaller": "/path/to/syzkaller/arm64/",
    "image": "/path/to/rootfs.ext3",
    "sshkey": "/path/to/id_rsa",
    "procs": 8,
    "type": "qemu",
    "vm": {
        "count": 1,
        "qemu": "/path/to/qemu-system-aarch64",
        "cmdline": "console=ttyAMA0 root=/dev/vda",
        "kernel": "/path/to/Image",
        "cpu": 2,
        "mem": 2048
    }
}
```

此时，你应该能够访问 `localhost:56700` 并查看模糊测试的结果。

如果在 `syz-manager` 启动后遇到问题，请考虑使用 `-debug` 标志运行它。
还可以查看 [此页面](/docs/troubleshooting.md) 获取故障排除提示。
