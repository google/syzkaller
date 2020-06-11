# Setup: Ubuntu host, Odroid C2 board, arm64 kernel

Note: these instructions are currently outdated, but can still be used as a reference.

These are the instructions on how to fuzz the kernel on an [Odroid C2](http://www.hardkernel.com/main/products/prdt_info.php) board using Ubuntu 14.04 on the host machine and Ubuntu on the Odroid.

## Hardware setup

### Required hardware

Your hardware setup must satisfy the following requirements:

1. Host machine should be able to read the Odroid kernel log.
2. Host machine should be able to ssh to the Odroid board.
3. Host machine should be able to forcefully reboot the Odroid.

The particular setup described below requires the following hardware:

1. [Odroid C2 board](http://www.hardkernel.com/main/products/prdt_info.php)
2. SD card (8 GB should be enough)
3. SD card reader (like [this one](https://www.amazon.de/gp/product/B009D79VH4/ref=oh_aui_detailpage_o06_s00?ie=UTF8&psc=1))
4. [USB-UART cable](http://www.hardkernel.com/main/products/prdt_info.php?g_code=G134111883934)
5. USB Ethernet adapter (like [this one](https://www.amazon.de/Apple-MC704LL-A-USB-Ethernet-Adapter/dp/B00W7W9FK0/ref=dp_ob_title_ce))
6. Ethernet cable
7. USB hub with [Per Port Power Switching support](http://www.gniibe.org/development/ac-power-control-by-USB-hub/index.html) (like D-Link DUB H7, **silver** edition).
8. [USB-DC Plug Cable](http://www.hardkernel.com/main/products/prdt_info.php?g_code=G141637559827)

If you decide to use a different setup, you will need to update [Odroid-related code](/vm/odroid/odroid.go) in syzkaller manager.

### Setup Odroid

1. Download and flash [Ubuntu image](http://odroid.com/dokuwiki/doku.php?id=en:c2_release_linux_ubuntu) onto SD card as described [here](http://odroid.com/dokuwiki/doku.php?id=en:odroid_flashing_tools).
2. Connect USB-UART cable and install minicom as described [here](http://odroid.com/dokuwiki/doku.php?id=en:usb_uart_kit).
3. Connect power plug, Odroid will start booting, make sure you see bootloader and kernel logs in minicom.
4. Make sure you can login through minicom as user `odroid` with password `odroid`. This user is a sudoer.

When `systemd` starts Odroid stops sending kernel logs to UART.
To fix this login to the Odroid board and add `kernel.printk = 7 4 1 3` line to `/etc/sysctl.conf` and then do `sysctl -p`:
``` bash
$ cat /etc/sysctl.conf | tail -n 1
kernel.printk = 7 4 1 3
$ sudo sysctl -p
kernel.printk = 7 4 1 3
```

Now make sure you can see kernel messages in minicom:
```
$ echo "Some message" | sudo tee /dev/kmsg
Some message
[  233.128597] Some message
```

### Setup network

1. Connect USB Ethernet adapter to the host machine.
2. Use Ethernet cable to connect Odroid and the host adapter.
3. Use minicom to modify `/etc/network/interfaces` on Odroid:

    ```
    auto eth0
    iface eth0 inet static
    	address 172.16.0.31
    	gateway 172.16.0.1
    	netmask 255.255.255.0
    ```

4. Reboot Odroid.

5. Setup the interface on the host machine (though Network Manager or via `/etc/network/interfaces`):

    ```
    auto eth1
    iface eth1 inet static
    	address 172.16.0.30
    	gateway 172.16.0.1
    	netmask 255.255.255.0
    ```

6. You should now be able to ssh to Odroid (user `root`, password `odroid`):

    ``` bash
    $ ssh root@172.16.0.31
    root@172.16.0.31's password: 
    ...
    Last login: Thu Feb 11 11:30:51 2016
    root@odroid64:~#
    ```

### Setup USB hub

To perform a hard reset of the Odroid board (by turning off power) I used a D-Link DUB H7 USB hub (**silver** edition, not the black one).
This hub has support for a feature called [Per Port Power Switching](http://www.gniibe.org/development/ac-power-control-by-USB-hub/index.html), which allows to turn off power on a selected port on the hub remotely (via USB connection to the host machine) .

[To be able to open the hub device entry](http://www.janosgyerik.com/adding-udev-rules-for-usb-debugging-android-devices/) under `/dev/` without being root, add the following file to `/etc/udev/rules.d/` on the host machine:
``` bash
$ cat /etc/udev/rules.d/10-local.rules 
SUBSYSTEM=="usb", ATTR{idVendor}=="2001", ATTR{idProduct}=="f103", MODE="0664", GROUP="plugdev"
```

`idVendor` and `idProduct` should correspond to the hub vendor and product id (can be seen via `lsusb`).
Don't forget to replug the hub after you add this file.

``` bash
$ lsusb 
...
Bus 003 Device 026: ID 2001:f103 D-Link Corp. DUB-H7 7-port USB 2.0 hub
...
```

Communication with the hub is done by sending USB control messages, which requires `libusb`:
``` bash
sudo apt-get install libusb-dev libusb-1.0-0-dev
```

Now plug in the hub and try to switch power on some of it's ports.
For that you can use the [hub-ctrl.c](https://github.com/codazoda/hub-ctrl.c) tool by Niibe Yutaka or it's [ simplified Go analog](https://gist.github.com/xairy/37264952ff35da6e7dcf51ef486368e5):
``` bash
$ go run hub.go -bus=3 -device=26 -port=6 -power=0
Power turned off on port 6
$ go run hub.go -bus=3 -device=26 -port=6 -power=1
Power turned on on port 6
```

Note, that the DUB-H7 hub has a weird port numbering: `5, 6, 1, 2, 7, 3, 4` from left to right.

Connect the Odroid board with a power plug to one of the USB hub ports and make sure you can forcefully reboot the Odroid by turning the power off and back on on this port.

## Cross-compiler

You need to compile full GCC cross-compiler tool-chain for aarch64 as described [here](http://preshing.com/20141119/how-to-build-a-gcc-cross-compiler/) (including the standard libraries).
Use GCC revision 242378 (newer revisions should work as well, but weren't tested).
The result should be a `$PREFIX` directory with cross-compiler, standard library headers, etc.
```
$ ls $PREFIX
aarch64-linux  bin  include  lib  libexec  share
```

## Kernel

Set environment variables, they will be detected and used during kernel compilation:
``` bash
export PATH="$PREFIX/bin:$PATH"
export ARCH=arm64
export CROSS_COMPILE=aarch64-linux-
```

Clone the linux-next kernel into `$KERNEL`:
``` bash
git clone https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git $KERNEL
cd $KERNEL
```

Apply the following patch, otherwise building the kernel with newer GCC fails (the patch is taken from [here](https://patchwork.kernel.org/patch/9380181/)):
``` makefile
diff --git a/Makefile b/Makefile
index 165cf9783a5d..ff8b40dca9e2 100644
--- a/Makefile
+++ b/Makefile
@@ -653,6 +653,11 @@ KBUILD_CFLAGS += $(call cc-ifversion, -lt, 0409, \
 # Tell gcc to never replace conditional load with a non-conditional one
 KBUILD_CFLAGS  += $(call cc-option,--param=allow-store-data-races=0)
 
+# Stop gcc from converting switches into a form that defeats dead code
+# elimination and can subsequently lead to calls to intentionally
+# undefined functions appearing in the final link.
+KBUILD_CFLAGS  += $(call cc-option,--param=max-fsm-thread-path-insns=1)
+
 include scripts/Makefile.gcc-plugins
 
 ifdef CONFIG_READABLE_ASM
```

Apply the following patch to disable KASAN bug detection on stack and globals (kernel doesn't boot, KASAN needs to be fixed):
``` makefile
diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
index 9576775a86f6..8bc4eb36fc1b 100644
--- a/scripts/Makefile.kasan
+++ b/scripts/Makefile.kasan
@@ -11,7 +11,6 @@ CFLAGS_KASAN_MINIMAL := -fsanitize=kernel-address
 
 CFLAGS_KASAN := $(call cc-option, -fsanitize=kernel-address \
                -fasan-shadow-offset=$(KASAN_SHADOW_OFFSET) \
-               --param asan-stack=1 --param asan-globals=1 \
                --param asan-instrumentation-with-call-threshold=$(call_threshold))
 
 ifeq ($(call cc-option, $(CFLAGS_KASAN_MINIMAL) -Werror),)
```

Configure the kernel (you might wan't to enable more configs as listed [here](kernel_configs.md)):
``` bash
make defconfig
# Edit .config to enable the following configs:
# CONFIG_KCOV=y
# CONFIG_KASAN=y
# CONFIG_KASAN_INLINE=y
# CONFIG_TEST_KASAN=m
# CONFIG_PANIC_ON_OOPS=y
make oldconfig
```

Build the kernel:
``` bash
make -j48 dtbs Image modules LOCALVERSION=-xc2
```

## Installation

Install the `mkimage` util with arm64 support (part of the `u-boot-tools` package).
You might have it by default, but it's not available on Ubuntu 14.04 in the default package repos.
In this case download the package from [here](https://launchpad.net/ubuntu/xenial/amd64/u-boot-tools/2016.01+dfsg1-2ubuntu1) and use `sudo dpkg -i` to install.

Insert the SD card reader with the SD card inside into the host machine.
You should see two partitions automounted (or mount them manually), for example `sdb1` mounted at `$MOUNT_PATH/boot` and `sdb2` mounted at `$MOUNT_PATH/rootfs`.

Build the kernel image:
``` bash
mkimage -A arm64 -O linux -T kernel -C none -a 0x1080000 -e 0x1080000 -n linux-next -d arch/arm64/boot/Image ./uImage
```

Copy the kernel image, modules and device tree:
``` bash
KERNEL_VERSION=`cat ./include/config/kernel.release`
cp ./uImage $MOUNT_PATH/boot/uImage-$KERNEL_VERSION
make modules_install LOCALVERSION=-xc2 INSTALL_MOD_PATH=$MOUNT_PATH/rootfs/
cp ./arch/arm64/boot/dts/amlogic/meson-gxbb-odroidc2.dtb $MOUNT_PATH/boot/meson-gxbb-odroidc2-$KERNEL_VERSION.dtb
cp .config $MOUNT_PATH/boot/config-$KERNEL_VERSION
```

Backup the old bootloader config; if something doesn't work with the new kernel, you can always roll back to the old one by restoring `boot.ini`:
``` bash
cd $MOUNT_PATH/boot/
cp boot.ini boot.ini.orig
```

Replace the bootloader config `boot.ini` (based on the one taken from [here](http://forum.odroid.com/viewtopic.php?p=162045#p162045)) with the following; don't forget to update `version`:
```
ODROIDC2-UBOOT-CONFIG

# Set version to $KERNEL_VERSION
setenv version 4.11.0-rc1-next-20170308-xc2-dirty
setenv uImage uImage-${version}
setenv fdtbin meson-gxbb-odroidc2-${version}.dtb

setenv initrd_high   0xffffffff
setenv fdt_high      0xffffffff
setenv uimage_addr_r 0x01080000
setenv fdtbin_addr_r 0x01000000

# You might need to use root=/dev/mmcblk0p2 below, try booting and see if the current one works.
setenv bootargs "console=ttyAML0,115200 root=/dev/mmcblk1p2 rootwait ro fsck.mode=force fsck.repair=yes net.ifnames=0 oops=panic panic_on_warn=1 panic=86400 systemd.show_status=no"

fatload mmc 0:1 ${fdtbin_addr_r} ${fdtbin}
fatload mmc 0:1 ${uimage_addr_r} ${uImage}
bootm ${uimage_addr_r} - ${fdtbin_addr_r}
```

Sync and unmount:
``` bash
sync
umount $MOUNT_PATH/boot
umount $MOUNT_PATH/rootfs
```

Now plug the SD card into the Odroid board and boot.
The new kernel should now be used.
It makes sense to ensure that you still can ssh to Odroid.

## Syzkaller

Generate ssh key and copy it to Odroid:
``` bash
mkdir ssh
ssh-keygen -f ssh/id_rsa -t rsa -N ''
ssh root@172.16.0.31 "mkdir /root/.ssh/"
scp ./ssh/id_rsa.pub root@172.16.0.31:/root/.ssh/authorized_keys
```

Now make sure you can ssh with the key:
``` bash
ssh -i ./ssh/id_rsa root@172.16.0.31
```

Build syzkaller as described [here](/docs/linux/setup.md#go-and-syzkaller), with `odroid` build tag:

``` bash
make GOTAGS=odroid TARGETARCH=arm64
```

Use the following config:
```
{
	"target": "linux/arm64",
	"http": "127.0.0.1:56741",
	"workdir": "/syzkaller/workdir",
	"kernel_obj": "/linux-next",
	"syzkaller": "/go/src/github.com/google/syzkaller",
	"sshkey": "/odroid/ssh/id_rsa",
	"rpc": "172.16.0.30:0",
	"sandbox": "namespace",
	"reproduce": false,
	"procs": 8,
	"type": "odroid",
	"vm": {
		"host_addr": "172.16.0.30",
		"device_addr": "172.16.0.31",
		"console": "/dev/ttyUSB0",
		"hub_bus": 3,
		"hub_device": 26,
		"hub_port": 5
	}
}
```

Don't forget to update:
 - `workdir` (path to the workdir)
 - `kernel_obj` (path to kernel build directory)
 - `sshkey` (path to the generated ssh private key)
 - `vm.console` (serial device you used in `minicom`)
 - `vm.hub_bus` (number of the bus to which USB hub is connected, view with `lsusb`)
 - `vm.hub_device` (device number for the USB hub, view with `lsusb`)
 - `vm.hub_port` (number of the USB hub port to which Odroid power plug is connected)

Now start syzkaller:
``` bash
./bin/syz-manager -config=odroid.cfg
```

If you get issues after `syz-manager` starts, consider running it with the `-debug` flag.
Also see [this page](/docs/troubleshooting.md) for troubleshooting tips.
