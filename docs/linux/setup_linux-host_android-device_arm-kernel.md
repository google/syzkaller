# Setup: Linux host, Android device, arm32/64 kernel

**Note: fuzzing the kernel on a real Android device may brick it.**

This document details the steps involved in setting up a syzkaller instance fuzzing an `arm32/64` linux kernel on an Android device.

Some features of syzkaller may not yet work properly on `arm32`. For example, not all debugging and test coverage features are available in the Linux kernel for `arm32`, limiting the efficacy of syskaller in finding bugs fast.
 
These were tested on an NXP Pico-Pi-IMX7D following the instructions [here](https://developer.android.com/things/hardware/developer-kits.html).

You may find additional details in syzkaller's `adb` vm implementation [here](/vm/adb/adb.go).

## Device setup

Follow the instructions for your board to install Android and make sure the device boots properly.

Set up the adb bridge so that adb and fastboot work.

Set up a serial port, following the instructions for your device so that you can monitor kernel log messages. On Android-based boards the serial port is typically exposed as a USB (or some custom) port, or over GPIO pins. On phones you can use Android Serial Cable or [Suzy-Q](https://chromium.googlesource.com/chromiumos/platform/ec/+/master/docs/case_closed_debugging.md). syzkaller can work without a dedicated serial port as well (by falling back to `adb shell dmesg -w`), but that is unreliable and turns lots of crashes into "lost connection to test machine" crashes with no additional info.

Get the proper compiler toolchain for your device.

Recompile and reinstall the Linux kernel with [debugging kernel options](https://github.com/xairy/syzkaller/blob/up-docs/docs/linux/kernel_configs.md) available on your board. You might benefit from backporting KCOV or KASAN patches.

## Building syzkaller

Get syzkaller as described [here](/docs/linux/setup.md#go-and-syzkaller).

The build it for either `arm` or `arm64` target architecture depending on the device you're using.

``` bash
make TARGETOS=linux TARGETARCH=arm
```

``` bash
make TARGETOS=linux TARGETARCH=arm64
```

In case you have old Android `/dev/ion` driver (kernel <= 3.18) before building syzkaller copy old `/dev/ion` descriptions:

``` bash
cp sys/android/* sys/linux
```

## Manager config

Create a manager config `android.cfg`:

```
{
	"target": "linux/arm",
	"http": "127.0.0.1:56741",
	"workdir": "$GOPATH/src/github.com/google/syzkaller/workdir",
	"kernel_obj": "$KERNEL",
	"syzkaller": "$GOPATH/src/github.com/google/syzkaller",
	"sandbox": none,
	"procs": 1,
	"type": "adb",
	"cover": true,
	"vm": {
		"devices": [$DEVICES],
		"battery_check": true
	}
}
```

Replace the variables `$GOPATH`, `$KERNEL` (path to kernel build directory), and `$DEVICES` (the device ID for your board as reported by adb devices, e.g. `ABCD000010`) with their actual values.

For `arm64` use `"target": "linux/arm64"`.

If your kernel doesn't support coverage collection (e.g. `arm32` without KCOV patches) set `"cover": false`.

Turn off `battery_check` if your device doesn't have battery service, see the comment [here](/vm/adb/adb.go) for details.

## Running syzkaller

Run syzkaller manager:

``` bash
./bin/syz-manager -config=android.cfg
```

Now syzkaller should be running, you can check manager status with your web browser at `127.0.0.1:56741`.

If you get issues after `syz-manager` starts, consider running it with the `-debug` flag.

Also see [this page](/docs/troubleshooting.md) for troubleshooting tips and [Building a Pixel kernel with KASAN+KCOV](https://source.android.com/devices/tech/debug/kasan-kcov) or [Building a PH-1 kernel with KASAN+KCOV](https://github.com/EssentialOpenSource/kernel-manifest/blob/master/README.md) for kernel build/boot instructions.
