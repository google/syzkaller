# Setup: Ubuntu host, arm32 kernel on an Android device

This document will detail the steps involved in setting up a syzkaller instance fuzzing an ARM32 linux kernel on an Android (or Android Things) device. This is a work-in-progress at this time and being provided to spur further development. Some features of syzkaller may not yet work on ARM32. For example, not all debugging and test coverage features are available in the Linux kernel for ARM32, limiting the efficacy of syskaller in finding bugs fast. These instructions help set up syzkaller to be a basic fuzzer that does not rely on test coverage data from the kernel. 

## Install Android and Linux kernel on an ARM32 device

Follow the instructions for the ARM32 board to install Android or 
Android Things and make sure the device boots properly.

Set up the adb bridge so that adb and fastboot work.

Setup a serial port, following the instructions for your board so that you can monitor any messages from the kernel.

These were tested on an NXP Pico-Pi-IMX7D following the instructions [here](https://developer.android.com/things/hardware/developer-kits.html).

If feasible, recompile and reinstall the Linux kernel with any debugging options available on your board.

## Build syzkaller executables

Build syzkaller as described [here](/docs/contributing.md), with `arm` target:

```
make TARGETOS=linux TARGETARCH=arm
```

## Create a manager configuration file

Create a manager config myboard.cfg, replacing the environment
variables `$GOPATH`, `$KERNEL` (path to kernel build dir for the ARM32 board), and `$DEVICES` (the device ID for your board as reported by adb devices) with their actual values. Change any other flags as needed for your ARM board.
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
	"cover": false, 
	"vm": {
		"devices": [$DEVICES],
		"battery_check": false
	}
}
```

Run syzkaller manager:
``` bash
./bin/syz-manager -config=myboard.cfg
```

Now syzkaller should be running, you can check manager status with your web browser at `127.0.0.1:56741`.

If you get issues after `syz-manager` starts, consider running it with the `-debug` flag.
Also see [this page](troubleshooting.md) for troubleshooting tips.
