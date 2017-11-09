# Setup: Ubuntu host, arm32 kernel on an Android device

This document will detail the steps involved in setting up a Syzkaller instance fuzzing an ARM32 linux kernel on an Android (or Android Things) device. This is a work-in-progress at this time and being provided to spur further development. Some features of syzkaller may not yet work on ARM32. For example, not all debugging and test coverage features are available in the Linux kernel for ARM32, limiting the efficacy of syskaller in finding bugs fast. These instructions help set up syzkaller to be a basic fuzzer that does not rely on test coverage data from the kernel. 

## Install Android and Linux kernel on an ARM32 device

Follow the instructions for the ARM32 board to install Android or 
Android Things and make sure the device boots properly.

Set up the adb bridge so that adb and fastboot work.

Setup a serial port, following the instructions for your board so that you can monitor any messages from the kernel.

These were tested on an NXP Pico-Pi-IMX7D following the instructions at:

```

https://developer.android.com/things/hardware/developer-kits.html.

```


If feasible, recompile and reinstall the Linux kernel with any debugging options available on your board.


## Optional: Setup the NDK cross-compiler toolchain


You can find the NDK packages here:

https://developer.android.com/ndk/downloads/index.html


Download the package for your host system (linux-x86_64). After you have unzipped it, you should have a directory named android-ndk-r15c, or the latest stable release. We will refer to this directory as $(NDK).


Generate a standalone toolchain for the target device in a destination of your choice (assumed to be defined in the variable NDKARM). The destination folder $NDKARM will get created by the code below.

```
export NDKARM=~/armtc
cd $NDK
./build/tools/make_standalone_toolchain.py --arch arm --api 26 --stl=libc++ --install-dir $NDKARM
```

## Install Go

Install Go:
``` bash
wget https://storage.googleapis.com/golang/go1.8.1.linux-amd64.tar.gz
tar -xf go1.8.1.linux-amd64.tar.gz
mv go goroot
export GOROOT=`pwd`/goroot
export PATH=$GOROOT/bin:$PATH
mkdir gopath
export GOPATH=`pwd`/gopath

```

## Build syzkaller code

### Initialize a working directory and set up environment variables
Create a working directory. Also make sure GOROOT, GOPATH, and optionally NDKARM are defined and exported as instructed earlier. 

``` bash
go get -u -d github.com/atulprak/syzkaller/...
cd gopath/src/github.com/atulprak/syzkaller/
mkdir workdir 

```


### Build syzkaller executables

Run make. The output should go to ./bin and ./bin/linux_arm directories.

To use the Android cross-compile toolchain, NDKARM must be defined. Use the following:
```
TARGETOS=android TARGETARCH=arm make
```

Alternatively, to use the gcc cross-compiler, use the following:

```
TARGETOS=linux TARGETARCH=arm make
```

### Create a manager configuration file

Create a manager config myboard.cfg, replacing the environment
variables `$GOPATH`, `$VMLINUX` (path to vmlinux for the ARM32 board), and $DEVICES (the device ID for your board as reported by adb devices) with their actual values.
```
{
	"target": "linux/arm",
	"http": "127.0.0.1:56741",
	"workdir": "$GOPATH/src/github.com/google/syzkaller/workdir",
	"vmlinux": "$KERNEL/vmlinux",
	"syzkaller": "$GOPATH/src/github.com/google/syzkaller",
    "sandbox": none,
	"procs": 1,
	"type": "adb",
    "cover": false, 
	"vm": {
        "devices": [$DEVICES]
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





