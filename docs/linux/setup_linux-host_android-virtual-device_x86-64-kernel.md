# Setup: Linux host, Android virtual device, x86-64 kernel

This document details the steps involved in setting up a syzkaller instance fuzzing an `x86-64` linux kernel on an Android virtual device.

In the instructions below, the `$VAR` notation (e.g. `$GSI`, `$GKI`, etc.) is used to denote paths to directories that are either created when executing the instructions, or that you have to create yourself before running the instructions. Substitute the values for those variables manually.

Note:
- All commands below assume root privileges.
- It is recommended to have at least 64 GB of RAM and 500 GB of free disk space.

## Install prerequisites

Command:
``` bash
apt update
apt install sudo git wget curl repo libncurses5 vim gcc make bison bc zip rsync language-pack-en-base
```

## Cuttlefish

It is recommended to use [Cuttlefish](https://github.com/google/android-cuttlefish) to emulate Android devices. Build and install it from source (v1.16.0 as an example):

Command:
``` bash
apt install git devscripts equivs config-package-dev debhelper-compat golang curl
git clone -b v1.16.0 https://github.com/google/android-cuttlefish
cd android-cuttlefish
tools/buildutils/build_packages.sh
dpkg -i ./cuttlefish-base_*_*64.deb || sudo apt-get install -y -f
dpkg -i ./cuttlefish-user_*_*64.deb || sudo apt-get install -y -f
usermod -aG kvm,cvdnetwork,render root
reboot
```

## Generic System Images (GSI)

### Checkout GSI source

The GSI source checkout is close to 90 GB, and the build can take up about 300 GB of disk space.

Command:
``` bash
mkdir android13-gsi
cd android13-gsi
repo init -u https://android.googlesource.com/platform/manifest -b android13-gsi
repo sync -c
```

### Build GSI

Refresh the build environment and select the build target:

Command:
``` bash
source build/envsetup.sh
lunch aosp_cf_x86_64_phone-userdebug
```

The output should be as follows (may vary depending on the host):

``` text
============================================
PLATFORM_VERSION_CODENAME=REL
PLATFORM_VERSION=13
TARGET_PRODUCT=aosp_cf_x86_64_phone
TARGET_BUILD_VARIANT=userdebug
TARGET_BUILD_TYPE=release
TARGET_ARCH=x86_64
TARGET_ARCH_VARIANT=silvermont
TARGET_2ND_ARCH=x86
TARGET_2ND_ARCH_VARIANT=silvermont
HOST_ARCH=x86_64
HOST_2ND_ARCH=x86
HOST_OS=linux
HOST_OS_EXTRA=Linux-6.8.0-65-generic-x86_64-Ubuntu-22.04.4-LTS
HOST_CROSS_OS=windows
HOST_CROSS_ARCH=x86
HOST_CROSS_2ND_ARCH=x86_64
HOST_BUILD_TYPE=release
BUILD_ID=TP1A.220624.019
OUT_DIR=out
PRODUCT_SOONG_NAMESPACES=device/generic/goldfish-opengl device/generic/goldfish device/generic/goldfish-opengl hardware/google/camera hardware/google/camera/devices/EmulatedCamera device/google/cuttlefish/apex/com.google.cf.wifi_hwsim external/mesa3d vendor/google_devices/common/proprietary/confirmatioui_hal
============================================
```

Start building:

Command:
``` bash
m
```

You can test your setup by launching the virtual device:

Command:
```bash
launch_cvd
```

Open [http://localhost:8443](http://localhost:8443) in your browser, you should see a virtual device. Click `Connect` to interact with it as you would with a real phone. Press `Ctrl-C` in the terminal to stop the simulator.

## Kernel

### Checkout Android Generic Kernel Image (GKI) source

Command:
``` bash
mkdir common-android13-5.15
cd common-android13-5.15
repo init -u https://android.googlesource.com/kernel/manifest -b common-android13-5.15
repo sync -c
```

### Build GKI

We need to build the Android Kernel with KASAN and KCOV so that syzkaller can get coverage and bug information during fuzzing.

Command:
``` bash
BUILD_CONFIG=common/build.config.gki_kasan.x86_64 build/build.sh
```

Build vendor modules with KASAN and KCOV:

Command:
``` bash
BUILD_CONFIG=common-modules/virtual-device/build.config.virtual_device_kasan.x86_64 build/build.sh
```

## syzkaller

### Build syzkaller

Build syzkaller as described [here](/docs/linux/setup.md#go-and-syzkaller).
Then create a manager config like the following, replacing the environment
variables `$GOPATH` and `$GKI` with their actual values.

``` json
{
	"target": "linux/amd64",
	"http": "127.0.0.1:56741",
	"workdir": "$GOPATH/src/github.com/google/syzkaller/workdir/android/out",
	"kernel_obj": "$GKI/out/android13-5.15/dist",
	"syzkaller": "$GOPATH/src/github.com/google/syzkaller",
	"cover": true,
	"type": "adb",
	"vm": {
		"devices": ["0.0.0.0:6520"],
		"battery_check": true
	}
}
```

### Launch the virtual device

Launch the Android system with the KASAN and KCOV kernel.

Command:
``` bash
cd $GSI
source build/envsetup.sh
lunch aosp_cf_x86_64_phone-userdebug
launch_cvd -daemon -kernel_path=$GKI/out/android13-5.15/dist/bzImage -initramfs_path=$GKI/out/android13-5.15/dist/initramfs.img
```

Connect to the virtual device with adb:

Command:
``` bash
adb connect 0.0.0.0:6520
```

List available virtual devices:

Command:
``` bash
adb devices
```

### Run syzkaller

Run syzkaller manager:

Command:
```bash
cd $GOPATH/src/github.com/google/syzkaller
./bin/syz-manager -config=android.cfg
```

Now syzkaller should be running, you can check manager status with your web browser at `127.0.0.1:56741`.

If you get issues after `syz-manager` starts, consider running it with the `-debug` flag.

Here are some useful links:

- [github - google/android-cuttlefish](https://github.com/google/android-cuttlefish)
- [AOSP - Cuttlefish virtual Android devices](https://source.android.com/docs/devices/cuttlefish)
- [AOSP - Cuttlefish: Get started](https://source.android.com/docs/devices/cuttlefish/get-started)
- [AOSP - Download the Android source](https://source.android.com/docs/setup/download)
- [AOSP - Build Android](https://source.android.com/docs/setup/build/building)
- [AOSP - Generic system images](https://source.android.com/docs/core/tests/vts/gsi#building-gsis)
- [AOSP - Architecture overview](https://source.android.com/docs/core/architecture)
- [AOSP - Build kernels](https://source.android.com/docs/setup/build/building-kernels)
- [AOSP - Kernel branches and their build systems](https://source.android.com/docs/setup/reference/bazel-support)