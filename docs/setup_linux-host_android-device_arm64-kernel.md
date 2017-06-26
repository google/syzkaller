# Setup: Linux host, Android device, arm64 kernel

Prerequisites:
 - go1.8+ toolchain (can be downloaded from [here](https://golang.org/dl/))
 - Android NDK (tested with r15 on API24) (can be downloaded from [here](https://developer.android.com/ndk/downloads/index.html))
 - Android Serial Cable or [Suzy-Q](https://chromium.googlesource.com/chromiumos/platform/ec/+/master/docs/case_closed_debugging.md) device to capture console output is preferable but optional. syzkaller can work with normal USB cable as well, but that can be somewhat unreliable and turn lots of crashes into "lost connection to test machine" crashes with no additional info.

From `syzkaller` checkout:
 - Build `syz-manager` for host:
```
go build -o bin/syz-manager ./syz-manager
```

 - Build `syz-fuzzer` and `syz-execprog` for arm64:
```
GOOS=linux GOARCH=arm64 go build -o bin/syz-fuzzer ./syz-fuzzer
GOOS=linux GOARCH=arm64 go build -o bin/syz-execprog ./tools/syz-execprog
```

 - Build `syz-executor` for arm64:

```sh
NDK=/path/to/android-ndk-r15
UNAME=$(uname | tr '[:upper:]' '[:lower:]')
TOOLCHAIN=aarch64-linux-android
API=24
ARCH=arm64
$NDK/toolchains/$TOOLCHAIN-4.9/prebuilt/$UNAME-x86_64/bin/$TOOLCHAIN-g++ \
  -I $NDK/sources/cxx-stl/llvm-libc++/include \
  --sysroot=$NDK/platforms/android-$API/arch-$ARCH \
  executor/executor.cc -O1 -g -Wall -static -o bin/syz-executor
```

 - Create config with `"type": "adb"` and specify adb devices to use. For example:
```
{
	"http": "localhost:50000",
	"workdir": "/gopath/src/github.com/google/syzkaller/workdir",
	"syzkaller": "/gopath/src/github.com/google/syzkaller",
	"vmlinux": "-",
	"sandbox": "none",
	"procs": 8,
	"type": "adb",
	"vm": {
		"devices": ["ABCD000010"]
	}
}
```

 - Start `syz-manager -config adb.cfg` as usual.
