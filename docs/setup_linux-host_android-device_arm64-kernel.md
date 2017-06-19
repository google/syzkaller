# Setup: Linux host, Android device, arm64 kernel

Prerequisites:
 - go1.8+ toolchain (can be downloaded from [here](https://golang.org/dl/))
 - Android NDK (tested with r12b) (can be downloaded from [here](https://developer.android.com/ndk/downloads/index.html))
 - Android Serial Cable or [Suzy-Q](https://chromium.googlesource.com/chromiumos/platform/ec/+/master/docs/case_closed_debugging.md) device to capture console output is preferable but optional. syzkaller can work with normal USB cable as well, but that can be somewhat unreliable and turn lots of crashes into "lost connection to test machine" crashes with no additional info.

From `syzkaller` checkout:
 - Build `syz-manager` for host:
```
go build -o bin/syz-manager ./syz-manager
```

 - Build `syz-fuzzer` and `syz-execprog` for arm64:
```
GOARCH=arm64 go build -o bin/syz-fuzzer ./syz-fuzzer
GOARCH=arm64 go build -o bin/syz-execprog ./tools/syz-execprog
```

 - Build `syz-executor` for arm64:
```
/android-ndk-r12b/toolchains/aarch64-linux-android-4.9/prebuilt/linux-x86_64/bin/aarch64-linux-android-g++ \
  -I/android-ndk-r12b/sources/cxx-stl/llvm-libc++/libcxx/include \
  --sysroot=/android-ndk-r12b/platforms/android-22/arch-arm64 \
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
