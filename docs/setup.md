# How to install syzkaller

Generic setup instructions are outlined [here](setup_generic.md).
Instructions for a particular VM or kernel arch can be found on these pages:

- [Setup: Ubuntu host, QEMU vm, x86-64 kernel](setup_ubuntu-host_qemu-vm_x86-64-kernel.md)
- [Setup: Ubuntu host, Odroid C2 board, arm64 kernel](setup_ubuntu-host_odroid-c2-board_arm64-kernel.md)
- [Setup: Linux host, QEMU vm, arm64 kernel](setup_linux-host_qemu-vm_arm64-kernel.md)
- [Setup: Linux host, Android device, arm64 kernel](setup_linux-host_android-device_arm64-kernel.md)
- [Setup: Linux isolated host](setup_linux-host_isolated.md)

After following these instructions you should be able to run `syz-manager`, see it executing programs and be able to access statistics exposed at `http://127.0.0.1:56741`:

```
$ ./bin/syz-manager -config=my.cfg
2017/06/14 16:39:05 loading corpus...
2017/06/14 16:39:05 loaded 0 programs (0 total, 0 deleted)
2017/06/14 16:39:05 serving http on http://127.0.0.1:56741
2017/06/14 16:39:05 serving rpc on tcp://127.0.0.1:34918
2017/06/14 16:39:05 booting test machines...
2017/06/14 16:39:05 wait for the connection from test machine...
2017/06/14 16:39:59 received first connection from test machine vm-9
2017/06/14 16:40:05 executed programs: 9, crashes: 0
2017/06/14 16:40:15 executed programs: 13, crashes: 0
2017/06/14 16:40:25 executed programs: 15042, crashes: 0
2017/06/14 16:40:35 executed programs: 24391, crashes: 0
```

More information on the configuration file format is available [here](configuration.md).

See [this page](troubleshooting.md) for troubleshooting tips.
