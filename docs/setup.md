# How to set up syzkaller

Generic setup instructions for fuzzing Linux kernel are outlined [here](linux/setup.md).

For other kernels see:
[Akaros](akaros/README.md),
[FreeBSD](freebsd/README.md),
[Fuchsia](fuchsia/README.md),
[NetBSD](netbsd/README.md),
[OpenBSD](openbsd/setup.md),
[Windows](windows/README.md).

After following these instructions you should be able to run `syz-manager`, see it executing programs, and be able to access statistics exposed at `http://127.0.0.1:56741` (or whatever address you've specified in the manager config).
If everything is working properly, a typical execution log would look like:

```
$ ./bin/syz-manager -config=my.cfg
2017/06/14 16:39:05 loading corpus...
2017/06/14 16:39:05 loaded 0 programs (0 total, 0 deleted)
2017/06/14 16:39:05 serving http on http://127.0.0.1:56741
2017/06/14 16:39:05 serving rpc on tcp://127.0.0.1:34918
2017/06/14 16:39:05 booting test machines...
2017/06/14 16:39:05 wait for the connection from test machine...
2017/06/14 16:39:59 received first connection from test machine vm-9
2017/06/14 16:40:05 executed 293, cover 43260, crashes 0, repro 0
2017/06/14 16:40:15 executed 5992, cover 88463, crashes 0, repro 0
2017/06/14 16:40:25 executed 10959, cover 116991, crashes 0, repro 0
2017/06/14 16:40:35 executed 15504, cover 132403, crashes 0, repro 0
```

At this point it's important to ensure that syzkaller is able to collect code coverage of the executed programs
(unless you specified `"cover": false` in the config or coverage is not yet supported for the kernel you're fuzzing).
The `cover` counter on the web page should be non zero.

More information on the configuration file format is available [here](configuration.md).

See [this page](troubleshooting.md) for troubleshooting tips.
