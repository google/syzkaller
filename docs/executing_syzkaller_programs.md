# Executing syzkaller programs

This page describes how to execute existing syzkaller programs for the purpose
of bug reproduction. This way you can replay a single program or a whole
execution log with several programs.

1. Setup Go toolchain (if you don't yet have it, you need version 1.16 or higher):
Download latest Go distribution from (https://golang.org/dl/). Unpack it to `$HOME/goroot`.
``` bash
export GOROOT=$HOME/goroot
export GOPATH=$HOME/gopath
```

2. Download syzkaller sources:
``` bash
git clone https://github.com/google/syzkaller
```

Note that your syzkaller revision must be the same as the one that generated the
program you're trying to execute.

3. Build necessary syzkaller binaries:
``` bash
cd syzkaller
make
```

4. Copy binaries and the program to test machine (substitute target `linux_amd64`
as necessary):
``` bash
scp -P 10022 -i stretch.img.key bin/linux_amd64/syz-execprog bin/linux_amd64/syz-executor program root@localhost:
```

5. Run the program on the test machine:
``` bash
./syz-execprog -repeat=0 -procs=8 program
```

Several useful `syz-execprog` flags:
```
  -procs int
    	number of parallel processes to execute programs (default 1)
  -repeat int
    	repeat execution that many times (0 for infinite loop) (default 1)
  -sandbox string
    	sandbox for fuzzing (none/setuid/namespace) (default "setuid")
  -threaded
    	use threaded mode in executor (default true)
```

If you pass `-threaded=0`, programs will be executed as a simple single-threaded
sequence of syscalls. `-threaded=1` forces execution of each syscall in a
separate thread, so that execution can proceed over blocking syscalls.

Older syzkaller versions also had the following flag:
```
  -collide
    	collide syscalls to provoke data races (default true)
```
`-collide=1` forced second round of execution of syscalls when pairs of syscalls
are executed concurrently. You might need to use this flag if you're running an
old reproducer.


If you are replaying a reproducer program that contains a header along the
following lines:
```
# {Threaded:true Repeat:true RepeatTimes:0 Procs:8 Slowdown:1 Sandbox:none Leak:false NetInjection:true NetDevices:true NetReset:true Cgroups:true BinfmtMisc:true CloseFDs:true KCSAN:false DevlinkPCI:false USB:true VhciInjection:true Wifi:true IEEE802154:true Sysctl:true UseTmpDir:true HandleSegv:true Repro:false Trace:false LegacyOptions:{Collide:false Fault:false FaultCall:0 FaultNth:0}}
```
then you need to adjust `syz-execprog` flags based on the values in the
header. Namely, `Threaded`/`Procs`/`Sandbox` directly relate to
`-threaded`/`-procs`/`-sandbox` flags. If `Repeat` is set to `true`, add
`-repeat=0` flag to `syz-execprog`.
