# Executing syzkaller programs

This page describes how to execute existing syzkaller programs for the purpose of bug reproduction. This way you can replay a single program or a whole execution log with several programs.

1. Setup Go toolchain (if you don't yet have it, you need version 1.8 or higher):
Download latest Go distribution from (https://golang.org/dl/). Unpack it to `$HOME/go1.8`.
``` bash
$ export GOROOT=$HOME/go1.8
$ export GOPATH=$HOME/gopath
```

2. Download syzkaller sources:
``` bash
$ go get -u -d github.com/google/syzkaller/...
```

3. Build necessary syzkaller binaries:
``` bash
$ cd $GOPATH/src/github.com/google/syzkaller
$ make
```

4. Copy binaries and the program to test machine:
``` bash
$ scp bin/syz-execprog bin/syz-executor program test@machine
```

5. Run the program on the test machine:
``` bash
$ ./syz-execprog -executor ./syz-executor -cover=0 -repeat=0 -procs=16 program
```

Several useful `syz-execprog` flags:
```
  -collide
    	collide syscalls to provoke data races (default true)
  -procs int
    	number of parallel processes to execute programs (default 1)
  -repeat int
    	repeat execution that many times (0 for infinite loop) (default 1)
  -sandbox string
    	sandbox for fuzzing (none/setuid/namespace) (default "setuid")
  -threaded
    	use threaded mode in executor (default true)
```

If you pass `-threaded=0 -collide=0`, programs will be executed as a simple single-threaded sequence of syscalls. `-threaded=1` forces execution of each syscall in a separate thread, so that execution can proceed over blocking syscalls. `-collide=0` forces second round of execution of syscalls when pairs of syscalls are executed concurrently.
