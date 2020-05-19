# How to reproduce crashes

The process of creating reproducer programs for syzkaller bugs is automated, however it's not perfect, so syzkaller provides a few tools for executing and reproducing programs manually.

Crash logs created in manager `workdir/crashes` dir contain programs executed just before a crash. In parallel execution mode (when `procs` parameter in manager config is set to value larger than 1), program that caused the crash does not necessary immediately precedes it; the guilty program can be somewhere before.
There are two tools that can help you identify and minimize the program that causes a crash: `tools/syz-execprog` and `tools/syz-prog2c`.

`tools/syz-execprog` executes a single syzkaller program or a set of programs in various modes (once or loop indefinitely; in threaded/collide mode (see below), with or without coverage collection). You can start by running all programs in the crash log in a loop to check that at least one of them indeed crashes kernel: `./syz-execprog -executor=./syz-executor -repeat=0 -procs=16 -cover=0 crash-log`. Then try to identify the single program that causes the crash, you can test programs with `./syz-execprog -executor=./syz-executor -repeat=0 -procs=16 -cover=0 file-with-a-single-program`.

Note: `syz-execprog` executes programs locally. So you need to copy `syz-execprog` and `syz-executor` into a VM with the test kernel and run it there.

Once you have a single program that causes the crash, try to minimize it by removing individual syscalls from the program (you can comment out single lines with `#` at the beginning of line), and by removing unnecessary data (e.g. replacing `&(0x7f0000001000)="73656c6600"` syscall argument with `&(0x7f0000001000)=nil`). You can also try to coalesce all mmap calls into a single mmap call that maps whole required area. Again, test minimization with `syz-execprog` tool.

Now that you have a minimized program, check if the crash still reproduces with `./syz-execprog -threaded=0 -collide=0` flags. If not, then you will need to do some additional work later.

Now, run `syz-prog2c` tool on the program. It will give you executable C source. If the crash reproduces with `-threaded/collide=0` flags, then this C program should cause the crash as well.

If the crash is not reproducible with `-threaded/collide=0` flags, then you need this last step. You can think of threaded/collide mode as if each syscall is executed in its own thread. To mode such execution mode, move individual syscalls into separate threads. You can see an example here: https://groups.google.com/d/msg/syzkaller/fHZ42YrQM-Y/Z4Xf-BbUDgAJ.

This process is automated to some degree in the `syz-repro` utility. You need to give it your manager config and a crash report file. And you can refer to the [example config file](/pkg/mgrconfig/testdata/qemu.cfg).
```
./syz-repro -config my.cfg crash-qemu-1-1455745459265726910
```
It will try to find the offending program and minimize it. But since there are lots of factors that can affect reproducibility, it does not always work.
