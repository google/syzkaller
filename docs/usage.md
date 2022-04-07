# How to use syzkaller

## Running

Start the `syz-manager` process as:
```
./bin/syz-manager -config my.cfg
```

The `syz-manager` process will wind up VMs and start fuzzing in them.
The `-config` command line option gives the location of the configuration file, which is described [here](configuration.md).
Found crashes, statistics and other information is exposed on the HTTP address specified in the manager config.

## Crashes

Once syzkaller detected a kernel crash in one of the VMs, it will automatically start the process of reproducing this crash (unless you specified `"reproduce": false` in the config).
By default it will use 4 VMs to reproduce the crash and then minimize the program that caused it.
This may stop the fuzzing, since all of the VMs might be busy reproducing detected crashes.

The process of reproducing one crash may take from a few minutes up to an hour depending on whether the crash is easily reproducible or non-reproducible at all.
Since this process is not perfect, there's a way to try to manually reproduce the crash, as described [here](reproducing_crashes.md).

If a reproducer is successfully found, it can be generated in one of the two forms: syzkaller program or C program.
Syzkaller always tries to generate a more user-friendly C reproducer, but sometimes fails for various reasons (for example slightly different timings).
In case syzkaller only generated a syzkaller program, there's [a way to execute them](reproducing_crashes.md) to reproduce and debug the crash manually.

## Hub

In case you're running multiple `syz-manager` instances, there's a way to connect them together and allow to exchange programs and reproducers, see the details [here](hub.md).

## Reporting bugs

Check [here](linux/reporting_kernel_bugs.md) for the instructions on how to report Linux kernel bugs.
