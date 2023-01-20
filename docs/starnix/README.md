# starnix support

## Prerequisites

To run syzkaller for fuzzing starnix, you will need a checkout of the Fuchsia
source repository.

The rest of this document will use the environment variable `SOURCEDIR` to
identify the path to your Fuchsia checkout (e.g. `/home/you/fuchsia`). The
commands below assume you have set `SOURCEDIR`, like so:

```bash
export SOURCEDIR=/home/you/fuchsia
```

To build Fuchsia for qemu-x64, run:
```
fx --dir "out/qemu-x64" set workstation_eng.qemu-x64 \
  --with "//bundles/tools" \
  --with "//src/proc/bin/starnix"
fx build
```

You will also need to follow the instructions in the sections `GCC` and `Kernel`
of the [setup\_ubuntu-host\_qemu-vm\_x86-64-kernel.md](../linux/setup_ubuntu-host_qemu-vm_x86-64-kernel.md) file.


## syzkaller

### Building binaries for starnix
First, you need to build all the binaries required for running syzkaller in starnix.
For that, you only need to run this from inside your syzkaller checkout (assuming you built Fuchsia for x64):

```bash
SYZ_STARNIX_HACK=1 make TARGETOS=linux TARGETARCH=amd64
```

### Configuration file
Create a manager config like the following, replacing the environment variables `$SYZKALLER`, `$KERNEL` and `$IMAGE` with their actual values.

> **_NOTE:_**  `ffx` is still under development, for that reason VM count of 1 is recommended until fxbug.dev/118926 is solved.

```bash
{
    "target": "linux/amd64",
    "http": "127.0.0.1:56741",
    "workdir": "$SYZKALLER/workdir",
    "kernel_obj": "$KERNEL",
    "kernel_src": "$SOURCEDIR",
    "syzkaller": "$SYZKALLER",
    "procs": 8,
    "type": "starnix",
    "vm": {
        "count": 1
    },
    "cover": false
}
```

### Running

Lastly, just run the command below to start fuzzing.

```bash
SYZ_STARNIX_HACK=1 bin/syz-manager -config=./starnix.cfg
```
