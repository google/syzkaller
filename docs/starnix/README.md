# Starnix support

## Prerequisites

To run Syzkaller with a Starnix target, you will need a checkout of the Fuchsia
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

You will also need to follow the instructions in the sections `GCC` and `Kernel` of the [setup\_ubuntu-host\_qemu-vm\_x86-64-kernel.md](../linux/setup_ubuntu-host_qemu-vm_x86-64-kernel.md) file.


## Syzkaller

### Building binaries for Starnix
First, you need to build all the binaries required for running Syzkaller in Starnix. For that, you only need to run this from inside your Syzkaller checkout (assuming you built Fuchsia for x64):

```bash
make TARGETOS=starnix TARGETARCH=amd64
```

### Configuration file
Create a manager config like the following, replacing the environment variables `$SYZKALLER`, `$KERNEL` and `$IMAGE` with their actual values.

> **_NOTE:_**  Starnix support is still under development, for that reason VM count of 1 is recommended for now

```bash
{
    "target": "starnix/amd64",
    "http": "127.0.0.1:56741",
    "workdir": "$SYZKALLER/workdir",
    "kernel_obj": "$KERNEL",
    "syzkaller": "$SYZKALLER",
    "procs": 8,
    "type": "starnix",
    "vm": {
        "count": 1,
        "fuchsia": "$SOURCEDIR"
    },
    "cover": false
}
```

### Running

Lastly, just run the command below to start fuzzing. 

```bash
bin/syz-manager -config=./starnix.cfg
```
