# Kaspersky OS support

Kaspersky OS Community Edition is available
[here](https://os.kaspersky.com/download-community-edition/).

KasperskyOS Community Edition is distributed as a DEB package that you will need to install
(follow the instructions on the
[Getting started](https://support.kaspersky.com/help/KCE/1.0/en-US/getting_started.htm) page.


In the instructions below, the $VAR notation (e.g. $GCC, $KERNEL, etc.)
is used to denote paths to directories:

- $KERNEL: Kaspersky OS kernel image directory
- $KOSPATH: Installation path of Kaspersky OS (/opt/KasperskyOS-Community-Edition-{version})
- $SYZKALLER: Syzkaller directory

## Build Kaspersky OS image

### 1. Create a directory to build Kaspersky OS image

```bash
$ mkdir $IMAGE && cd $IMAGE
```

### 2. Create the files from `$SYZKALLER/executor/kos` folder into `$IMAGE` folder
TODO: (discuss better place to store initial files to build kos kernel image)

```bash
$ cp $SYZKALLER/executor/kos/* .
```

### 3. Build the Einit entity
In  KasperskyOS processe are called entities.
Einit is one of the most important entities in KasperskyOS.
It's the first entity started by the operating system kernel when the
image is loaded and it starts all other entities included in the
solution, which means that it serves as the initializing entity.

Generate the code of the Einit entity in C
```bash
$ einit -I $KOSPATH/sysroot-arm-kos/include \
-I $KOSPATH/toolchain/arm-kos/include \
-I $KOSPATH/toolchain/include \
-I . -o einit.c init.yaml
```

A file named `einit.c` will be generated.

Compile the `einit.c` file into the executable file of the Einit entity
```bash
$ arm-kos-gcc einit.c -o Einit
```

### 4. Build syz-executor for Kaspersky OS

TODO: when executor for kos is implemented

### 5. Build Kaspersky OS qemu image with executor binary

The following command builds Kaspersky OS qemu image with Einit and Executor entities:
```bash
$ makeimg \
 --target=arm-kos --sys-root=$KOSPATH/sysroot-arm-kos \
 --with-toolchain=$KOSPATH/toolchain \
 --ldscript=$KOSPATH/sysroot-arm-kos/../libexec/arm-kos/kos-qemu.ld \
 --img-src=$KOSPATH/sysroot-arm-kos/../libexec/arm-kos/kos-qemu \
 --with-init=Einit \
 --img-dst=kos-image \
 /path/to/executor
```

## Build syzkaller for Kaspersky OS

```bash
$ make TARGETOS=kos TARGETARCH=arm64
```
