# Adding new OS support

Here are the common parts of syzkaller to edit in order to make syzkaller support a new OS kernel. However, there may be some specific changes that will be required for a given kernel (for example, gathering coverage from a given kernel, or some errors that might pop up and give a hint about what to tweak).

## syz-executor

For each OS, there is this file `executor/executor_GOOS.h` where GOOS is the OS name. This file contains two important functions:

- `os_init` which is responsible for mapping a virtual address space for the calling process,
- `execute_syscall` which is responsible for executing system calls for a particular OS kernel.

These two functions, are called in `executor/executor.cc`, which is mainly responsible for executing the syscalls programs, and managing the threads in which the programs run.

`executor_GOOS.h` also contains functions related to that operating system such as functions that allow it to gather coverage information, detect bitness, etc. (Example: [executor_linux.h](/executor/executor_linux.h) ).

The intended function will be called according to the target kernel as defined by the macros in the `executor/executor.cc` file.

## Build files `pkg/`

- The OS name is added to `pkg/build/build.go` along with the supported architecture
- Creating a file that builds the image for the targeted kernel under `pkg/build/`. This file contains functions for configuring the build of the bootable image, for building it, and for generate SSH keys which will be used by Syzkaller in order to access the VM. There is a file per each of the supported OSes by Syzkaller where the name pattern is `GOOS.go`.

- Adding the given target to the `s/makefile/Makefile/`.

## Report files `pkg/report/`

Creating a file that reports build errors  for the targeted kernel under `pkg/report/`. There is a file per each of the supported OSes by Syzkaller where the name pattern is `GOOS.go`.

## Editing `pkg/host/`

- implement `isSupported` function that returns true for a supported syscall, it is located under `pkg/host/GOOS`.

## Creating a file under `sys/GOOS/`

Creating a file `init.go` for the targeted kernel under `sys/GOOS/`that included the function `initTarget` that initializes the target and the different supported architectures.

## Editing `sys/syz-extract`

Adding the new kernel name with already existing supported kernels to the file `sys/syz-extract/extract.go`.

## Editing `sys/targets`

Adding the new kernel name with already existing supported kernels to the file `targets.go` which is located under`sys/targets`.

## Editing `vm/qemu`

Adding the new kernel name with already existing supported kernels to the file `qemo.go` which is located under `vm/qemu`.

## Syzkaller description & pseudo-syscalls

Check [descriptions](/docs/syscall_descriptions.md), and [pseudo-syscalls](/docs/pseudo_syscalls.md).
