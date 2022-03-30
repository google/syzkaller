# Extending syzkaller

Here are the common files and some general edits that need to be made in order to extend syzkaller for a new OS kernel. However, there are some specific changes that may be required for a given kernel (For example gathering coverage from a given kernel, or some errors that might pop up and give a hint about what to tweak).

## First general file

`executor/executor.cc`

This file is mainly responsible for executing the syscalls programs, and managing the
threads in which the programs run. It also contains the `init_os` function which is responsible for mapping a virtual address space for the calling process, and “execute_syscall” which is responsible for executing system calls for a particular OS kernel. `init_os`and `execute_syscall` are implemented in files in which their names follow a pattern `executor_os_name.h` where os_name can be linux, fuschia, windows, karos, etc.

`executor_os_name.h` also contains functions related to that operating system such as functions that allow it to gather coverage information, detect bitness, etc. (Example: [executor_linux.h](/executor/executor_linux.h) ).

The intended function will be called according to the target as defined by the macros in the “executor.cc” file.

## Build files

- The OS name is added to `pkg/build/build.go` along with the supported architecture
- Creating a file that builds the image for the targeted kernel under `pkg/build/`. There is a file per each of the supported OSes by Syzkaller where the name pattern is `os_name.go`.

- Adding the given target to the `makefile`.

## Other needed edits

- implement `isSupported` function that returns true for a supported syscall, it is located under `pkg/host/host_os_name`.

- Creating a file “init.go” for the targeted kernel under `sys/os_name/`that included the function `initTarget` that initializes the target and the different supported architectures.
Creating a file that reports build errors  for the targeted kernel under `pkg/report/`. There is a file per each of the supported OSes by Syzkaller where the name pattern is `os_name.go`.


- Adding the new kernel name with already existing supported kernels to the file `extract.go` which is located under `sys/syz-extract`.

- Adding the new kernel name with already existing supported kernels to the file `targets.go` which is located under`“sys/targets`.

- Adding the new kernel name with already existing supported kernels to the file `qemo.go` which is located under `vm/qemu`.

## Syzkaller description & pseudo-syscalls

Check [descriptions](/docs/syscall_descriptions.md), and [pseudo-syscalls](/docs/pseudo_syscalls.md).
