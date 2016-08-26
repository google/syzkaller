# Syscall Description

`syzkaller` uses declarative description of syscalls to generate, mutate, minimize,
serialize and deserialize programs (sequences of syscalls). Below you can see
(hopefully self-explanatory) excerpt from the description:

```
open(file filename, flags flags[open_flags], mode flags[open_mode]) fd
read(fd fd, buf buffer[out], count len[buf]) len[buf]
close(fd fd)
open_mode = S_IRUSR, S_IWUSR, S_IXUSR, S_IRGRP, S_IWGRP, S_IXGRP, S_IROTH, S_IWOTH, S_IXOTH
```

The description is contained in `sys/*.txt` files. See for example [sys/sys.txt](sys/sys.txt) file.

## Syntax

Pseudo-formal grammar of syscall description:
```
	syscallname "(" [arg ["," arg]*] ")" [type]
	arg = argname type
	argname = identifier
	type = typename [ "[" type-options "]" ]
	typename = "fd" | "fileoff" | "buffer" | "vma" , "len" | "flags" | "filename" | "ptr" | "array" | "intN" | "intptr"
	type-options = [type-opt ["," type-opt]]
```
common type-options include:
```
	"opt" - the argument is optional (like mmap fd argument, or accept peer argument)
```
rest of the type-options are type-specific:
```
	"fd": file descriptor, type-options: kind of fd (file/sock/pipe/rand) (optional)
	"fileoff": offset within a file, type-options: argname of the file
	"buffer": a pointer to a memory buffer (like read/write buffer argument), type-options: direction (in/out/inout)
	"string": a pointer to a memory buffer, similar to buffer[in]
	"vma": a pointer to a set of pages (used as input for mmap/munmap/mremap/madvise)
	"len": length of buffer/vma/arrayptr (for array it is number of elements), type-options: argname of the object
	"flags": a set of flags, type-options: reference to flags description
	"filename": a file/link/dir name
	"ptr": a pointer to an object, type-options: type of the object; direction (in/out/inout)
	"array": a variable/fixed-length array, type-options: type of elements, optional size for fixed-length arrays
	"intN"/"intptr": an integer without a particular meaning, type-options: range of values (e.g. "5:10", or "-100:200", optional)
```
flags/len/flags also have trailing underlying type type-option when used in structs/unions/pointers.

Flags are described as:
```
	flagname = const ["," const]
```

Structs are described as:
```
	structname "{" "\n"
		(fieldname type "\n")+
	"}"
```
Structs can have trailing attributes "packed" and "align_N",
they are specified in square brackets after the struct.

Unions are described as:
```
	unionname "[" "\n"
		(fieldname type "\n")+
	"]"
```
Unions can have a trailing "varlen" attribute (specified in square brackets after the union),
which means that union length is not maximum of all option lengths,
but rather length of a particular chosen option (such unions can't be part of a struct,
because their size is not statically known).

Description files also contain `include` directives that refer to Linux kernel header files
and `define` directives that define symbolic constant values. See

## Fuzzing new system calls

This section describes how to extend syzkaller to allow fuzz testing of a new system call;
this is particularly useful for kernel developers who are proposing new system calls.

First, add a declarative description of the new system call to the appropriate file:
 - Various `sys/<subsystem>.txt` files hold system calls for particular kernel
   subsystems, for example `bpf` or `socket`.
 - [sys/sys.txt](sys/sys.txt) holds descriptions for more general system calls.
 - An entirely new subsystem can be added as a new `sys/<new>.txt` file, but needs
   the `generate` target in the [Makefile](Makefile) to be updated to include it.

The description format is described [above](#syscall-description) and in the
master [sys/sys.txt](sys/sys.txt) file.

Next, run `make LINUX=$KSRC generate` with `KSRC` set to the location of a kernel
source tree (for up to date kernel headers); if the kernel was built into a separate
directory (with `make O=...`) then also set `LINUXBLD=$KBLD` to the location of the
build directory.

This will re-create the following source code files:
 - `sys/sys.go`: Code to initialize a Go [data structure](sys/decl.go) with information
   about all of the available system calls.
 - `prog/consts.go`: Constant definitions for all the named constants that are
   mentioned in the system call descriptions.
 - `sys/sys_<ARCH>.go`: Data structure to map syzkaller internal syscall IDs to
   (per-architecture) kernel syscall numbers.
 - `executor/syscalls.h`: Constant definitions (in C) for all system call numbers.

If there are problems with this step, run `bin/syz-sysgen` directly and add
the use `-v=5` flag to show more details of the generation process.

Rebuild syzkaller (`make clean all`) to force use of the new system call definitions.

Finally, adjust the `enable_syscalls` configuration value for syzkaller to specifically target the
new system calls.

