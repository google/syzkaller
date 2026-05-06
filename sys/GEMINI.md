## Prerequisites

Syzkaller uses a special DSL called syzlang to express kernel interfaces.
Consult docs/syscall_descriptions.md and docs/syscall_descriptions_syntax.md
to learn more details.

The descriptions are located in sys/OS_NAME/ directories.
* Descriptions themselves are in .txt files.
* .txt.const files are generated from .txt files by running `make extract`.

## Writing descriptions for Linux

First ensure that you are given a path to a Linux kernel checkout.
We strive to write descriptions based on the latest linux-next tag.

When adding new syscalls and structures, try to follow the style
of existing descriptions. In particular, try to use existing types
and flags when possible.

First, find the definitions of syscalls and their arguments in the
kernel source code.
* DO NOT rely on the syscalls(7) man page, it is often outdated.
* DO NOT search for syscall definitions on the internet.
* DO grep kernel source code, especially the include/uapi folder.

Then, find the right file to add new descriptions. In many cases,
you will find such a file by looking at where related system calls
are described.
* IMPORTANT: DO NOT create new files unless absolutely necessary.
  Often, you can put the descriptions to more generic files.

For integer fields that look like bitmasks, try to find the flags
they could take and define them as flags in syzlang, listing all
possible const names. Note that sometimes you might have to add an
include directive. Look for inspiration to other .txt files in sys/linux.

For integer fiels that look like file handles, try to find more details
about them and see whether they can be defined as resources. Try to find
existing resources in sys/linux/ that can be used, most likely they are
already there.

If the integer field is used for padding, ensure that you define it as const.

For other integer fields, explore how they are used in the Linux kernel source
code to see whether there are clear indications of the range of values they are
supposed to take.

After adding descriptions, you should run `make extract` to extract
the newly introduced constants into the `sys/linux/` directory.

It should only be run on latest `linux-next` tag this way:
`$ CI=true ./tools/syz-env make extract SOURCEDIR=$PATH_TO_LINUX_CHECKOUT`

If `make extract` fails, it might indicate that you are missing some includes.

At the end, help the user review the results by indicating the locations
in the Linux kernel source code where the new syscalls and structures
were found.

## Testing

Then, run `make generate` to verify that the descriptions are correct.

Also, do not forget to run `make format` to ensure that the descriptions
are formatted correctly.

Remember that these commands must be run inside of the syzkaller checkout.
