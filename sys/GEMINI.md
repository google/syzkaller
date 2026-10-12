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

For integer fields that look like bitmasks or enums, try to find the flags
or enum values they could take and define them as `flags[...]` or `const[...]`
in syzlang, listing the official kernel constant names via an `include <...>`
directive rather than hardcoding magic numbers. Look for inspiration in other
`.txt` files in `sys/linux`.

For integer fields that look like file handles, keys, or object IDs, check
whether they can be defined as `resource`. Try to find existing resources in
`sys/linux/` that can be reused before defining new ones.

If an integer field is used for padding or reserved bytes, define it as `const[0, intN]`.

For other integer fields, explore how they are used in the Linux kernel source
code to see whether there are clear indications of the range of values they are
supposed to take.

### Common Syzlang Pitfalls

* **Struct sizes and `[align[N]]`**: Always verify struct sizes and field offsets
  against the kernel UAPI definitions. Note that `[align[8]]` automatically pads a
  struct's total size to a multiple of 8 bytes *after* all explicit fields—never add
  manual tail padding *and* `[align[8]]` unless the C struct genuinely has both.
* **32-bit vs 64-bit addresses**: Use `vma64` (not `vma`) for `__u64` / `__aligned_u64`
  virtual address fields in UAPI structs so 32-bit targets (`386`, `arm`) preserve
  8-byte field size and alignment.
* **Size annotations (`bytesize`, `bytesize4`, `bytesize8`)**: Check whether the kernel
  expects byte length (`bytesize`), 4-byte words (`bytesize4`), or 8-byte words
  (`bytesize8`), and whether the count covers the `parent` struct or a specific buffer.
* **Endianness**: Little-endian is the default (`int16`, `int32`, `int64`); `int16le` /
  `int32le` do not exist. Use `int16be` / `int32be` / `int64be` for big-endian fields.
* **Do not rely on repeated addresses or random values**: Never design descriptions or
  seed programs that require passing the same hardcoded memory address or random integer
  in multiple places. If the same address or value must be reused across calls or fields,
  model it as a syzlang `resource` (see e.g. `ptr_futex` / `syz_create_resource`) or
  normalize base addresses to `0` (`const[0, int64]`) when the kernel permits 0-based
  offsets.

### Extracting Constants

After adding or updating descriptions, extract the constants into `.txt.const`.
We typically extract constants on the latest `linux-next` tag (ensure
`$PATH_TO_LINUX_CHECKOUT` is checked out at the latest `next-*` tag):

`$ CI=true ./tools/syz-env make extract SOURCEDIR=$PATH_TO_LINUX_CHECKOUT`

To speed up extraction or if `$PATH_TO_LINUX_CHECKOUT` is not on the latest
`linux-next` tag (where unrelated `.txt` files might fail on missing headers),
you can extract **only** the modified `.txt` file across all architectures:

`$ CI=true ./tools/syz-env SOURCEDIR=$PATH_TO_LINUX_CHECKOUT go run ./sys/syz-extract -os linux -sourcedir /syzkaller/kernel -build <file>.txt`

* **IMPORTANT**: Do **not** pass `-arch amd64` to `syz-extract` for a multi-arch `.txt`
  file, as it overwrites `arches = amd64` in `.txt.const` and drops constants for the
  other 8 architectures.

At the end, help the user review the results by indicating the locations
in the Linux kernel source code where the new syscalls and structures
were found.

## Writing Seed Programs (`sys/linux/test/*`)

* **One scenario per seed**: Keep each seed program focused on a single scenario and
  as short as possible (~5–15 calls). Split independent scenarios into separate files.
* **Omit teardown calls**: Do not add trailing `close`, `munmap`, or `DESTROY_*` calls
  unless teardown itself is being tested; keeping resources alive at the end of the seed
  allows fuzzer mutations to append calls that consume them.
* **Use `AUTO` and `&AUTO` extensively**: Use `AUTO` for all `const`, `len`, `bytesize`,
  and default fields, and `&AUTO` for pointers. Never hardcode the same address in
  multiple places—if an address must be shared, turn it into a `resource` in the
  descriptions.
* **Follow `prog.Strict` serialization rules**: `go test ./pkg/runtest -run TestParsing`
  parses all seeds in `Strict` mode across all 9 architectures:
  * `vma` / `vma64` arguments do not support `&AUTO` in the parser (because `vma` has no
    inner element from which to infer the mapping size); write each `vma` with a distinct
    page range such as `&(0x7f0000001000/0x1000)=nil`, `&(0x7f0000002000/0x1000)=nil`, etc.
  * Fixed-size byte or const-padding arrays (`array[int8, N]`, `array[const[0, int32], K]`)
    compile to `BufferType` and must be written as `""/<byte_len>` (e.g., `""/120` for
    `array[const[0, int32], 30]`), not `[]` or `AUTO`.

## Testing

1. Run `CI=true ./tools/syz-env make generate` and `CI=true ./tools/syz-env make format`.
2. Run host unit tests to verify strict parsing and C code generation across all arches:
   * `CI=true ./tools/syz-env go test -count=1 ./pkg/runtest -run TestParsing`
   * `CI=true ./tools/syz-env go test -short ./sys/linux -run Test`
   * `CI=true ./tools/syz-env go test -short ./pkg/csource/...`
3. When a target kernel image (`bzImage`) is available, verify the seed program inside a
   QEMU VM by following the [`syzlang-vm-testing`](../.agents/skills/syzlang-vm-testing/SKILL.md)
   skill.
