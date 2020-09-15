# Coverage

Syzkaller uses [kcov](https://www.kernel.org/doc/html/latest/dev-tools/kcov.html) to collect coverage from the kernel. kcov exports the address of each executed basic block, and syzkaller runtime uses tools from `binutils` (`objdump`, `nm`, `addr2line` and `readelf`) to map these addresses to lines and functions in the source code.

## Binutils

Note that if you are fuzzing in cross-arch environment you need to provide correct `binutils` cross-tools to syzkaller before starting `syz-manager`:

``` bash
mkdir -p ~/bin/mips64le
ln -s `which mips64el-linux-gnuabi64-addr2line` ~/bin/mips64le/addr2line
ln -s `which mips64el-linux-gnuabi64-nm` ~/bin/mips64le/nm
ln -s `which mips64el-linux-gnuabi64-objdump` ~/bin/mips64le/objdump
ln -s `which mips64el-linux-gnuabi64-readelf` ~/bin/mips64le/readelf
export PATH=~/bin/mips64le:$PATH
```

The target-triple prefix is determined based on the `target` config option.

### readelf

`readelf` is used to detect virtual memory offset.

```
readelf -SW kernel_image
```

The meaning of the flags is as follows:

* `-S' - list section headers in the kernel image file
* `-W' - output each section header entry in a single line

Example output of the command:

```
There are 59 section headers, starting at offset 0x3825258:

Section Headers:
  [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            0000000000000000 000000 000000 00      0   0  0
  [ 1] .text             PROGBITS        ffffffff81000000 200000 e010f7 00  AX  0   0 4096
  [ 2] .rela.text        RELA            0000000000000000 23ff488 684720 18   I 56   1  8
  [ 3] .rodata           PROGBITS        ffffffff82000000 1200000 2df790 00  WA  0   0 4096
  [ 4] .rela.rodata      RELA            0000000000000000 2a83ba8 0d8e28 18   I 56   3  8
  [ 5] .pci_fixup        PROGBITS        ffffffff822df790 14df790 003180 00   A  0   0 16
  [ 6] .rela.pci_fixup   RELA            0000000000000000 2b5c9d0 004a40 18   I 56   5  8
  [ 7] .tracedata        PROGBITS        ffffffff822e2910 14e2910 000078 00   A  0   0  1
  [ 8] .rela.tracedata   RELA            0000000000000000 2b61410 000120 18   I 56   7  8
  [ 9] __ksymtab         PROGBITS        ffffffff822e2988 14e2988 011b68 00   A  0   0  4
  [10] ...
```

Executor truncates PC values into `uint32` before sending them to `syz-manager` and `syz-manager` uses section header information to recover the offset. Only the section headers of type `PROGBITS` are considered. The `Address` field represents the virtual address of a section in memory (for the sections that are loaded). It is required that all `PROGBITS` sections have same upper 32 bits in the `Address` field. These 32 bits are used as recovery offset.


## Reporting coverage data

`MakeReportGenerator` factory creates an object database for the report. It requires target data, as well as information on the location of the source files and build directory. The first step in building this database is
extracting the function data from the target binary.
### nm

`nm` is used to parse address and size of each function in the kernel image

```
nm -Ptx kernel_image
```

The meaning of the flags is as follows:

* `-P` - use the portable output format (Standard Output)
* `-tx` - write the numeric values in the hex format

Output is of the following form:

```
tracepoint_module_nb d ffffffff84509580 0000000000000018
...
udp_lib_hash t ffffffff831a4660 0000000000000007
```

The first column is a symbol name and the second column is its type (e.g. text section, data section, debugging symbol, undefined, zero-init section, etc.). The third column is the symbol value in hex format while the forth column contains its size. The size is always rounded to up to 16 in syzkaller. For the report, we are only interested in the code sections so the `nm` output is filtered for the symbols with type `t` or `T`.
The final result is a map with symbol names as keys, values being starting and ending address of a symbol. This information is used to map coverage data to symbols (functions). This step is needed to find out whether certain functions are called at all.

## Object Dump and Symbolize

In order to provide the necessary information for tracking the coverage information with syzkaller, the compiler is instrumented to insert the `__sanitizer_cov_trace_pc` call into every basic block generated during the build process. These instructions are then used as anchor points to backtrack the covered code lines.

### objdump

`objdump` is used to parse PC value of each call to `__sanitizer_cov_trace_pc` in the kernel image. These PC values are representing all code that is built into kernel image. PC values exported by kcov are compared against these to determine coverage.

The kernel image is disassembled using the following command:

```
objdump -d --no-show-raw-insn kernel_image
```

The meaning of the flags is as follows:

* `-d` - disassemble executable code blocks
* `-no-show-raw-insn` - prevent printing hex alongside symbolic disassembly

Excerpt output looks like this:

```
...
ffffffff81000f41:	callq  ffffffff81382a00 <__sanitizer_cov_trace_pc>
ffffffff81000f46:	lea    -0x80(%r13),%rdx
ffffffff81000f4a:	lea    -0x40(%r13),%rsi
ffffffff81000f4e:	mov    $0x1c,%edi
ffffffff81000f53:	callq  ffffffff813ed680 <perf_trace_buf_alloc>
ffffffff81000f58:	test   %rax,%rax
ffffffff81000f5b:	je     ffffffff8100110e <perf_trace_initcall_finish+0x2ae>
ffffffff81000f61:	mov    %rax,-0xd8(%rbp)
ffffffff81000f68:	callq  ffffffff81382a00 <__sanitizer_cov_trace_pc>
ffffffff81000f6d:	mov    -0x40(%r13),%rdx
ffffffff81000f71:	mov    0x8(%rbp),%rsi
...
```

From this output coverage trace calls are identified to determine the start of the executable block addresses:

```
ffffffff81000f41:	callq  ffffffff81382a00 <__sanitizer_cov_trace_pc>
ffffffff81000f68:	callq  ffffffff81382a00 <__sanitizer_cov_trace_pc>
```

### addr2line

`addr2line` is used for mapping PC values exported by kcov and parsed by `objdump` to source code files and lines.

```
addr2line -afi -e kernel_image
```

The meaning of the flags is as follows:

* `-afi` - means show addresses, function names and unwind inlined functions
* `-e` - is switch for specifying executable instead of using default

`addr2line` reads hexadecimal addresses from standard input and prints the filename
function and line number for each address on standard output. Example usage:

```
>> ffffffff8148ba08
<< 0xffffffff8148ba08
<< generic_file_read_iter
<< /home/user/linux/mm/filemap.c:2363
```

where `>>` represents the query and `<<` is the response from the `addr2line`.

The final goal is to have a hash table of frames where key is a program counter
and value is a frame array consisting of a following information:

* `PC` - 64bit program counter value (same as key)
* `Func` - function name to which the frame belongs
* `File` - file where function/frame code is located
* `Line` - Line in a file to which program counter maps
* `Inline` - boolean inlining information

Multiple frames can be linked to a single program counter value due to inlining.

## Creating report

Once the database of the frames and function address ranges is created the next step is to determine the program coverage. Each program is represented here as a series of program counter values. As the function address ranges are known at this point it is easy to determine which functions were called by simply comparing the program counters against these address intervals. In addition, the coverage information is aggregated over the source files based on the program counters that are keys in the frame hash map. These are marked as `coveredPCs`. The resulting coverage is not line based but the basic block based. The end result is stored in the `file` struct containing the following information:

* `lines` - lines covered in the file
* `totalPCs` - total program counters identified for this file
* `coveredPCs` - the program counters that were executed in the program run
* `totalInline` - total number of program counters mapped to inlined frames
* `coveredInline` - the program counters mapped to inlined frames that were executed in the program run
