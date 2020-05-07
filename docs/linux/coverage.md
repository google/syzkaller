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

### objdump

`objdump` is used to parse PC value of each call to `__sanitizer_cov_trace_pc` in the kernel image. These PC values are representing all code that is built into kernel image. PC values exported by kcov are compared against these to determine coverage.

### nm

`nm` is used to parse address and size of each function in the kernel image. This information is used to map coverage data to functions. This is needed to find out whether certain functions are called at all.

### addr2line

`addr2line` is used for mapping PC values exported by kcov and parsed by `objdump` to source code files and lines.

### readelf

`readelf` is used to detect virtual memory offset. Executor truncates PC values into `uint32` before sending them to `syz-manager` and `syz-manager` has to detect the offset.
