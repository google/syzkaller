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

## Web Interface

When clicking on `cover` link you get view showing each directory located in your kernel build directory. It's showing either percentage number or `---`. `---` indicates code in that directory is not instrumented by kcov or there are not yet coverage in that directory.

Directory can be clicked and you get view on files and possible subdirectories. On each source code file there is again either `---` or coverage percentage.

If you click on any C files you will get source code view. There is certain coloring used in the source code view. Color definitions can be found in [coverTemplate](/pkg/cover/report.go#L504). Coloring is described below.

### Covered: black (#000000)

All PC values associated to that line are covered. There is number on the left side indicating how many programs have triggered executing the PC values assocaciated to this line. You can click on that number and it will open last executed program. Example below shows how single line which is fully covered is shown.

![Code line is fully covered](coverage_covered.png?raw=true)

### Both: orange (#ff6400)

There are several PC values associated to the line and not all of these are executed. Again there is number left to the source code line that can clicked to open last program triggering associated PC values. Example below shows single line which has both excuted and non-executed PC values associated to it.

![Code line has executed and not executed PC values](coverage_both.png?raw=true)

###  Weak-uncovered: crimson red (#c80000)

Function (symbol) this line is in doesn't have any coverage. I.e. the function is not executed at all. Please note that if compiler have optimized certain symbol out and made the code inline instead symbol associated with this line is the one where the code is compiled into. This makes it sometimes real hard to figure out meaning of coloring. Example below shows how single line which is uncovered and PC values associated to it are in function(s) that are not executed either is shown.

![PC values associated to the line are not exexuted and these PC values are in functions that are not executed either](coverage_weak-uncovered.png?raw=true)

### Uncovered: red (#ff0000)

Line is uncovered. Function (symbol) this line is in is executed and one of the PC values associated to this line. Example below shows how single line which is not covered is shown.

![Code line has no executed PC values associated. Function it is in is executed](coverage_uncovered.png?raw=true)

### Not instrumented: grey (#505050)

PC values associated to the line are not instrumented or source line doesn't generate code at all. Example below shows how all not instrumented code is shown.

![Not instrumented code lines](coverage_not_instrumented.png?raw=true)

## syz-cover

There is small utility in syzkaller repository to generate coverage report on kcov data. This is available in [syz-cover](/tools/syz-cover) and can be build by:

``` bash
GOOS=linux GOARCH=amd64 go build "-ldflags=-s -w" -o ./bin/syz-cover github.com/google/syzkaller/tools/syz-cover
```

kcov data can be obtained from running `syz-manager` by:

``` bash
wget http://localhost:<your syz-manager port>/rawcover
```

Now this raw cover data can be fed to `syz-cover` to generate coverage report:

``` bash
./bin/syz-cover --kernel_obj <directory where vmlinux is located> rawcover
```
