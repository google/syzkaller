# Coverage

`syzkaller` uses [sanitizer coverage (tracing mode)](https://clang.llvm.org/docs/SanitizerCoverage.html#tracing-pcs)
and [KCOV](https://www.kernel.org/doc/html/latest/dev-tools/kcov.html) for coverage collection.
Sanitizer coverage is also supported by `gcc` and `KCOV` is supported by some other OSes.
Note: `gVisor` coverage is completely different.

Coverage is based on tracing `coverage points` inserted into the object code by the compiler.
A coverage point generally refers to a [basic block](https://en.wikipedia.org/wiki/Basic_block) of code
or a [CFG edge](https://en.wikipedia.org/wiki/Control-flow_graph)
(this depends on the compiler and instrumentation mode used during build,
e.g. for `Linux` and `clang` the default mode is CFG edges, while for `gcc` the default mode is basic blocks).
Note that coverage points are inserted by the compiler in the middle-end after a significant number
of transformation and optimization passes. As the result coverage may poorly relate to the source code.
For example, you may see a covered line after a non-covered line, or you may not see a coverage point
where you would expect to see it, or vice versa (this may happen if the compiler splits basic blocks,
or turns control flow constructs into conditional moves without control flow, etc).
Assessing coverage is still generally very useful and allows to understand overall fuzzing progress,
but treat it with a grain of salt.

See [this](linux/coverage.md) for Linux kernel specific coverage information.

## Web Interface

When clicking on `cover` link you get view showing each directory located in your kernel build directory. It's showing either percentage number `X% of N` or `---`. `X% of N` means that `X%` of `N` coverage points are covered so far, . `---` indicates there is no coverage in that directory.

Directory can be clicked and you get view on files and possible subdirectories. On each source code file there is again either `---` or coverage percentage.

If you click on any C files you will get source code view. There is certain coloring used in the source code view. Color definitions can be found in [coverTemplate](/pkg/cover/report.go#L504). Coloring is described below.

If you click on percentage number of any listed source file you will get cover percentage for each function in that source file.

### Covered: black (#000000)

All PC values associated to that line are covered. There is number on the left side indicating how many programs have triggered executing the PC values assocaciated to this line. You can click on that number and it will open last executed program. Example below shows how single line which is fully covered is shown.

![Code line is fully covered](coverage_covered.png?raw=true)

### Both: orange (#c86400)

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

There is small utility in syzkaller repository to generate coverage report based on raw coverage data. This is available in [syz-cover](/tools/syz-cover) and can be built by:

``` bash
GOOS=linux GOARCH=amd64 go build "-ldflags=-s -w" -o ./bin/syz-cover github.com/google/syzkaller/tools/syz-cover
```

Raw coverage data can be obtained from running `syz-manager` by:

``` bash
wget http://localhost:<your syz-manager port>/rawcover
```

Now this raw cover data can be fed to `syz-cover` to generate coverage report:

``` bash
./bin/syz-cover --kernel_obj <directory where vmlinux is located> rawcover
```

You can also export CSV file containing function coverage by:

``` bash
./bin/syz-cover --kernel_obj <directory where vmlinux is located> --csv <filename where to export>  rawcover
```
