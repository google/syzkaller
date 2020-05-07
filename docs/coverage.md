# Coverage

See [this](linux/coverage.md) for Linux kernel specific coverage information.

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
