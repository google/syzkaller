This dir contains sources of a fake kernel that resembles Linux for testing of the `syz-declextract` tool.

For each `*.c` file there 3 golden files:
 - `*.c.json` with the expected output of the clang tool
 - `*.c.txt` with the expected syzlang descriptions
 - `*.c.info` with the expected kernel interface list

Testing is done by `tools/syz-declextract` tests.

`TestClangTool` invokes the clang tool and verifies `*.c.json` contents.
The test requires the clang tool binary specified in the `-bin`, otherwise it skips testing.
You also want to run it with `-count=1` flag since the Go tool does not detect changes in the tool binary,
and will cache and reuse test results:
```
go test -count=1 ./tools/syz-declextract -bin=llvm/build/bin/syz-declextract
```

`TestDeclextract` verifies `*.c.txt` and `*.c.info` using `*.c.json` files as inputs
(it does not involve the clang tool and runs always).

All tests also support `-update` flag, which updates the golden files.
Generally you don't need to update them manually.

Since the test covers multiple packages, it's useful to run coverage as follows:
```
go test -count=1 -coverprofile=/tmp/cover -coverpkg="github.com/google/syzkaller/tools/syz-declextract,github.com/google/syzkaller/pkg/declextract,github.com/google/syzkaller/pkg/clangtool" ./tools/syz-declextract -bin=llvm/build/bin/syz-declextract
go tool cover -html /tmp/cover
```
