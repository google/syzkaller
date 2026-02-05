# syz-declextract

## Linux Kernel (for testing purposes)
```
export KERNEL=$PWD/linux
git clone git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git $KERNEL
cd $KERNEL
make CC=clang defconfig
./scripts/config -e FTRACE_SYSCALLS
make CC=clang olddefconfig
make CC=clang -j`nproc` vmlinux compile_commands.json # kernel has to be built at least once for the script to work
```

## Running on a single source file
```
./bin/syz-declextract $KERNEL/fs/read_write.c | less # or any other .c file
```

## Coverage Data

Coverage data (coverage.jsonl) can be obtained from syzbot dashboard using:
```
curl --header "accept-encoding: gzip" https://syzkaller.appspot.com/upstream/coverage?jsonl=1 | gunzip > coverage.jsonl
```
Note: the coverage is tied to a particular kernel commit. For consistency that commit
should be used for the rest of the process as well.

## Running on the whole kernel
```
go run ./tools/syz-declextract -config=manager.cfg -coverage coverage.jsonl
syz-env make extract SOURCEDIR=$KERNEL
```

The tool caches results of static kernel analysis in manager.workdir/declextract.cache file,
and results of the dynamic kernel probing in manager.workdir/interfaces.json file.
These can be examined for debugging purposes, and will be reused in future runs if exist
(greatly saves time). If the clang tool/kernel has changed, delete these cache files
so that they are updated.
