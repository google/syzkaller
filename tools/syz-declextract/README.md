# syz-declextract

## Linux Kernel (for testing purposes)
```
export KERNEL=$PWD/linux
git clone git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git $KERNEL
cd $KERNEL
make CC=clang defconfig
./scripts/config -e FTRACE_SYSCALLS
make CC=clang olddefconfig
make CC=clang -j`nproc` # kernel has to be built at least once for the script to work
./scripts/clang-tools/gen_compile_commands.py
```

## LLVM Project
```
LLVM=$PWD/llvm-project
git clone https://github.com/llvm/llvm-project.git $LLVM
cd $LLVM
git checkout d28b4d89166fb705577a2d3a329006f0c0e0aacc # In case of any breaking changes, this commit works
echo '
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-c++20-designator -Wno-missing-designated-field-initializers")
add_clang_executable(syz-declextract syz-declextract/declextract.cpp)
target_link_libraries(syz-declextract PRIVATE clangTooling)
' >> $LLVM/clang/CMakeLists.txt
```

## syz-declextract
```
mkdir $LLVM/clang/syz-declextract
```
Copy `tools/syz-declextract/clangtool/*.{cpp,h}` files to `$LLVM/clang/syz-declextract/` directory.
```
LLVM_BUILD=$PWD/syz
mkdir $LLVM_BUILD && cd $LLVM_BUILD
cmake -DLLVM_ENABLE_PROJECTS="clang" -DCMAKE_BUILD_TYPE=Release -DLLVM_ENABLE_ASSERTIONS=On \
-DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -GNinja $LLVM/llvm
ninja syz-declextract
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
go run ./tools/syz-declextract -binary=$LLVM_BUILD/bin/syz-declextract -config=manager.cfg \
	-coverage coverage.jsonl
syz-env make extract SOURCEDIR=$KERNEL
```

The tool caches results of static kernel analysis in manager.workdir/declextract.cache file,
and results of the dynamic kernel probing in manager.workdir/interfaces.json file.
These can be examined for debugging purposes, and will be reused in future runs if exist
(greatly saves time). If the clang tool/kernel has changed, delete these cache files
so that they are updated.
