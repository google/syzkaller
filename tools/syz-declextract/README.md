# syz-declextract

## Linux Kernel (for testing purposes)
```
export KERNEL=$PWD/linux
git clone git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git $KERNEL
cd $KERNEL
make CC=clang defconfig # Having clang as the compiler is optional but removes erros later on
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
git checkout 3a31427224d4fa49d7ef737b21f6027dc4928ecf # In case of any breaking changes, this commit works
echo 'add_clang_executable(syz-declextract syz-declextract/declextract.cpp)
target_link_libraries(syz-declextract PRIVATE clangTooling)' >> $LLVM/clang/CMakeLists.txt
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
make -j`nproc` syz-declextract
```

## Running on a single source file
```
./bin/syz-declextract $KERNEL/fs/read_write.c | less # or any other .c file
```

## Running on the whole kernel
```
go run tools/syz-declextract -binary=$LLVM_BUILD/bin/syz-declextract -config=manager.cfg
syz-env make extract SOURCEDIR=$KERNEL
```

The tool caches results of static kernel analysis in manager.workdir/declextract.cache file,
and results of the dynamic kernel probing in manager.workdir/interfaces.json file.
These can be examined for debugging purposes, and will be reused in future runs if exist
(greatly saves time). If the clang tool/kernel has changed, delete these cache files
so that they are updated.
