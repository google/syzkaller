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
git checkout 0f231567719c99caa99164d8f91bad50883dab03 # In case of any breaking changes, this commit works
echo 'add_clang_executable(syz-declextract syz-declextract/syz-declextract.cpp)
target_link_libraries(syz-declextract PRIVATE clangTooling)' >> $LLVM/clang/CMakeLists.txt
```
## syz-declextract
```
mkdir $LLVM/clang/syz-declextract
```
Download `syz-declextract.cpp` file and add it to `$LLVM/clang/syz-declextract` directory
```
SYZ=$PWD/syz
mkdir $SYZ && cd $SYZ
cmake -DLLVM_ENABLE_PROJECTS="clang" -DCMAKE_BUILD_TYPE=Release -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
-DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ $LLVM/llvm
make -j`nproc` syz-declextract
```
## Example
```
./bin/syz-declextract $KERNEL/fs/read_write.c | less # or any other .c file
```
## Running the tool
Download `run.go`, build it and run it
```
go build run.go
./run -binary $SYZ/bin/syz-declextract -output auto.txt -sourcedir $KERNEL
```
