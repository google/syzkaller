This was manually vendored on the version v2.0.8
(which matches the compiler version in the env container)
using the following commands:

```
git clone --branch=v2.0.8 --depth=1 --single-branch https://github.com/google/flatbuffers.git
cp flatbuffers/LICENSE.txt syzkaller/executor/_include/flatbuffers
cp flatbuffers/include/flatbuffers/*.h syzkaller/executor/_include/flatbuffers
```
