# Strace

Syzkaller can be instructed to execute programs under
[strace](https://strace.io/) and capture the output.

If the `strace_bin` is set to an `strace` binary, syzkaller will automatically
run each reproducer it managed to find under the `strace` binary.
* If a syz-manager is attached to a `dashboard`, syzkaller will upload the
  resulting output as a normal log file if the generated reproducer still
  managed to produce the same crash.
* Otherwise, the output of strace will be saved to a separate file and will be
  accessible through the syz-manager's web interface.

## How to compile the strace binary

It is safer to compile `strace` as a statically linked binary in order to
prevent problems with mismatching libc versions on the kernel image used for
fuzzing.

```
git clone https://github.com/strace/strace.git
cd strace
./bootstrap
./configure --enable-mpers=no LDFLAGS='-static -pthread'
make -j`nproc`
```

The resulting binary can be found at `src/strace`.

## syz-crush

It's possible to instruct `syz-crush` to run the attached repro under strace. In
order to do so, make sure `strace_bin` is specified in the syz-manager config
file and pass an extra `-strace` arugment to the command arguments.

## syz-repro

If `-strace file-name.log` is appended to the `syz-repro`'s arguments, the tool
will run the resulting repro (if it managed to generate one) under strace and
save its output.
