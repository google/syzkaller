# Linux kernel configs

List of recommended kernel configs for `syzkaller`:

## Syzkaller features

To enable coverage collection, which is extremely important for effective fuzzing:
```
CONFIG_KCOV=y
CONFIG_KCOV_INSTRUMENT_ALL=y
CONFIG_DEBUG_FS=y
```

To show code coverage in web interface:
```
CONFIG_DEBUG_INFO=y
```

For `namespace` sandbox:
```
CONFIG_NAMESPACES=y
CONFIG_USER_NS=y
CONFIG_UTS_NS=y
CONFIG_IPC_NS=y
CONFIG_PID_NS=y
CONFIG_NET_NS=y
```

If your kernel doesn't have commits [arm64: setup: introduce kaslr_offset()](https://github.com/torvalds/linux/commit/7ede8665f27cde7da69e8b2fbeaa1ed0664879c5)
 and [kcov: make kcov work properly with KASLR enabled](https://github.com/torvalds/linux/commit/4983f0ab7ffaad1e534b21975367429736475205), disable the following config:
```
# CONFIG_RANDOMIZE_BASE is not set
```

## Bug detection configs

Syzkaller is meant to be used with
[KASAN](https://kernel.org/doc/html/latest/dev-tools/kasan.html) (available upstream with `CONFIG_KASAN=y`),
[KTSAN](https://github.com/google/ktsan) (prototype available),
[KMSAN](https://github.com/google/kmsan) (prototype available),
or [KUBSAN](https://kernel.org/doc/html/latest/dev-tools/ubsan.html) (available upstream with `CONFIG_UBSAN=y`).

Enable `KASAN` for use-after-free and out-of-bounds detection:
```
CONFIG_KASAN=y
CONFIG_KASAN_INLINE=y
```

Any other debugging configs, the more the better, here are some that proved to be especially useful:
```
CONFIG_LOCKDEP=y
CONFIG_PROVE_LOCKING=y
CONFIG_DEBUG_ATOMIC_SLEEP=y
CONFIG_PROVE_RCU=y
CONFIG_DEBUG_VM=y
CONFIG_REFCOUNT_FULL=y
CONFIG_FORTIFY_SOURCE=y
CONFIG_HARDENED_USERCOPY=y
CONFIG_LOCKUP_DETECTOR=y
CONFIG_SOFTLOCKUP_DETECTOR=y
CONFIG_HARDLOCKUP_DETECTOR=y
CONFIG_DETECT_HUNG_TASK=y
CONFIG_WQ_WATCHDOG=y
```

Increase RCU stall timeout to reduce false positive rate:
```
CONFIG_RCU_CPU_STALL_TIMEOUT=60
```
