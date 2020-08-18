# Linux kernel configs

List of recommended kernel configs for `syzkaller`. See [syzbot config](/dashboard/config/upstream-kasan.config) for a reference config.

## Syzkaller features

To enable coverage collection, which is extremely important for effective fuzzing:
```
CONFIG_KCOV=y
CONFIG_KCOV_INSTRUMENT_ALL=y
CONFIG_KCOV_ENABLE_COMPARISONS=y
CONFIG_DEBUG_FS=y
```
Note that `CONFIG_KCOV_ENABLE_COMPARISONS` feature also requires `gcc8+` and the following commits if you are testing an old kernel:
```
    kcov: support comparison operands collection
    kcov: fix comparison callback signature
```

To detect memory leaks using the [Kernel Memory Leak Detector
(kmemleak)](https://www.kernel.org/doc/html/latest/dev-tools/kmemleak.html):

```
CONFIG_DEBUG_KMEMLEAK=y
```

To show code coverage in web interface:
```
CONFIG_DEBUG_INFO=y
```

For detection of enabled syscalls and kernel bitness:
```
CONFIG_KALLSYMS=y
CONFIG_KALLSYMS_ALL=y
```

For better sandboxing:
```
CONFIG_NAMESPACES=y
CONFIG_UTS_NS=y
CONFIG_IPC_NS=y
CONFIG_PID_NS=y
CONFIG_NET_NS=y
CONFIG_CGROUP_PIDS=y
CONFIG_MEMCG=y
```

For `namespace` sandbox:
```
CONFIG_USER_NS=y
```

For running in VMs `make kvmconfig` is generally required.

Debian images produced by [tools/create-image.sh](/tools/create-image.sh) also require:
```
CONFIG_CONFIGFS_FS=y
CONFIG_SECURITYFS=y
```

It is recommended to disable the following config (and required if your kernel doesn't have commits [arm64: setup: introduce kaslr_offset()](https://github.com/torvalds/linux/commit/7ede8665f27cde7da69e8b2fbeaa1ed0664879c5)
 and [kcov: make kcov work properly with KASLR enabled](https://github.com/torvalds/linux/commit/4983f0ab7ffaad1e534b21975367429736475205)):
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

For testing with fault injection enable the following configs (syzkaller will pick it up automatically):
```
CONFIG_FAULT_INJECTION=y
CONFIG_FAULT_INJECTION_DEBUG_FS=y
CONFIG_FAILSLAB=y
CONFIG_FAIL_PAGE_ALLOC=y
CONFIG_FAIL_MAKE_REQUEST=y
CONFIG_FAIL_IO_TIMEOUT=y
CONFIG_FAIL_FUTEX=y
```
Note: you also need the following commits if you are testing an old kernel:
```
    fault-inject: support systematic fault injection
    fault-inject: simplify access check for fail-nth
    fault-inject: fix wrong should_fail() decision in task context
    fault-inject: add /proc/<pid>/fail-nth
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
CONFIG_BOOTPARAM_HARDLOCKUP_PANIC=y
CONFIG_DETECT_HUNG_TASK=y
CONFIG_WQ_WATCHDOG=y
```

Increase hung/stall timeout to reduce false positive rate:
```
CONFIG_DEFAULT_HUNG_TASK_TIMEOUT=140
CONFIG_RCU_CPU_STALL_TIMEOUT=100
```
