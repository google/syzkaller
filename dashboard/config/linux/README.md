This dir contains kernel configs used by [syzbot](/docs/syzbot.md).

# Updating Linux configs

To update the main linux config [upstream-kasan.config](./upstream-kasan.config) used by `syzbot`:

1. Check out latest `linux-next` (we tend to use `linux-next` as it contains the most latest features in a single tree).
2. Copy the config into kernel tree as `.config`.
3. Run `make olddefconfig`.
4. Make any additional changes to the config you want to do (e.g. enable/disable some configs with `make menuconfig`).
5. Build and boot the kernel. Ensure there are no bugs during boot (in particular, `WARNING`'s and `LOCKDEP` reports).
6. Copy back the [custom configs](https://github.com/google/syzkaller/blob/1f448cd62db290246f8793128f85bd84aaa7a59d/dashboard/config/upstream-kasan.config#L6-L14) into the `.config` (see comments there).
7. For compiler you need to use a recent gcc (8+). Some of the debugging configs may be disabled due to old/different compiler, in particular `CONFIG_KCOV_ENABLE_COMPARISONS`. You may also restore the [compiler info part](https://github.com/google/syzkaller/blob/1f448cd62db290246f8793128f85bd84aaa7a59d/dashboard/config/upstream-kasan.config#L16-L20) just to reduce the diff size.
8. Copy the config back as `upstream-kasan.config` and send a PR. It will be deployed to `syzbot` within a day after merging.
