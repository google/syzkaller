---
name: linux-config-update
description: >-
  Update Linux kernel configurations in dashboard/config/linux (bits/*.yml, main.yml, and
  generated *.config files) using syz-kconf (`./tools/syz-env make configs`). Use when enabling or
  disabling kernel config options, bumping kernel tags (`bits/linux-upstream.yml`, `bits/linux-next.yml`),
  adding new config fragments or instances, or regenerating syzbot Linux kernel configs.
---

# Updating Linux Kernel Configs (`dashboard/config/linux`)

Use this skill when modifying `dashboard/config/linux/` — whether enabling new `CONFIG_*` options,
updating kernel tags for a new Linux release, adding new instances/fragments, or regenerating
`.config` files.

First, read [`dashboard/config/linux/README.md`](../../../dashboard/config/linux/README.md) for the
`main.yml` and `bits/*.yml` declarative syntax, instance features (`baseline`, `base-config`,
`nonoise`, `reduced`, `vX.Y` version tags), and how [`tools/syz-kconf`](../../../tools/syz-kconf/kconf.go)
generates `<name>.config` and `<name>-base.config`.

## 1. Running `make configs` (Always Use `syz-env`!)

> [!IMPORTANT]
> **Always run config generation inside `./tools/syz-env`.**
> Kernel Kconfig evaluates compiler capabilities (`cc-option`, `CC_VERSION_TEXT`, `CLANG_VERSION`,
> `GCC_VERSION`, rustc/bindgen availability, etc.). Running outside `syz-env` uses host compilers
> and produces massive, unintended diffs across all `.config` files.
> **Never manually edit generated `*.config` files.**

### Fast Iteration with `INSTANCE=`

A full `make configs` run checks out multiple kernel trees (upstream, linux-next, stable, Android,
ChromeOS) and generates ~80 configs, which is very slow.

When testing new options or debugging a failure, iterate on individual instances first using
`INSTANCE=<name>` (or `INSTANCE=<name>-base` for the baseline config):

```bash
# Quick check on a single upstream x86_64 instance:
CI=true ./tools/syz-env make configs SOURCEDIR=$KERNEL_PATH INSTANCE=upstream-apparmor-kasan

# Check older stable/android/arch/sanitizer instances to verify version and arch constraints:
CI=true ./tools/syz-env make configs SOURCEDIR=$KERNEL_PATH INSTANCE=stable-5.15-kasan
CI=true ./tools/syz-env make configs SOURCEDIR=$KERNEL_PATH INSTANCE=upstream-s390-kasan
CI=true ./tools/syz-env make configs SOURCEDIR=$KERNEL_PATH INSTANCE=upstream-kmsan
```

Once single-instance checks pass, run the **full** command without `INSTANCE=` to update all
affected `.config` files before committing:
```bash
CI=true ./tools/syz-env make configs SOURCEDIR=$KERNEL_PATH
```
Remove any untracked `dashboard/config/linux/*.config.tmp` files if left behind.

## 2. Determining Kernel Versions for New or Removed Options

Never guess version constraints or slap `weak` / `optional` on a config to silence errors on older
kernels. Always find the exact kernel release in `$KERNEL_PATH`:

1. **Find When a New Option Appeared**:
   ```bash
   # Find the commit that introduced `config FOO` in Kconfig:
   git -C "$KERNEL_PATH" log -S "config FOO" --oneline -- "**/Kconfig*" "Kconfig*"

   # Instant check of the base kernel version at that commit:
   git -C "$KERNEL_PATH" show <commit_hash>:Makefile | head -n 5

   # Verify the exact release tag containing that commit (note: a commit authored on v6.13-rcX
   # typically merges in v6.14-rc1):
   git -C "$KERNEL_PATH" merge-base --is-ancestor <commit_hash> v6.14
   # Or:
   git -C "$KERNEL_PATH" describe --contains --match "v[0-9]*.[0-9]*-rc1" <commit_hash>
   # e.g., "v6.14-rc1~42^2~5" -> appeared in v6.14 -> use [v6.14]
   ```
   - If the oldest kernel instance that includes the fragment already has the option (note:
     `android-5.4` is `v5.4`, `android-5.10` / `chromeos-5.10` are `v5.10`, `stable-5.15` is
     `v5.15`), no version tag is needed.
   - If the commit is only in `linux-next` and not yet in `bits/linux-upstream.yml`, use
     `[linux-next]`. When bumping `bits/linux-upstream.yml` to a new release, replace `[linux-next]`
     on options that graduated into mainline with their `[vX.Y]` tag.
   - Inspect `depends on` in the Kconfig definition: if `FOO` depends on an architecture (e.g.,
     `X86_64`) or conflicts with a feature (e.g., `!PREEMPT_RT`, `!KMSAN`), add the corresponding
     constraints (e.g., `[x86_64, v6.14]`, `[-s390]`, `[-preempt_rt]`).

2. **Find When an Option Was Removed, Renamed, or Migrated**:
   ```bash
   git -C "$KERNEL_PATH" log -n 5 -S "config OLD_FOO" --oneline -- "**/Kconfig*" "Kconfig*"
   git -C "$KERNEL_PATH" describe --contains --match "v[0-9]*.[0-9]*-rc1" <commit_hash>
   ```
   - Add an upper-bound version constraint (e.g., `[-v7.1]`) and document the kernel commit above it:
     - `# Removed in <12-char-hash> "<commit_title>".`
     - `# Renamed to <NEW_CONFIG> in <12-char-hash> "<commit_title>".` (and add `- NEW_CONFIG: [vX.Y]`)
     - `# Migrated to library in <12-char-hash> "<commit_title>".`
   - If the option was only tagged `[linux-next]` (never enabled in any released kernel config),
     remove the line directly and explain it in the commit message.

## 3. Avoid `override`, `weak`, and `optional` at All Costs

> [!WARNING]
> **Avoid `override`, `weak`, and `optional` at all costs!**
> They hide broken dependencies, silently drop coverage when Kconfig dependencies change in future
> kernel releases, and make fragment inclusion order fragile.

Use these patterns instead:

1. **Instead of `weak` / `optional` when an option fails verification on some instances**:
   - Inspect why `olddefconfig` dropped or altered the option (check Kconfig `depends on` and
     `select` in `$KERNEL_PATH`, and compare `<instance>.config.tmp` with `<instance>.config`).
   - Enable missing prerequisite Kconfig options if appropriate.
   - Otherwise, add **explicit constraints** for the kernel version, architecture, or instance
     features where the option is unsupported (e.g., `[v6.17, x86_64, -kmsan, -preempt_rt]`,
     `[-arm, -riscv, -s390]`), with a brief comment explaining non-obvious exclusions.

2. **Instead of `override` when two fragments or features want different values**:
   - **Use mutual exclusion tags on the original definition**: For example, when enabling
     `ANDROID_BINDER_IPC_RUST: [v6.18, rust]`, do NOT override `ANDROID_BINDER_IPC: n` in `rust.yml`.
     Instead, restrict the original entry in `subsystems.yml` to `ANDROID_BINDER_IPC: [-rust]`.
   - **Move the option to a more specific existing bit or extract a new `bits/<topic>.yml` bit**:
     - Example: `DEBUG_INFO_BTF` was moved from `base.yml` to `bpf.yml` (which is excluded on
       `-baseline`, `-onlynet`, `-onlyusb`) instead of overriding it in baseline/minimal configs.
     - Example: Sound options were extracted from `subsystems.yml` into `bits/sound.yml` included in
       `main.yml` with `[-baseline, -onlynet, -onlyusb, -arm64_gce]`.
     - Every new file created in `dashboard/config/linux/bits/` must have a copyright header and a
       top-level comment explaining the purpose of the fragment and where it is used.

3. **When all options in a fragment are removed in a new kernel**:
   - Exclude the entire fragment in `main.yml` using instance tags (e.g., `-upstream, -linux-next`
     with a comment citing the removal commit, as done for `hamradio.yml`; remember `[-vX.Y]` does
     not work on `includes:` in `main.yml`).

## 4. Troubleshooting Common Issues

- **`pkg/kconfig` Parser Limitations**:
  If a new kernel introduces Kconfig syntax that `syz-kconf` fails to parse, **never modify Kconfig
  files in `$KERNEL_PATH`**. Implement support for the syntax in
  [`pkg/kconfig/kconfig.go`](../../../pkg/kconfig/kconfig.go) and add a test in
  [`pkg/kconfig/kconfig_test.go`](../../../pkg/kconfig/kconfig_test.go).
- **Git Fetch / Checkout Failures**:
  `syz-kconf` adds hashed remotes to `$KERNEL_PATH`. If a checkout fails (e.g., on Android/ChromeOS
  trees), find the remote hash in the error output, run `git -C "$KERNEL_PATH" fetch <remote> <tag>`
  manually, and retry `make configs`.

## 5. Commit Structure & Conventions

- When updating `bits/linux-upstream.yml` and `bits/linux-next.yml` to new tags (use release tags
  like `v7.2` or `next-YYYYMMDD`, not raw commit hashes), split changes into logical commits:
  1. `dashboard/config/linux: update config fragments for vX.Y` (tag updates + disabling removed
     options with commit references).
  2. `dashboard/config/linux: enable more configs` (enabling newly introduced bug-finding or
     subsystem options; if notable new options were skipped, explain why in the commit message).
  3. `dashboard/config/linux: update generated configs` (the generated `*.config` files as the
     very last commit).
- For targeted single-feature changes (e.g., `dashboard/config/linux: enable CONFIG_FOO`), check
  whether the user wants a single commit or separate commits for `bits/` and `*.config`.
