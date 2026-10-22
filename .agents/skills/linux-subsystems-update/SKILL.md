---
name: linux-subsystems-update
description: >-
  Update and regenerate the Linux kernel subsystem list in pkg/subsystem/lists/linux.go
  (and custom rules in pkg/subsystem/linux/) using tools/syz-query-subsystems against a
  mainline (torvalds) Linux kernel checkout. Use when regenerating Linux subsystems for a
  new kernel release, adding custom subsystem rules, fixing MAINTAINERS parsing/naming
  errors, or associating syzkaller pseudo-syscalls with subsystems.
---

# Updating Linux Subsystems (`pkg/subsystem/lists/linux.go`)

Use this skill when updating or regenerating [`pkg/subsystem/lists/linux.go`](../../../pkg/subsystem/lists/linux.go)
or modifying the Linux subsystem extraction rules in [`pkg/subsystem/linux/`](../../../pkg/subsystem/linux/).
Read the code in `pkg/subsystem/linux/` (`subsystems.go`, `rules.go`, `names.go`, `parents.go`, `maintainers.go`)
as needed to understand how subsystems and hierarchies are inferred.

## 1. Obtaining a Linux Kernel Checkout (`torvalds`, NOT `linux-next`)

If the user has not provided a path to a Linux kernel checkout (`$KERNEL_PATH`), **ask the user for one** before running the generator.

> [!IMPORTANT]
> - **Use upstream mainline (`torvalds/linux.git`), NOT `linux-next`.**
>   All subsystem list updates target mainline Linux, ideally checked out at the latest release or
>   release candidate tag (e.g., `v6.19-rc6`, `v6.16-rc7`) so the generated header comment and
>   revision date reflect a mainline release tag.
> - **Ensure the kernel working tree is clean.**
>   The generator walks source files in `$KERNEL_PATH` to count files per subsystem and infer
>   parent-child relationships. Untracked build artifacts or out-of-tree source files will skew file
>   counts and parent inference.

## 2. Running `syz-query-subsystems`

Never hand-edit `pkg/subsystem/lists/linux.go`. Regenerate it via [`tools/syz-query-subsystems`](../../../tools/syz-query-subsystems/query_subsystems.go) (run directly on the host so `$KERNEL_PATH` outside the repo is accessible):

```bash
go run ./tools/syz-query-subsystems \
  -os linux \
  -kernel "$KERNEL_PATH" \
  -syzkaller . \
  -name linux
```

- Pass `-debug` to print the exact list of kernel source paths matched by each subsystem.
- When investigating why a subsystem was dropped, merged, or assigned unexpected parents, it often helps to **apply temporary debugging changes** to [`pkg/subsystem/linux/`](../../../pkg/subsystem/linux/) and re-run `syz-query-subsystems` to extract more information. Revert any temporary debugging code when done.

## 3. Caveats & Resolving Regeneration Errors

When `MAINTAINERS` or the kernel tree changes upstream, `syz-query-subsystems` may fail with errors or produce undesirable changes in `pkg/subsystem/lists/linux.go`:

1. **Naming Failures or Collisions ([`pkg/subsystem/linux/names.go`](../../../pkg/subsystem/linux/names.go))**:
   - First check if the new mailing list actually represents a distinct kernel subsystem. If it is a secondary/user list, a company/team catch-all (`kernel@collabora.com`, `coreteam@netfilter.org`), or an overly broad cross-cutting list (`x86@kernel.org`), **exclude it** via `notSubsystemEmails` in [`pkg/subsystem/linux/rules.go`](../../../pkg/subsystem/linux/rules.go).
   - If it is a genuine subsystem whose mailing list cannot be cleanly parsed by the generic rules or produces a name longer than 16 characters, add a mapping to `emailExceptions` in `names.go` (and remove obsolete exceptions if a mailing list migrated upstream).

2. **Broken or Dangling Custom Rules ([`pkg/subsystem/linux/rules.go`](../../../pkg/subsystem/linux/rules.go))**:
   - **`MAINTAINERS record not found`**: A section title in `extraSubsystems` was renamed or removed upstream in `MAINTAINERS`. Update `extraSubsystems` with the new title.
   - **`unused keys` in rule checks**:
     - If the subsystem was removed from the kernel (e.g., `bcachefs`, `reiserfs`), remove it from `rules.go` (if a `syz_mount_image$*` call still exists without a subsystem, move it to the `TODO` comment in `subsystemCalls`).
     - If the subsystem was renamed or merged into another subsystem (e.g., `ntfs` -> `ntfs3`, `fat` -> `exfat`), move its rules to the new subsystem name.
     - If a still-existing subsystem vanished only because its `L:` mailing list was removed or merged into a shared list (like `linux-fsdevel@vger.kernel.org` or `netdev@vger.kernel.org`), preserve it by adding its `MAINTAINERS` section title(s) to `extraSubsystems`.

3. **`MAINTAINERS` Parser Issues ([`pkg/subsystem/linux/maintainers.go`](../../../pkg/subsystem/linux/maintainers.go))**:
   - Never edit `$KERNEL_PATH/MAINTAINERS` to work around parsing errors. Fix the parser in `maintainers.go` and add a unit test in `maintainers_test.go`.

## 4. Reviewing the Generated Diff in `pkg/subsystem/lists/linux.go`

Even when `syz-query-subsystems` succeeds without errors, **always inspect the diff of `pkg/subsystem/lists/linux.go`**, especially the `// The subsystem list:` hierarchy comment at the top:

- **Overly Broad New Subsystems**: If a new mailing list covers a huge swath of the tree and swallows unrelated subsystems as children (check the `// Auto-inferred:` parent comments), add the list to `notSubsystemEmails` in `rules.go`.
- **Important Subsystems Lost**: If a major subsystem disappeared from the hierarchy tree because its dedicated mailing list was removed in `MAINTAINERS`, add it to `extraSubsystems` in `rules.go`.
- **Custom Hierarchy Adjustments**: Use `addParents`, `noIndirectCc`, and `noReminders` in `rules.go` when automatic parent inference or CC rules need manual overrides.

## 5. Testing and Committing

1. **Run Subsystem and Dashboard Tests**:
   ```bash
   CI=true ./tools/syz-env go test ./pkg/subsystem/... ./dashboard/app/...
   ```
   - If [`TestLinuxUpstreamSubsystems`](../../../pkg/subsystem/lists/linux_test.go) fails after regeneration, investigate whether a subsystem's path rules or parent hierarchy regressed.
   - If a subsystem referenced in `dashboard/app` (e.g., `SubsystemEmbargo`) was renamed or removed, update the dashboard config or `Redirect` map accordingly.

2. **Commit Conventions**:
   - Separate any parser/logic changes in `pkg/subsystem/` or `tools/syz-query-subsystems/` into their own commit(s) first.
   - For the regeneration commit (including rule/name adjustments in `pkg/subsystem/linux/`), use a commit message like `pkg/subsystem: regenerate Linux subsystems` and mention the target kernel tag (e.g., `v6.19-rc6`).
