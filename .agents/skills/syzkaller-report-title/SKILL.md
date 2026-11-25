---
name: syzkaller-report-title
description: >-
  Improves syzkaller/syzbot crash report title extraction, stack-frame skipping,
  and guilty file attribution in pkg/report/linux.go when unrelated kernel bugs
  collapse into a single generic bucket (e.g., WARNING in vfree, WARNING in
  free_percpu). Use when fixing uninformative syzbot crash titles, adding frames
  to skipPatterns or warningStackFmt, adding oopsFormat rules, or updating
  guiltyFileIgnores.
---

# Syzkaller Report Title & Bucketing

Fixes uninformative syzbot crash titles where generic kernel helpers (e.g., `vfree`, `free_percpu`, `mark_buffer_dirty`, `dput`, `ifs_free`) appear at the top of a `WARNING` or `BUG` stack trace and merge unrelated subsystem bugs into one bucket.

## Workflow

### 1. Inspect the Crash Report(s) and Call Chain

1. Read the full crash report(s) on the syzbot dashboard (`Crash report` section) or in the bug report.
2. Check whether multiple distinct callers/subsystems are hitting the same generic function.
3. Inspect the **entire stack trace**, not just the top frame:
   - Identify adjacent generic helpers that would become the new top frame once the leaf is skipped (e.g., for `vfree`, check `vunmap`, `delayed_vfree_work`, `kvfree`; for `free_percpu`, check `__free_percpu`; for timers, `__mod_timer` was needed alongside `lock_timer_base`).
   - Check the source file of the generic frame (e.g., `mm/vmalloc.c`, `mm/percpu.c`) to see if `guiltyFileIgnores` also needs updating.

### 2. Choose the Right Mechanism in `pkg/report/linux.go`

1. **Global skip (`linuxStackParams.skipPatterns`)**:
   - Skips matching frames **unconditionally across all crash types** (`BUG`, `KASAN`, `KMSAN`, `WARNING`, etc.).
   - Use only when a function is virtually never the root cause in any crash type (e.g., `^kv?free$`, `^vfree$`, `^free_percpu$`, `ida_free`, `drop_nlink`, `mark_buffer_dirty`, `^put_device$`).
2. **Scoped skip (`stackFmt.skip` / `warningStackFmt(...)`)**:
   - Skips frames **only for a specific `oopsFormat` rule** (e.g., `WARNING: .*mm/.*\.c.* k?.?malloc` skips `"kmalloc", "krealloc", "slab", "kmem"`).
   - Prefer scoped `stack.skip` when a frame is only generic for a specific warning/oops pattern, or when you want a custom title prefix like `WARNING: ... in %[1]v`.
3. **Specific `oopsFormat` before generic `WARNING:` fallbacks**:
   - `linuxOopses` is matched top-to-bottom; the first matching `oopsFormat` wins.
   - Place any specific `WARNING:` rule **above** the generic `WARNING: ... at {{SRC}} {{FUNC}}` fallback entries.
   - If `report` fails to match (e.g., older kernel formats), `pkg/report` falls through to the simpler rules below.
4. **Guilty file attribution (`ctx.guiltyFileIgnores` and `guiltyDir`)**:
   - Fixing the title does not automatically fix `extractGuiltyFileImpl`.
   - Verify the helper's source file is in `ctx.guiltyFileIgnores` (e.g., `^mm/vmalloc\.c`, `^mm/percpu.*`), or if it is a shared library directory like `fs/iomap` or `fs/netfs`, handle its directory depth in `guiltyDir`.

### 3. Pitfalls to Avoid

- **Unanchored regexes in `skipPatterns` / `stack.skip`**: `extractStackFrame` joins all skip entries with `|` into a single `regexp.MustCompile` and matches **substrings without implicit `^`/`$` anchors**. Unanchored `"vfree"` will also match `"delayed_vfree_work"` or driver helpers containing `"vfree"`. Always anchor exact function names (e.g., `^vfree$`, `^free_percpu$`) unless substring matching is intentional.
- **Skipping only the leaf frame**: Check if the next frame up is another generic wrapper with hundreds of call sites (e.g., `__mod_timer`, `truncate_inode_pages_range`).
- **Over-skipping into `"corrupted"`**: If every frame in a stack trace matches `skipPatterns`, `extractStackFrameImpl` marks the report `"corrupted"`.
- **Silent title regressions**: Adding a skip pattern can change titles for existing `pkg/report/testdata/linux/report/*` cases and cause syzbot to file duplicate bugs on live trees. Always run the full `pkg/report` test suite to catch unintended title changes.
- **Go `regexp` multiline & symbol matching**: `.` does not match `\n` in Go `regexp` — use `(?:.*\n)+?` for multi-line patterns. Use `{{FUNC}}` or `[a-zA-Z0-9_]+` for symbol names (some start with digits or have `.isra.`/`.cold` suffixes).
- **Unix paths in Go**: Kernel source paths always use `/`. Use `path.Clean`/`path.Dir` (not `filepath.*`, which uses `\` on Windows hosts) or normalize with `filepath.ToSlash`.

### 4. Add Tests

1. Find the next unused numeric filename in `pkg/report/testdata/linux/report/` (and `pkg/report/testdata/linux/guilty/` if guilty file extraction changed).
2. Add a test file with the expected header (`TITLE: ...` or `FILE: ...`) followed by the crash log.
3. **Keep testdata concise**: Trim unrelated console noise and trailing register/hexdump lines after the stack trace while keeping the full warning header and `Call Trace:` needed for parsing.

### 5. Verify & Prepare PR

- Run tests, formatter, and linter:
  ```bash
  CI=true ./tools/syz-env go test ./pkg/report/...
  CI=true ./tools/syz-env make format
  CI=true ./tools/syz-env make lint
  ```
- **Commit / PR conventions**:
  - Summary format: `pkg/report: <lowercase description without trailing dot>` (e.g., `pkg/report: skip vfree and free_percpu frames`).
  - Include the syzbot dashboard link(s) in the PR body explaining why the frame is too generic and merges unrelated bugs.
