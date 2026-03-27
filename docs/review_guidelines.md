# Automated Code Review Guidelines (DVYUKOV.md)

This file contains curated recommendations extracted from automated pull request reviews. Ingest this file into your LLM pipeline to ensure compliance with repository style and best practices!

## 1. Go Coding Style & Idioms
- **Naming:**
  - Lowercase package names (no underscores or MixedCaps).
  - Use `NewFoo` or `MakeFoo` for constructors; return pointers if methods are defined on pointers.
  - Avoid repeating type names in method names (e.g., `linux.Foo()` not `linux.FooLinux()`).
  - Avoid "syz" prefixes for internal structs/fields (e.g., `exec_total` not `syz_exec_total`).
  - Use `i` for loop indices; use descriptive names for slice elements.
  - Favor positive boolean naming (`active` vs `not_inactive`).
- **Declarations:**
  - Combine declaration and initialization (`x := foo()`).
  - Rely on zero-value defaults; do not manually initialize to 0, "", or `map[type]type{}`.
  - Unexport symbols (types, fields, constants, functions) not needed externally.
  - Use `iota` for enums and make `Invalid` the first value (0) to catch uninitialized fields.
  - Use `go:embed` for embedding static assets like HTML or text templates.
- **Functions & Control Flow:**
  - Return early on errors (standard `if err != nil` check); avoid deep nesting.
  - Avoid naked or named returns unless they significantly simplify repetitive code.
  - Drop unnecessary `else` after `return`, `break`, or `continue`.
  - Prefer free/normal functions over closures if no context is captured from the outer scope.
  - Use closures to deduplicate scoped logic within a single function.
- **Miscellaneous:**
  - Cap Go lines at 120 columns; use tabs for indentation.
  - Use `%s` for struct string conversion in `fmt` functions (idiomatic `v.String()` call).
  - Avoid unneeded parentheses in expressions and `()` to refer to functions in comments.

## 2. Error Handling & Reliability
- **Return Errors:** Never swallow errors or return `nil` on unexpected conditions.
- **Fail Fast:**
  - Validate invariants early (e.g., during initialization or deserialization).
  - Panic on impossible internal logic corruption or broken engine invariants.
  - For external tools/plugins, use `SYZFAIL:` prefix for internal bugs to distinguish from target crashes.
- **Error Context:**
  - Don't wrap errors without adding specific, helpful context (Syzkaller libs often add basic context).
  - Use `aflow.BadCallError` for invalid tool inputs in agent workflows.
- **Validation:**
  - Always validate inputs at boundaries (datastores, APIs, CLI flags, regexes).
  - Guard against underflows/overflows in length checks and binary formats.

## 3. Testing Best Practices
- **Assertions:** Use `github.com/stretchr/testify/require` (or `assert`) for single-line, readable assertions.
- **Structure:**
  - Use table-driven tests with `t.Run` for isolation and subtest selection.
  - Keep helper functions at the bottom of the test file; use `t.Cleanup` for teardown.
- **Data Handling:**
  - Use backtick raw string literals (`` ` ``) for multi-line test data, regexes, and assembly.
  - Use `AUTO` in syzlang tests for auto-computing lengths and offsets.
  - Use `timeNow` over `time.Now` for deterministic test stubbing.
- **Robustness:**
  - Run tests with `-race` to surface data races.
  - Check for goroutine leaks in tests using background concurrency.
  - Test boundary conditions (e.g., empty slices, index limits, or corrupted inputs).
  - Never just disable failing tests; fix them or document why they are disabled.
  - Include sample reports in `pkg/report/testdata` for new crash parsers.

## 4. Architecture & Design
- **YAGNI (You Ain't Gonna Need It):**
  - Don't add code "just in case"; remove unused types, fields, and dead code immediately.
  - Avoid unnecessary tunables/config flags; pick sensible defaults and scale timeouts.
- **Decoupling:**
  - Keep logic uniform across different execution modes (e.g., fork-server vs no-fork-server).
  - Use standard interfaces (e.g., `io.Closer`) over custom cleanup methods.
  - Prefer specific, descriptive package names over generic ones like `util` or `generic`.
  - Prioritize larger, coherent packages over many micro-packages.
- **State Management:**
  - Favor simple state tracking (single counter/slice) over complex nested maps.
  - Use fields in the `targets.Target` struct (often referred to as Arch struct) instead of logic-driven switches for architecture differences.
  - Pass objects/pointers early instead of passing IDs and doing repeated lookups.

## 5. Performance & Resource Management
- **Efficiency:**
  - Use map lookups (O(1)) instead of double loops (O(N^2)) for filtering.
  - Avoid casting large buffers to strings if only byte processing is needed.
  - Prefer direct slicing over `io.Reader` for byte processing to reduce garbage.
  - Avoid `bufio.Writer` when writing to `bytes.Buffer`.
- **Resource Cleanup:**
  - Always `Wait()` on launched commands; use `defer` to close file descriptors and pipes.
  - Extract loop bodies into functions if they use `defer` to ensure per-iteration cleanup.
- **Concurrency:**
  - Use channels for semaphores or async notifications; use capacity 1 to prevent blocking.
  - Use `nil` channels to disable `select` cases.
  - Ensure condition variables are checked in a loop to prevent race hangs.
  - Avoid infinite goroutine spawning in pools; track wait states.

## 6. Logging & Observability
- **Hygiene:**
  - Use the internal `log` package consistently; avoid mixing multiple logger libraries.
  - Log only actionable information at verbosity 0; use info logs for invalid user requests.
  - Don't suffix log messages with newlines (`\n`).
  - Format string safety: use `Logf(1, "%s", out)` instead of `Logf(1, out)`.
- **Determinism:** Always sort map keys when serializing to persistent formats (configs, logs, coverage).
- **Metrics:** Rename existing metrics rather than adding confusing duplicates when semantics change.
- **Reporting:** Keep email prefixes short; e.g. explain why something was skipped in bisection logs.

## 7. Syzkaller Specifics (Syzlang & Executor)
- **Syzlang (files in `sys/*/*.txt`):**
  - Use exact kernel field names; use descriptive prefixes to avoid collisions.
  - Use `const[0]` for reserved/unused fields to optimize mutation.
  - Use `ignore_return` for syscalls returning random system IDs or times.
- **Executor (C++ files in `executor`):**
  - Keep `executor.cc` free of OS-specific `#ifdefs`; use OS-specific headers.
  - Use `const std::string&` or `std::string_view` for immutable strings.
  - Check for short writes in output loops.
  - Avoid C89 start-of-block declarations; combine declaration and initialization.

## 8. Tooling & Infrastructure
- **CLI Tools:**
  - Standardize on `tool.Init()` and `tool.Failf()` from `pkg/tool`.
  - Declare CLI flags in `main()` to avoid global namespace pollution.
  - Use `runtime.NumCPU()` for default worker counts.
- **OS Operations:**
  - Use `filepath.Join` for OS-agnostic paths; use `osutil.IsExist` for existence checks.
  - Combine multiple shell commands (e.g., `adb shell 'cmd1; cmd2'`) to reduce overhead.
- **HTML/UI:**
  - Use standard `<details>` and `<summary>` for collapsibles.
  - Use tabs for HTML templates.
