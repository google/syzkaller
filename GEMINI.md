# syzkaller - Context for Gemini

## Project Overview
`syzkaller` is an unsupervised, coverage-guided kernel fuzzer. It is a hybrid
system consisting of a **Go-based manager** (running on a host) and a **C++
executor** (running inside the target VM).

-   **Primary Language:** Go (Manager, Tools), C++ (Executor).
-   **Architecture:**
    -   `syz-manager`: Orchestrates the fuzzing process, manages corpus, and monitors VMs.
    -   `syz-executor`: Runs inside the VM, executes test programs via syscalls, and collects coverage.
    -   `syz-ci`, `syz-hub`, `dashboard`: Infrastructure for continuous fuzzing and reporting.

## Building and Testing

Prefer to use the `syz-env` Docker container to build the compontents and run
tests. There's a `./tools/syz-env` script that will start a container and run
the given command inside it.

Some reference commands:
* Build everything: `CI=true ./tools/syz-env make`.
* Run a linter: `CI=true ./tools/syz-env make lint`.
* Run a test: `CI=true ./tools/syz-env go test ./package -run TestName`.
* Formatter: `CI=true ./tools/syz-env make format` (runs `gofmt`, `clang-format`, etc).

Note the `CI=true` part - otherwise the commands may not run in your environment.

When running tests (especially in `./prog` and `./pkg/csource`) prefer to run
individual tests you have affected, otherwise it may take a lot of time. Some
packages also offer a `-short` flag to run a lighter version of tests.

It may be necessary to first run `CI=true ./tools/syz-env make descriptions` to
pre-build descriptions for the `sys/*` targets. It may be necessary for all
tests that eventually use `prog.Target` or `targets.Target`.

## Key Directories

-   `syz-manager/`: Entry point for the main fuzzing manager.
-   `executor/`: C++ source code for the test program executor.
-   `pkg/`: Core Go libraries:
    -   `pkg/ipc`: IPC mechanism between manager and executor.
    -   `pkg/fuzzer`: Fuzzing logic.
    -   `pkg/manager`: Manager logic library.
-   `sys/`: System call descriptions (essential for the fuzzer to know how to call the kernel).
    -   `sys/linux/`: Linux-specific descriptions (`.txt` and `.const`).
-   `tools/`: Helper utilities (`syz-repro`, `syz-mutate`, etc.).
-   `docs/`: Extensive documentation on setup, internals, and contribution.

## Development Conventions

-   **Commit Messages:** Strict formatting required.
    -   Format: `dir/path: description` (e.g., `pkg/fuzzer: fix crash in minimization`).
    -   No trailing dot in the summary.
-   **Testing:** New features must have tests.
-   **Formatting:** Always run `make format` before committing.
-   **Syscall Descriptions:** When modifying `sys/*/*.txt`, `make generate` must be run to update generated code.
-   **Copyright:** When you add new .go files, make sure to add the copyright header to them (use other .go files for reference and update the year to the current one).
