# C Reproducer Generation Workflow

## Objective
Generate strictly standalone C reproducers from textual bug descriptions. This workflow is used to verify bugs and their fixes in an isolated environment.

## Current Implementation State

The workflow is registered as `repro-c` and consists of a preprocessing phase followed by an iterative loop that attempts to generate and verify a reproducer.

### Inputs
- `BugDescription`: Textual description of the bug.
- `KernelRepo`: Git repository URL.
- `KernelCommit`: Commit hash to checkout.
- `KernelConfig`: Kernel configuration.
- `Image`: Path to the VM image.
- `Type`: VM type (e.g., "qemu" or "gce").
- `VM`: JSON raw message for VM configuration.
- `Syzkaller`: Path to syzkaller directory.

### Preprocessing
1.  **Kernel Setup**: The workflow starts by checking out the kernel source (`kernel.Checkout`) and building it (`kernel.Build`).
2.  **Index Preparation**: Prepares the codesearch index (`codesearcher.PrepareIndex`).
3.  **Initial Research**: The `initial-researcher` agent analyzes the bug description and generates an initial reproduction strategy (`InitialReproStrategy`). It has access to codesearch and grep tools, as well as the toolkit query tool.

### Iterative Loop
The workflow enters a `DoWhile` loop with a maximum of 20 iterations. The loop condition is controlled by `ContinueSignal`.

In each iteration, the following steps are executed:
1.  **Strategy Refinement**: If `OracleFeedback` is available (from previous iterations), the `strategy-refiner` agent is invoked to update the strategy, producing `RefinedReproStrategy`.
2.  **Strategy Merge**: `MergeStrategy` merges `InitialReproStrategy` and `RefinedReproStrategy` into `CurrentReproStrategy`. If a refined strategy exists, it is preferred.
3.  **Code Generation**: The `repro-generator` agent generates C code (`RawCandidateReproC`) and a boolean `IsProbe` flag based on `CurrentReproStrategy`.
    *   **Structured Probe Strategy**: The generator is instructed to prioritize a simple "probe" program to verify subsystem availability and kernel privileges (both on the very first attempt, or if a previous probe failed). It sets `IsProbe` to `true` for environment probes, and `false` for full reproducer candidates attempting to trigger the crash.
4.  **Self-Repair & Toolkit Expansion**: The workflow enters a nested `DoWhile` loop (max 3 iterations) to handle compilation failures:
    *   **Toolkit Expansion & Compilation**: `CompileCProg` action replaces `#include "race_toolkit.h"` with the
        actual content of the race toolkit and attempts to compile the program.
        *   **Race Condition Toolkit**: The toolkit (`race_toolkit.h`) provides pre-defined C snippets and macros
            for advanced race setups: CPU pinning (`PIN_TO_CPU`), memory barriers (`MB`), spin-wait barriers
            (`WAIT_ON`/`SIGNAL`), userfaultfd (`setup_uffd`), and robust timing primitives (`TIMER_START`,
            `TIMER_NOT_EXPIRED`) designed to survive clock resets/drifts in minimal QEMU VM environments.
    *   **Success**: If compilation succeeds, it outputs `FormattedReproC` and clears `CompilerError` to exit the repair loop.
    *   **Repair**: If compilation fails, the `repro-repairer` agent is invoked to fix the code based on the compiler error, updating `RawCandidateReproC` for the next attempt.
5.  **Execution**: `crash.RunCRepro` runs the candidate reproducer in the VM. It returns whether it reproduced the crash, the console output, and crash report details if successful.
6.  **Log Truncation**: `TruncateLog` keeps the last 200 lines of console output to fit LLM context limits.
7.  **Oracle Analysis**: The `repro-oracle` agent analyzes the execution results using the structured `IsProbe` flag to branch its logic:
    *   **If `IsProbe` is true**: A successful run (all capability checks passed) confirms the environment is ready, and the Oracle instructs the generator to proceed to the full reproducer. A failed run prompts feedback on which capabilities failed to help the generator adjust its setups.
    *   **If `IsProbe` is false**: A successful execution (exit 0) WITHOUT a crash means reproduction failed to trigger the bug (NOT a successful probe). The Oracle analyzes strace/console output to tighten the race window or adjust input parameters.
8.  **Loop Control**: `LoopController` determines if the loop should continue:
    *   If successful reproduction occurred and the title matches, it promotes the candidate to the final output and stops (`ContinueSignal` becomes empty).
    *   If a collision is detected (different crash), it provides feedback and continues.
    *   Otherwise, it continues.

### Output
- `Reproduced`: Boolean flag indicating success.
- `ReproC`: The successful C reproducer code.
- `ReproducedBugTitle`: Title of the reproduced crash.
- `ReproducedCrashReport`: Full crash report.

---

## Potential Improvements

### Robust Execution Analysis
- **Hang Detection**: Explicitly distinguish between clean exits and timeouts (hangs) in the VM to provide clearer signals to the Oracle.

### Iteration Tracking
- **Iteration Count Injection**: Inject `IterationCount` into the loop state so that agents can adapt their strategy based on how many attempts are left (e.g., Oracle deciding to stop refining on the final attempt).

### Scalable Analysis
- **Advanced Log Management**: Implement specialized tools for the Oracle to grep for patterns or paginate through logs if they exceed the context window.
- **Dynamic Platform Brief**: Augment the generation guide with target-specific kernel details.
