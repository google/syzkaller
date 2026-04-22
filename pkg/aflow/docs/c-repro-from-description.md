# Design Plan: C Reproducer Generation Workflow (Phased)

## Objective
Implement a new `aflow` workflow to generate strictly standalone C reproducers from textual bug descriptions, starting from the skeleton in commit `f42ae9b8d68dcd64a163026fcabc35cba17ff764`.

## Phase 1: MVP (Filling the Skeleton Gaps)
The goal of this phase is to transform the single-agent skeleton into a functional, iterative reproduction loop with robust state management.

### 1. Structure & Registration
- **Workflow Name**: Use the registered `ai.WorkflowReproC` ("repro-c").
- **Inputs**: Update the existing `ReproCInputs` in `pkg/aflow/flow/reproc/reproc.go` to include:
  - Infrastructure: `Image`, `Type`, `VM` (json.RawMessage), `Syzkaller` (directory path).
- **Output Struct**: Update the existing `ReproCOutputs` in `pkg/aflow/ai/ai.go` to include:
  - `Reproduced`: Success flag (true only if bug identity is verified).
  - `ReproducedBugTitle`: Title of the verified crash.
  - `ReproducedCrashReport`: Full verified report.
- **Initialization**: Note that `OracleFeedback` is NOT initialized in `Flow.Consts` (as that causes overwrite conflicts in `aflow`). Instead, `aflow.DoWhile` auto-initializes it as a loop variable to an empty string before the loop starts.

### 2. Core Workflow (Iterative Loop)
Expand the `Root` pipeline in `pkg/aflow/flow/reproc/reproc.go` into a multi-agent iterative loop.

**Pipeline Structure**:
1. `kernel.Checkout`: Checkout the kernel source.
2. `kernel.Build`: Build the kernel.
3. `codesearcher.PrepareIndex`: Prepare the codesearch index (required by codesearcher tools).
4. `initial-researcher`: LLM Agent (outside loop) that generates an initial `InitialReproStrategy` from the `BugDescription`. **Tools**: Access to `codesearcher` and `grepper` for deep analysis.
5. `aflow.DoWhile` loop:
   - **MaxIterations**: 5
   - **While Variable**: `ContinueSignal` (string bridge).
   - **Actions (Inside Loop)**:
     - `strategy-refiner`: Conditional logic implemented using a new `aflow.If` action.
       - **Mechanism**: `aflow.If("OracleFeedback", strategy_refinement_agent)`.
       - **Behavior**: If `OracleFeedback` is empty (Iteration 1), the agent is skipped. If non-empty, the agent is invoked to pivot the strategy. Outputs `RefinedReproStrategy`.
     - `merge-strategy`: `FuncAction` that merges `InitialReproStrategy` and `RefinedReproStrategy` into `CurrentReproStrategy` to avoid overwrite conflicts.
     - `repro-generator`: LLM Agent that generates C code into `CandidateReproC` using `CurrentReproStrategy`. **Tools**: Access to `codesearcher` and `grepper`.
     - `FormatC`: `FuncAction` wrapping `csource.Format` on `CandidateReproC`. Outputs `FormattedReproC` to avoid conflict.
     - `run_c_repro`: Specialized wrapper in `pkg/aflow/action/crash/run_c_repro.go`. Returns `CandidateReproduced` (bool), `ConsoleOutput` (raw), and unverified `CandidateBugTitle`/`CandidateCrashReport`. **Timeout**: Reduced to a fixed 3 minutes for C reproducers to avoid long waits on hangs.
     - `TruncateLog`: `FuncAction` that returns the last 200 lines of `ConsoleOutput` as `TruncatedConsoleOutput`. `CandidateCrashReport` is passed through intact as `TruncatedCrashReport`.
     - `repro-oracle`: LLM Agent using `aflow.LLMOutputs` to return: `{Feedback: string, ShouldContinue: bool, TitleMatches: bool}`. **Tools**: `codesearcher` and `grepper`. **Inputs**: Includes `CandidateBugTitle` and `BugDescription` for comparison.
       - **Instruction**: When `CandidateReproduced` is false, analyze `TruncatedConsoleOutput` for execution patterns (hangs, immediate exits, syscall failures).
     - `loop-controller`: `FuncAction` that:
       - Converts `ShouldContinue` to `ContinueSignal`.
       - **Promotion**: Promotes `CandidateReproC` to the final `ReproC` output ONLY if `TitleMatches` AND `CandidateReproduced` are true. Sets workflow output `Reproduced` to true.
       - If `CandidateReproduced` is true but `TitleMatches` is false, sets `ShouldContinue = true` and provides collision feedback.
6. `save-repro-c`: `FuncAction` (outside loop) that saves the successful reproducer to `repro.c` in the workdir.

### 3. Diagnostics & Context Management
- **Exhaustion**: If the loop finishes without a successful match, `ReproC` is left empty and `Reproduced` is `false`.
- **Platform Brief**: Static system instruction providing basic standalone C best practices.

---

## Phase 2: Advanced Enhancements (Polishing & Robustness)
Once the MVP is functional, these features will improve diagnostic depth and reliability.

### 1. Robust Execution Analysis
- **Compiler Feedback**: Modify `run_c_repro` to capture host-side `CompilerError` and provide it to the Oracle.
- **Hang Detection**: Explicitly distinguish between clean exits and timeouts (hangs) in the VM.
- **Diagnostics Priority**: The Oracle prioritizes `CompilerError` then `TruncatedConsoleOutput`.

### 2. Iteration Tracking
- **Iteration Tracking**: Inject `IterationCount` into the loop state.
- **Graceful Termination**: The Oracle uses the count to decide when to stop refining on the final attempt.

### 3. Scalable Analysis
- **Advanced Log Management**: Implement specialized tools for the Oracle to grep for patterns or paginate through logs.
- **Dynamic Platform Brief**: Augment the generation guide with target-specific kernel details.

---

## Key Files & Context
- `pkg/aflow/flow/reproc/reproc.go`: Workflow implementation.
- `pkg/aflow/action/crash/run_c_repro.go`: Specialized execution wrapper.
- `pkg/aflow/ai/ai.go`: Central output definitions.

## Verification & Testing
- Unit tests for new actions (`run_c_repro`, `FormatC`, `loop-controller`, `TruncateLog`).
