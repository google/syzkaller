# Proposal: AI-Driven Reproducer Generation Workflow

## 1. Objective
To design a new AI agent workflow within the syzkaller `aflow` framework (`pkg/aflow/flow/repro/repro.go`) that
automatically converts a kernel crash report (and associated execution logs) into a reliable
syzkaller reproducer (syzlang).
The agent will leverage existing syzlang descriptions (`sys/linux/*.txt`) to ensure the generated reproducers conform
to syzkaller's type system and API constraints.

First step is to generate the MVP that works and allows to parallelize the work. If some tool or feature may be
postponed it is better to postpone it.

## 2. High-Level Architecture & Agent Loop

The workflow will operate as an iterative feedback loop, utilizing the LLM's reasoning capabilities to bridge the gap
between a crash signature and a functional syzlang program.

1. **Context Initialization:** Ingest the kernel crash log with stack trace,
target kernel information (`.config`, `kernel repo`, `kernel commit`) and
the raw execution log leading up to the crash (if available from the fuzzing instance).
Core dump and kcov traces will be of great help when available.
   * MVP will get all the available information from syzbot dashboard. Bug ID is the input.
2. **Subsystem Analysis:** Identify the vulnerable subsystem (e.g., `io_uring`, `bpf`, `ext4`) based on the stack trace.
   * It will be needed to support requests w/o subsustem name. It is not needed for syzbot.
   * MVP gets subsystem information from dashboard.
3. **Syzlang Contextualization:** Query the syzlang descriptions to extract the relevant syscall signatures, structs,
and valid flags for the identified subsystem.
   * MVP tries to get ALL the descriptions assuming LLM context is big enough.
   * `$ cat *.txt | wc -l` gives 57k lines thus MVP may rely on all the descriptions.
4. **Draft Generation:** The LLM generates an initial candidate `.syz` reproducer.
5. **Execution & Verification:** Compile and run the candidate against an instrumented kernel VM.
   * MVP reuses syzkaller code to verity programs.
   * Note: The generated crash may be different from the original one (e.g. different stack trace, but same root cause).
   * We need to verify that the produced crash is "very close" to the original one (e.g. same function, same type).
   * TODO: explore execution options. See open questions.
6. **Iterative Refinement:** If the crash does not reproduce, or if there is a syzlang compilation error, the agent
analyzes the failure output, tweaks the arguments/syscall sequence, and tries again (up to a defined maximum
iteration limit).

## 3. Required Framework Extensions

To achieve this, the `aflow` framework will need new tools and actions specifically tailored for syzlang manipulation
and program execution.

### A. New Tools (`pkg/aflow/tool`)
No tools are needed for MVP.
* `SyzlangSearch`: A tool allowing the LLM to search for syzlang definitions.
    * *Input:* Subsystem name, syscall name, or resource type (e.g., `Search("bpf_prog_load")`).
    * *Output:* The syzlang syntax block defining the syscall, its arguments, and dependent structures from `sys/linux/`.
    * For declextract we build kernel call graph, so we know which syzlang entry points can reach what kernel functions.
* *Modification to Source Browser:* Currently the source browser only allows to read kernel sources.
  Ensure the existing source browsing tools can read `sys/` directory
contents natively, so the LLM can cross-reference kernel source with syzlang API constraints.

### B. Actions (`pkg/aflow/action`)
For MVP we need only `crash.Reproduce` (existing) and `SyzCompilerCheck`.
* `crash.Reproduce`: Runs the generated program in the test VM.
  * *Input:* Valid `.syz` program.
  * *Output:* Kernel log delta, crash signature produced (if any), and dmesg output.
  * Note: reusing `pkg/aflow/action/crash`. If changes are needed, we will modify it.
* `SyzCompilerCheck`: Validates the LLM-generated `.syz` program syntax.
    * *Input:* Raw syzlang text.
    * *Output:* Success, or a list of syntax/type errors from the syzkaller compiler.
    * TODO: this functionality is likely available in syzkaller.
* `CompareCrashSignature`: Evaluates if the produced crash matches the target crash we are trying to reproduce.
  * A better approach may be to evaluate the distance between the original and found crash points.
  * We accept the crash if it is very close to the original one (e.g. same function, same type of bug).

## 4. Implementation Plan

### Phase 1: Tooling & Infrastructure (Foundation)
* **Implement `SyzlangSearch` tool:** Parse the AST of `sys/linux/` and expose a search interface to the agent.
* **Reuse `crash.Reproduce` action:** Reuse the logic from `pkg/aflow/action/crash` so the agent can trigger executions inside the isolated
test VMs already managed by `aflow`'s checkout/build actions. Modify it if necessary.

### Phase 2: Prompt Engineering & Context Management
For MVP we don't care about the Context Window Optimization.
* **System Prompt:** Define the persona.
(e.g., *"You are an expert kernel security researcher. Your goal is to write a syzkaller program to trigger
a specific bug. Use syzlang syntax strictly."*)
* **Context Window Optimization:** Kernel logs and syzlang files can be large.
Implement truncation and selective inclusion for dmesg and syzlang structs to avoid blowing out the token limit.

### Phase 3: Workflow Implementation (`pkg/aflow/flow/repro/repro.go`)
* Wire the state machine. Initialize the flow with the bug report ID.
* Implement the iterative loop: *Generate -> Compile -> Execute -> Evaluate -> Refine*.
* Implement exit conditions: Success (matching crash signature produced), Max Iterations Reached,
or Unrecoverable Error.

### Phase 4: Evaluation & Syzbot Integration
* Test the workflow against historical syzbot bugs to measure the agent's success rate and iteration average.
  * Note: We don't need the known reproducers to measure success because the crash point is defined by the call stack.
  * Success is defined as triggering a crash "very close" to the original one (same root cause).
* Deploy as an experimental job type on `syzbot.org/upstream/ai`.

## 5. Open Questions for Discussion
* Is it better to run syz-manager in MCP mode or create the new tool?
* How to verify the generated program? It is likely already implemented.