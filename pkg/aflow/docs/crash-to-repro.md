# Proposal: AI-Driven Reproducer Generation Workflow

## 1. Objective
An AI agent workflow within the syzkaller `aflow` framework (`pkg/aflow/flow/repro/repro.go`) that
automatically converts a kernel crash report (and associated execution logs) into a reliable
syzkaller reproducer (syzlang).
The agent leverages existing syzlang descriptions (`sys/linux/*.txt`) to ensure the generated reproducers conform
to syzkaller's type system and API constraints.

## 2. High-Level Architecture & Agent Loop

The workflow operates as an iterative feedback loop, utilizing the LLM's reasoning capabilities to bridge the gap
between a crash signature and a functional syzlang program.

1. **Context Initialization:** Ingest the kernel crash log with stack trace,
      target kernel information (`.config`, `kernel repo`, `kernel commit`) and
      the raw execution log leading up to the crash (if available from the fuzzing instance).
      Core dump and kcov traces are of great help when available.
   * The workflow gets all the available information from syzbot dashboard using the Bug ID as input.
2. **Subsystem Analysis:** Identify the vulnerable subsystem (e.g., `io_uring`, `bpf`, `ext4`) based on the stack trace.
3. **Syzlang Contextualization:** Query the syzlang descriptions to extract the relevant syscall signatures, structs,
      and valid flags for the identified subsystem.
   * The prompt passes existing description filenames, and the LLM agent uses the `read-description` tool to lookup exact descriptions dynamically.
4. **Draft Generation:** The LLM generates an initial candidate `.syz` reproducer.
5. **Execution & Verification:** Compile and run the candidate against an instrumented kernel VM.
   * The LLMAgent uses the `reproduce-crash` tool to compile and execute the generated program directly in a loop. The tool also reports the triggered bug title and crash report.
   * Note: The generated crash may be different from the original one (e.g. different stack trace, but same root cause).
   * We need to verify that the produced crash is "very close" to the original one (e.g. same function, same type).
6. **Iterative Refinement:** If the crash does not reproduce, or if there is a syzlang compilation error, the agent
      analyzes the failure output, tweaks the arguments/syscall sequence, and tries again (up to a defined maximum
      iteration limit). This iteration logic is fully offloaded to the LLM agent instruction capabilities.

## 3. Required Framework Extensions

The `aflow` framework introduces tools and actions specifically tailored for syzlang manipulation
and program execution.

### A. New Tools (`pkg/aflow/tool`)
Several critical tools are introduced for the LLM agent to iterate effectively:
* `read-description`: Takes a file name and returns the content of the syzlang description file.
* `reproduce-crash`: Takes a `.syz` program, parses and deserializes it to catch compilation/syntax errors, then executes it in a test VM. Returns the triggered bug title, crash report, and a `CoverageID`.
* `get-coverage-files` & `get-file-coverage`: Tools taking a `CoverageID` to inspect which source files and executed functions/lines were covered.
* `codesearcher` & `grepper`: Tools enabling the LLM to inspect the Linux kernel source code and stack context on the fly.

### B. Actions (`pkg/aflow/action`)
The core workflow (`repro.go`) implements a linear pipeline combining kernel building actions with
reasoning and testing modules:
* `kernel.Checkout` and `kernel.Build`: Ensure the vulnerable kernel image is ready.
* `codesearcher.PrepareIndex`: Prepares a code search index.
* `aflow.LLMAgent`: Configured as `crash-repro-finder`, taking responsibility for the iterative
   *Generate -> Compile -> Execute -> Compare* loop using the newly defined `pkg/aflow/tool` set.
* `actionsyzlang.Format`: Formats the generated `.syz` program text.
* `crash.Reproduce`: Pipeline action running the ultimately verified `.syz` code inside the test VM.
* `aflow.Compare`: A generic variable comparison helper comparing if the produced crash directly matches the target bug title.

## 4. Implementation Plan

### Phase 1: Tooling & Infrastructure (Foundation)
* **Implement `read-description` tool:** Parse the AST of `sys/linux/` and expose a search interface to the agent.
* **Reuse `crash.Reproduce` action:** Reuse the logic from `pkg/aflow/action/crash` so the agent can trigger executions inside the isolated
   test VMs already managed by `aflow`'s checkout/build actions. Modify it if necessary.

### Phase 2: Prompt Engineering & Context Management
We don't care about the Context Window Optimization yet.
* **System Prompt:** Define the persona.
   (e.g., *"You are an expert kernel security researcher. Your goal is to write a syzkaller program to trigger
   a specific bug. Use syzlang syntax strictly."*)
* **Context Window Optimization:** Kernel logs and syzlang files can be large.
   Implement truncation and selective inclusion for dmesg and syzlang structs to avoid blowing out the token limit.

### Phase 3: Workflow Implementation (`pkg/aflow/flow/repro/repro.go`)
* Setup is a linear pipeline orchestrating `Checkout` -> `Build` -> `codesearcher.PrepareIndex` -> `LLMAgent` -> `Format` -> `Reproduce` -> `compare`.
* Implement the iterative loop: The loop structure (*Generate -> Compile -> Execute -> Evaluate -> Refine*) is
   abstracted and delegated entirely to the `LLMAgent`'s instructions, taking advantage of syzkaller tool execution.
* Implement exit conditions: Success (matching crash signature produced or tool exit rules), handled seamlessly.

### Phase 4: Evaluation & Syzbot Integration
* Test the workflow against historical syzbot bugs to measure the agent's success rate and iteration average.
   * Note: We don't need the known reproducers to measure success because the crash point is defined by the call stack.
   * Success is defined as triggering a crash "very close" to the original one (same root cause).
* Deploy as an experimental job type on `syzbot.org/upstream/ai`.

## 5. Resolved Design Decisions
* **`syz-manager` MCP mode vs separate runner:** Created a dedicated `syz-aflow` command-line tool
    (`tools/syz-aflow`) to invoke local workflows using JSON context inputs avoiding the complexity of modifying
    `syz-manager` directly.
* **Program verification logic:** Reused existing parsing directly via `prog.GetTarget("linux",
    "amd64").Deserialize(...)` embedded inside the `reproduce-crash` tool, keeping verification reliable and
    fast.

