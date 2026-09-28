# syzkaller - Agentic Flow (aflow)

`pkg/aflow` is a framework for building "Agentic Flows"-workflows that leverage LLMs (specifically Gemini).

## Project Overview

The `aflow` package provides a structured way to define and execute workflows composed of both traditional code
and AI agents. It is used in `syzkaller` for high-level automated tasks such as:
- **Patching**: Automatically generating and refining kernel patches.
- **Moderation**: Assessing the impact and actionability of bug reports.
- **Reproduction**: Finding ways to reproduce reported crashes (both syzkaller and C reproducers).
    See [crash-to-repro.md](docs/crash-to-repro.md) and
    [c-repro-from-description.md](docs/c-repro-from-description.md) for workflow design documents.
    Reproducer workflows often run generated code multiple times (e.g., executing with and without
    `strace`, or iterating through a repair loop) to gather debugging context.
- **Assessment**: Analyzing KCSAN and security reports.

### Core Concepts

- **Flow**: A high-level workflow definition that specifies inputs, outputs, and a sequence of
    actions. Workflows can also define constant variables available to all actions via `Flow.Consts`.
- **Action**: A single step in a flow.
    - **LLMAgent**: An AI agent powered by Gemini. It can be given instructions, a prompt, and a
        set of tools.
    - **FuncAction**: A standard Go function wrapped to be used as a workflow step.
    - **Control Flow**: Actions like `aflow.Pipeline`, `aflow.DoWhile`, `aflow.If`, and `aflow.ForEach`
        provide sequencing, conditional execution, and iteration within a flow.
- **Tool**: A capability provided to an `LLMAgent`.
    - **FuncTool**: A Go function exposed to the LLM.
    - **LLMTool**: A nested `LLMAgent` exposed as a tool to a parent agent, allowing for hierarchical reasoning.
- **Context**: Carries execution state, manages persistent caching (to avoid redundant LLM calls),
    and tracks execution history.
- **Trajectory**: A hierarchical log of "spans" (Flow, Action, Agent, LLM, Tool) that records the entire execution path,
    including LLM thoughts and token usage.

## Building and Running

Since `aflow` is a Go package within `syzkaller`, it is managed using standard Go tools,
typically through the `syz-env` wrapper.

### Common Commands

- **Run Tests**: `./tools/syz-env go test ./pkg/aflow/...`

## Development Conventions

### State Variable Naming Conventions

To allow actions and workflows to be composed without complex renaming logic, we attach **semantic
meaning** to state variable names rather than just using raw types. When adding or reusing state
variables, check existing definitions in:
- `pkg/aflow/ai/ai.go` and `pkg/aflow/flow/*` for workflow inputs and outputs.
- `pkg/aflow/action/*` for shared action inputs and outputs.
- `pkg/aflow/tool/*` for shared tool state parameters.

### Defining Workflows

Workflows are typically registered using `aflow.Register` and imported in `pkg/aflow/flow/flows.go`.
- Use `Args` and `Results` structs for `FuncAction` and `FuncTool`.
- Use `jsonschema` struct tags to provide descriptions for LLM tool parameters and outputs (and
    `json:",omitempty"` for optional fields). Keep `jsonschema` descriptions short and concise
    (fitting on a single line), and put detailed rules, criteria, or examples into the agent's
    `Instruction` (or tool description) instead.
- Define `WorkflowType` and output structs in `pkg/aflow/ai/ai.go`.

### Implementing Tools
- Tool names (the first string argument to `aflow.NewFuncTool`) should use `lowercase-with-dashes` instead of `CamelCase`.
- If a tool does not refer to the kernel state or checkout path, declare its state parameter directly as `state struct{}` in the function signature, instead of defining an empty struct type.
- When registering tools for an `LLMAgent`, **always** use `aflow.Tools(tool1, tool2, toolSlice...)` to avoid aliasing issues that can occur when combining slices of tools. Do not use standard `append()` or `[]aflow.Tool{...}` literal initializations when combining or adding to existing tool sets.

### LLM Integration

- **Models**: Use `aflow.DeepReasoningModel` (Pro) for complex causal reasoning, architectural planning, and security impact analysis.
    Use `aflow.CoreModel` (latest Flash) as the primary workhorse for agentic execution, C coding, review loops, and sub-agents.
    Use `aflow.LightweightModel` (Flash) for low-overhead text/tag extraction and context compression.
- **Validation & Output Formatting**: Structured outputs can be validated using
    `ValidatedLLMOutputs` (or `LLMReply` for text replies). If validation fails, an error is
    returned to the LLM as a `BadCallError`, creating a tight feedback loop for self-correction.
- **Caching**: LLM responses are cached by default based on the prompt, configuration, and history.
    This is crucial for development and cost management.
- **Error Handling**: Use `aflow.BadCallError` when an LLM provides invalid tool arguments to
    allow it to self-correct.

### MCP Integration

Workflows and tools can be exposed via the Model Context Protocol (MCP) in `mcp.go`.
A `session-initializer` tool is generally used first to set up initial workflow arguments in
MCP mode.

### Testing

- Most components have corresponding `_test.go` files.
- Trajectory spans are essential for debugging and are often validated in tests.
