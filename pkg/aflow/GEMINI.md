# syzkaller - Agentic Flow (aflow)

`pkg/aflow` is a framework for building "Agentic Flows"-workflows that leverage LLMs (specifically Gemini).

## Project Overview

The `aflow` package provides a structured way to define and execute workflows composed of both traditional code
and AI agents. It is used in `syzkaller` for high-level automated tasks such as:
- **Patching**: Automatically generating and refining kernel patches.
- **Moderation**: Assessing the impact and actionability of bug reports.
- **Reproduction**: Finding ways to reproduce reported crashes.
- **Assessment**: Analyzing KCSAN reports for confidence and benignity.

### Core Concepts

- **Flow**: A high-level workflow definition that specifies inputs, outputs, and a sequence of actions.
- **Action**: A single step in a flow.
    - **LLMAgent**: An AI agent powered by Gemini. It can be given instructions, a prompt, and a set of tools.
    - **FuncAction**: A standard Go function wrapped to be used as a workflow step.
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

### Defining Workflows

Workflows are typically registered using `aflow.Register`.
- Use `Args` and `Results` structs for `FuncAction` and `FuncTool`.
- Use `aflow` struct tags or comments to provide descriptions for LLM tool parameters.
- Define `WorkflowType` in `pkg/aflow/ai/ai.go`.
- First commit is better to be the simplest possible workflow definition without new tools.
    Commit `pkg/aflow: repro workflow skeleton` is an example.

### LLM Integration

- **Models**: Prefer `aflow.GoodBalancedModel` (Flash) for simple tasks and `aflow.BestExpensiveModel` (Pro)
    for complex reasoning.
- **Caching**: LLM responses are cached by default based on the prompt, configuration, and history.
    This is crucial for development and cost management.
- **Error Handling**: Use `aflow.BadCallError` when an LLM provides invalid tool arguments to allow it to self-correct.

### Dashboard integration

It is important to keep the dashboard integrated with dashboard through `../syz-agent`. We need this integration to be
in place from the very first commit.

### Testing

- Most components have corresponding `_test.go` files.
- Trajectory spans are essential for debugging and are often validated in tests.
