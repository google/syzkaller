# Design Document: JIT AI Summarization System for the Linux Kernel

## 1. Overview & Objectives

**Goal:** Provide LLM-based agentic tools with high-signal, low-noise context about the Linux kernel source code to enable automated reasoning, bug fixing, and explanation.

**Challenge:** The Linux kernel is massive (>30M LOC) and complex. Providing raw source code to an LLM is inefficient and often exceeds context windows.

**Solution:** **Just-In-Time (JIT) Summarization**. The system uses deterministic static analysis (Clang AST) to prune noise and LLM-powered semantic analysis (Gemini) to capture intent, invariants, and architectural details.

---

## 2. System Architecture

The system operates as a specialized Retrieve-then-Reason pipeline.

### Core Components

1.  **Static Analyzer (C++)**:
    *   **Tool**: `tools/clang/glance` (LibClang based).
    *   **Function**: Parses the AST using `compile_commands.json` to resolve macros and types. This dependency is critical: files not in the compilation database (e.g., due to disabled CONFIG options) cannot be fully analyzed.
    *   **Noise Reduction**: Filters out unreferenced headers and irrelevant code.
    *   **Feature Extraction**: Identifies function complexity, locking primitives, exported symbols (`EXPORT_SYMBOL`), included headers, and referenced `CONFIG_` variables.
    *   **Robustness**: Handles missing entries in `compile_commands.json` by probing for known kernel files (`init/main.c`, etc.) to deduce source root relocation, essential for containerized environments.

2.  **JIT Orchestrator (Go)**:
    *   **Package**: `pkg/glance`.
    *   **Function**: Manages the request lifecycle.
    *   **Flight Map**: Coalesces concurrent requests for the same file to prevent redundant work.
    *   **Summary Store**: A filesystem-based cache storing generated `.md` files in `${KERNEL_SRC}/glance/`, mirroring the source tree (e.g., `linux/glance/mm/kfence/core.c.md`).

3.  **LLM Integration**:
    *   **Package**: `pkg/aflow` (Gemini).
    *   **Function**: Generates semantic summaries based on the structural context provided by the analyzer.
    *   **Directory Aggregation**: Synthesizes file-level summaries into subsystem-level documentation (`README.md`).

---

## 3. Data Model

### The Summary File (`.summary.md`)

The output is a Markdown file with YAML frontmatter, designed for both human readability and machine parsing.

```markdown
---
path: "mm/kfence/core.c"
source_hash: "da39a3ee5e6..." # SHA1 hex digest of the source file content
description: "One-line description of the file/directory."
provided_apis: ["vfs_open", "vfs_truncate"]
referenced_configs: ["CONFIG_COMPAT", "CONFIG_AUDIT"]
includes: ["linux/syscalls.h", "linux/file.h"]
missing_compile_command: false
---

# Summary of mm/kfence/core.c

## 1. Description
KFENCE (Kernel Electric-Fence) is a low-overhead sampling-based memory safety error detector...

# Directory Summary Schema

```markdown
---
path: "mm/kfence"
source_hash: "..." # Hash of the aggregated file contents/summaries
description: "One-line description of the directory."
---

# Directory Summary of mm/kfence

### Exported APIs
## core.c
- kfence_alloc
- kfence_free

### File Descriptions
- **core.c**: Main logic for KFENCE...
- **report.c**: Error reporting logic...

### File Summaries
## File: core.c
...

## 2. Invariants & Locking
* **kfence_metadata_lock**: Protects the global metadata state...
```

---

## 4. Pipeline

### Phase 1: Request
*   An agent or user requests a summary for a specific kernel file (e.g., `mm/kfence/core.c`).

### Phase 2: Check Cache & Coalesce
*   **Cache Hit**: If a valid summary exists (SHA1 source hash matches), return it immediately.
*   **Coalesce**: If another request for the same file is in progress, wait for it to complete.

### Phase 3: Static Analysis
*   The orchestrator runs `syz-glance` (the C++ tool).
*   **JITI (Just-In-Time Inclusion)**: The tool extracts *only* the struct/enum definitions from headers that are actually used in the source file. This drastically reduces context size compared to including full headers.
*   **Complexity Filtering**: Functions with high cyclomatic complexity or locking operations are flagged for deeper analysis.

### Phase 4: LLM Generation
*   The orchestrator constructs a prompt containing:
    1.  The raw source code.
    2.  The JITI-extracted header definitions.
    3.  The list of "interesting" functions to focus on.
*   Gemini generates the summary, which is then cached and returned.

---

---

## 5. Caching Strategy

The system employs a two-level caching strategy to minimize redundant work (static analysis and LLM inference).

### File Summaries (`.md`) - `source_hash` = SHA1(file_content)
1.  **Check Cache**: Calculate `source_hash` of the target `.c` file.
2.  If `cache/file.c.md` exists and its `source_hash` matches:
    *   **Return immediately.**
    *   **Skip Clang Analysis.**
    *   **Skip LLM Inference.**
3.  Otherwise (or if `-force` is used):
    *   Run Clang Analysis.
    *   Run LLM Inference.
    *   Overwrite `cache/file.c.md`.

### Directory Summaries (`README.md`) - `source_hash` = SHA1(concatenated_file_summaries)
1.  **Ensure Freshness**: Process all files and subdirectories first (applying File Summary logic).
2.  **Aggregate**: Concatenate the *current* summaries of all `.c` files and subdirectories.
3.  **Check Cache**: Calculate `source_hash` of this aggregation.
4.  If `cache/dir/README.md` exists and its `source_hash` matches:
    *   **Return immediately.**
5.  Otherwise:
    *   Run LLM Inference for directory summarization.
    *   Overwrite `cache/dir/README.md`.

**Implication**: If a file's content doesn't change, its summary is preserved. However, if a file's *summary* is regenerated (e.g., via `-force`), the directory summary's source hash will change, triggering a directory-level re-summarization.

---

## 6. Clang Tooling Details

### 6.1 Hybrid Architecture

The analysis tool uses a hybrid Go/C++ architecture:
1.  **Driver (`pkg/clangtool`)**: A Go package that manages the `compile_commands.json` database, handles path relocation, and invokes the underlying tool.
2.  **Tool (`tools/clang/glance`)**: A C++ binary built with LibTooling. To avoid distributing a separate binary, the Go binary re-executes *itself* with a special environment variable (`SYZ_RUN_CLANGTOOL=glance`). The C++ code is linked into the Go binary and intercepts execution in a constructor (via `__attribute__((constructor))`), running the Clang tool logic before the Go runtime fully starts.

### 6.2 Compilation Database Handling

The system must work in containerized environments where the kernel source path (e.g., `/syzkaller/manager/linux`) differs from the path recorded in `compile_commands.json` (e.g., `/usr/local/google/home/user/linux`).

*   **Relocation**: `pkg/clangtool` detects this mismatch by probing for known kernel files (like `init/main.c`) in the current `SOURCEDIR`. It then deduces the "old" source root and rewrites all entries in `compile_commands.json` to point to the new location, saving the modified database to a temporary file.
*   **Filtering**: The database is filtered to remove commands that don't look like kernel builds (e.g., host tools compiled with `gcc`).
*   **No Fallbacks**: If a requested file is missing from the DB, we **skip static analysis** for that file. This is because synthesizing fallback commands is error-prone (compiler flag mismatches, path issues) and can cause the underlying Clang tool to crash or fail unexpectedly. Instead, `syz-glance` detects the missing command and proceeds to generate a summary using only the raw source code, marking the result with `missing_compile_command: true`.

### 6.3 AST Analysis

The C++ tool (`glance`) runs a series of AST Visitors:
*   **ComplexityVisitor**: Computes Cyclomatic Complexity.
*   **LockVisitor**: Detects usage of locking primitives (`spin_lock`, `rcu_read_lock`, etc.).
*   **JITIVisitor (Just-In-Time Inclusion)**: Walks the AST to find every type (`struct`, `enum`) and macro used in the function body. It then extracts their definitions from the headers. This creates a minimal, self-contained context for the LLM, avoiding the need to verify thousands of lines of unused header code.

---

## 7. Future Work

*   **Pre-heating**: Speculatively generating summaries for files frequently referenced in crash reports.

