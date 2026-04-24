# syz-glance: JIT AI Summarization for Linux Kernel

`syz-glance` is a tool for Just-In-Time (JIT) summarization of Linux kernel source files. It combines Clang-based static analysis with LLM-based semantic reasoning (via Gemini) to generate high-signal summaries of C code.

## Features

1.  **Static Analysis**:
    *   Extracts function complexity and locking primitives.
    *   Identifies exported symbols (`EXPORT_SYMBOL`) and `EXPORT_SYMBOL_GPL`.
    *   **JITI (Just-In-Time Inclusion)**: Automatically extracts definitions of structs and enums referenced in the target file from included headers.
    *   **Config Extraction**: Extracts `CONFIG_` variables referenced in the source code.
    *   **Include Extraction**: Lists files included via `#include` directives.

2.  **Semantic Summarization**:
    *   **File Level**: Uses Gemini (via `pkg/aflow`) to generate high-level technical summaries.
    *   **Directory Level**: Aggregates file summaries into a cohesive `README.md` for subsystems (e.g., `mm/kfence/README.md`), including one-line descriptions for each file.
    *   Highlights key invariants, locking rules, and API usage.

3.  **Performance**:
    *   **Flight Map**: Coalesces concurrent requests for the same file.
    *   **Caching**: Stores summaries locally in `${KERNEL_SRC}/glance/` to avoid redundant LLM calls.

## Prerequisites

*   **Docker** (for `syz-env`).
*   **Google Cloud Project** with Gemini API enabled.
*   **API Key**: A valid `GOOGLE_API_KEY`.
*   **Compilation Database**: `compile_commands.json` must be present in the kernel source root.

## Limitations

*   **Exported Symbols & JITI**: The tool relies on a valid `compile_commands.json` to correctly parse the file and expand macros. If a file is not present in the compilation database (e.g., because its config option is disabled), `syz-glance` will fail to detect exported symbols and JIT included types.

## Usage

### 1. Build the Tool

Since `syz-glance` depends on specific LLVM/Clang libraries (LLVM 19+), we strongly recommend building and running it inside the `syz-env` container.

```bash
# Build the binary inside the container
./tools/syz-env go build -o syz-glance ./tools/syz-glance
```

### 2. Generate `compile_commands.json`

The tool requires a compilation database to understand how to parse the kernel code. To ensure the paths in the database match the paths inside the container (where the kernel is mounted at `/syzkaller/kernel`), you have two options:

#### Option A: Generate inside the container (Recommended)

Run the generation command inside `syz-env`. We recommend using `make CC=clang` to ensure the kernel is built with Clang, which produces a compilation database that is most compatible with `syz-glance`.

```bash
# This mounts your kernel source to /syzkaller/kernel, changes to that directory, and runs the make command.
./tools/syz-env SOURCEDIR=/path/to/linux "cd /syzkaller/kernel && make CC=clang compile_commands.json"
```

*Note: You may need to run `make CC=clang olddefconfig` or similar configuration step first if you haven't configured the kernel yet.*





#### Option B: Rewrite paths

If you already have `compile_commands.json` generated on your host, you can rewrite the paths to match the container mount point:

```bash
sed -i 's|/path/to/linux|/syzkaller/kernel|g' /path/to/linux/compile_commands.json
```


### 3. Run Summarization

To run the tool, mount your kernel source into the container using the `SOURCEDIR` variable.

```bash
# Set your API key
export GOOGLE_API_KEY=...

# Run the tool
# Replace /path/to/linux with the absolute path to your kernel source
# Run the tool on a file
./tools/syz-env SOURCEDIR=/path/to/linux ./syz-glance /syzkaller/kernel mm/kfence/core.c

# Run the tool on a directory (generates README.md)
./tools/syz-env SOURCEDIR=/path/to/linux ./syz-glance /syzkaller/kernel mm/kfence

# Force re-summarization (bypass cache)
./tools/syz-env SOURCEDIR=/path/to/linux ./syz-glance -force /syzkaller/kernel mm/kfence/core.c
```

**Note:** The path `/syzkaller/kernel` inside the container maps to the `SOURCEDIR` you provided.

### 4. Output

The tool prints the generated Markdown summary to `stdout`.

```markdown
---
path: mm/kfence/core.c
source_hash: ...
---

# Summary of mm/kfence/core.c

KFENCE (Kernel Electric-Fence) is a low-overhead sampling-based memory safety error detector...
```

## Troubleshooting

### `libclang-cpp.so: cannot open shared object file`
If you see this error when running on your host, it means your host's LLVM libraries are missing or incompatible. Please use `syz-env` as described above.

### Empty Output / Demo Mode
If `GOOGLE_API_KEY` is not set, the tool runs in **DEMO** mode. It will static analysis results and the assembled prompt but will NOT call the LLM.

## Architecture

*   **`tools/clang/glance`**: C++ static analyzer (LibClang).
*   **`pkg/glance`**: Go orchestrator (manages JIT, caching, LLM calls).
*   **`pkg/aflow`**: Gemini integration.
