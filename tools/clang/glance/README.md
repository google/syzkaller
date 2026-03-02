# Glance Clang Tool

## Overview
`glance` is a Clang LibTooling-based utility designed to extract high-level semantic information from C source code, specifically optimized for the Linux kernel. It serves as the static analysis backend for `syz-glance`.

## Features
- **Function Extraction**: Locates function definitions and extracts their source ranges.
- **Complexity Analysis**: Calculates a basic cyclomatic complexity score for each function.
- **Lock Detection**: Identifies usage of locking primitives (e.g., `spin_lock`, `mutex_lock`, `rcu_read_lock`).
- **JIT Includes (JITI)**: Extracts definitions of types (structs, enums) used within function bodies to provide self-contained context for LLM processing.
- **Exported Symbol Detection**: Identifies functions exported via `EXPORT_SYMBOL` macros.

## Architecture

### Visitors
The tool uses `RecursiveASTVisitor` to traverse the AST:
1.  **ComplexityVisitor**: Computes cyclomatic complexity by counting branching statements (`if`, `for`, `while`, `case`, `||`, `&&`).
2.  **LockVisitor**: Scans for call expressions matching locking patterns (names containing "lock", "unlock", "rcu_read").
3.  **JITIVisitor**: Collects type definitions (`RecordDecl`, `EnumDecl`) referenced in the code, ensuring that the generated summary includes necessary context even if headers are not fully parsing.

### Matchers
It uses AST Matchers to find function definitions in the main file:
```cpp
functionDecl(isDefinition()).bind("func")
```

### Preprocessor Callbacks
It uses `PPCallbacks` to:
-   Track file inclusions (`InclusionDirective`).
-   Detect exported symbols (`MacroExpands` on `EXPORT_SYMBOL*`).

## Output Format
The tool outputs a JSON object (defined in `output.h`) containing:
-   `functions`: List of functions with metadata (name, file, lines, complexity, locks, is_exported).
-   `symbols`: List of extracted type definitions (JITI).
-   `includes`: List of included headers.
-   `missing_compile_command`: (Optional) Flag indicating if the file was not found in the compilation database.

## Usage
The tool is typically invoked via `pkg/clangtool` in `syz-glance`, which handles compilation database management and execution. It relies on a valid `compile_commands.json` to correctly parse kernel sources.

```bash
# Direct usage (requires compile_commands.json)
./glance -p path/to/compile_commands.json target_file.c
```
