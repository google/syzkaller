# syz-verifier

`syz-verifier` is a differential fuzzing tool for comparing the execution behavior of programs across different versions of the Linux kernel to detect semantic bugs and inconsistencies.

## Design Overview

The syz-verifier implements a centralized fuzzing architecture where a single `Verifier` instance manages multiple kernel configurations for differential testing:

### Core Architecture

```
                    ┌─────────────────────────────────┐
                    │          Verifier               │
                    │                                 │
                    │  ┌───────────────────────────┐  │
                    │  │        Fuzzer             │  │
                    │  │   (Program Generation)    │  │
                    │  └───────────────────────────┘  │
                    │              │                  │
                    │              ▼                  │
                    │  ┌───────────────────────────┐  │
                    │  │    Distribution Logic     │  │
                    │  └───────────────────────────┘  │
                    │         │        │        │     │
                    └─────────┼────────┼────────┼─────┘
                              ▼        ▼        ▼
                    ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
                    │   Queue A   │ │   Queue B   │ │   Queue C   │
                    │ (Kernel A)  │ │ (Kernel B)  │ │ (Kernel C)  │
                    └─────────────┘ └─────────────┘ └─────────────┘
```

### Key Components

1. **Single Fuzzer Instance**: The verifier maintains one `fuzzer.Fuzzer` that generates test programs
2. **Per-Kernel Queues**: Each kernel configuration gets its own `queue.PlainQueue` for task distribution

### Main loop

1. **Generation**: The central fuzzer generates a new program
2. **Distribution**: The program is cloned and sent to each kernel's queue
3. **Execution**: Each kernel executes the program independently
4. **Collection**: The verifier waits for all kernels to complete
5. **Comparison**: Results are collected for differential analysis
## Implementation Details

### Verifier Structure

The `Verifier` struct contains:
- `fuzzer atomic.Pointer[fuzzer.Fuzzer]`: Single fuzzer instance for program generation
- `sources map[int]*queue.PlainQueue`: Per-kernel queue mapping (kernel ID → queue)
- `kernels map[int]*Kernel`: Kernel configuration mapping
- `manager.HTTPServer`: The central HTTP server for all kernels


Holds the fuzzer and implements a "proxy" between it and all the kernels.
Also is responsible of aggregating requests from the different kernels

### Kernel Structure

Implements the functions so that it can work with the rpc server.
- MachineChecked: aggregate features and enabled syscalls to the verifier.
- MaxSignal: request the max signal from the verifier.
- BugFrames: not implemented.
- CoverageFilter: currently filters coverage similar to the KernelContext in diff.go. This is still work in progress.

## Usage

### Basic Usage

This is a prototype implementation demonstrating the core differential fuzzing architecture.

```bash
# Build the verifier
make verifier

# Run with kernel configurations (example)
./bin/syz-verifier -configs=kernel1.cfg,kernel2.cfg -debug

# For debug we can also run with a single kernel
./bin/syz-verifier -configs=kernel1.cfg -debug
```

## Development Status

This is a **prototype** showcasing the verifier design with:
- ✅ Centralized fuzzer architecture
- ✅ Per-kernel queue distribution
- ✅ Synchronous execution model
- 🚧 Result comparison logic (TODO)
- 🚧 Reproduction loop (TODO)
- 🚧 Http server (TODO)
- 🚧 Snapshots! are very important for diff fuzz (TODO)
