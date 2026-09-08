# `syz-uncovered-batch` - Uncovered Target Generator

`syz-uncovered-batch` extracts candidate uncovered functions and code locations from Syzkaller dashboard coverage data, and generates batch task input files for `syz-aflow`.

## Building

To build `syz-uncovered-batch`, run:
```bash
./tools/syz-env go build ./tools/syz-uncovered-batch
```

## Overview

The tool performs the following steps:
1. **Fetches Coverage Data:** Downloads the coverage JSONL stream from the dashboard API (e.g. `https://syzbot.org/upstream/coverage?jsonl=1&period=month`).
2. **Filters Targets:**
   - Filters source files by directory prefix (`-include-paths`, `-exclude-paths`) and file regex pattern (`-file-pattern`, default `.*\.c$`).
   - Filters functions by coverage (by default only functions with 0% coverage are selected; partial coverage can be enabled with `-include-covered-funcs`).
   - Excludes kernel initialization and setup routines (`*_init`, `init_*`, `*_setup`) by default with `-exclude-init=true`, with optional regex filtering via `-func-pattern` and `-exclude-func-pattern`.
   - Identifies uncovered basic blocks and lines inside each matching function.
3. **Samples Targets:** Shuffles candidate functions randomly and picks one uncovered block from each. If `-limit` is larger than the number of matching functions, the remaining uncovered blocks are sampled round-robin across them. `-limit 0` collects every uncovered block of every matching function.
4. **Generates Task Files:** Merges each target's `FilePath`, `LineNumber`, and coverage `KernelRepo`/`KernelCommit` into a base configuration template (`-base`), outputting individual `<task_id>.json` files into `-output-dir`.

## Usage

### 1. Prepare Base Configuration

Create a base template `base.json` defining the VM, kernel source, and image configuration for the target environment:

```json
{
  "Syzkaller": "/path/to/syzkaller",
  "Image": "/path/to/image",
  "KernelSrc": "/path/to/linux",
  "Type": "qemu",
  "VM": {
    "count": 1,
    "cpu": 2,
    "mem": 2048,
    "qemu_args": "-machine q35 -enable-kvm -smp 2,sockets=2,cores=1"
  }
}
```

### 2. Generate Tasks

Extract uncovered targets in specific subsystems (e.g. KVM and DRM) and generate 50 task files:

```bash
./tools/syz-env ./syz-uncovered-batch \
    -base base.json \
    -output-dir ./tasks \
    -include-paths virt/kvm,drivers/gpu/drm \
    -limit 50
```

### 3. Run Batch with `syz-aflow`

Execute the generated tasks in parallel using `syz-aflow`:

```bash
./tools/syz-env ./syz-aflow \
    -workflow seed-gen-file-line \
    -input ./tasks \
    -workdir ./workdir \
    -parallel 4 \
    -corpus
```
