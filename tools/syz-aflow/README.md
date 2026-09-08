# `syz-aflow` - AI Workflow Executor

`syz-aflow` is a CLI tool designed to execute `aflow` workflows locally for debugging and testing purposes. It supports both single-workflow execution and concurrent batch execution of multiple tasks.

## Building

To build `syz-aflow`, use the `syz-env` environment from the repository root:
```bash
./tools/syz-env go build ./tools/syz-aflow
```
This will create a `syz-aflow` binary in the repository root.

## Usage

### Single-Task Execution

To run a single workflow, specify the workflow name, an input JSON file, and a working directory:

```bash
./tools/syz-env ./syz-aflow -workflow <workflow_name> -input <input.json> -workdir <workdir>
```

You can monitor execution in real time by providing the `-html` flag:
```bash
./tools/syz-env ./syz-aflow -workflow <workflow_name> -input input.json -workdir ./workdir -html trajectory.html
```

### Batch Execution

When `-input` points to a directory containing `*.json` task files (such as those produced by `syz-uncovered-batch`), `syz-aflow` automatically executes them as a batch:

```bash
./tools/syz-env ./syz-aflow -workflow seed-gen-file-line -input ./tasks -workdir ./workdir -parallel 4 -corpus ./corpus.db
```

- **Parallel execution:** `-parallel <N>` runs multiple workers concurrently.
- **Trajectory classification:** Each task is tracked and classified into:
  `<workdir>/trajectories/{success,giveup,error}/<task_id>.{html,json}`
  Active tasks write real-time trajectories to `<workdir>/trajectories/in_progress/<task_id>.html`.
- **Restartability:** Previously completed tasks in any outcome directory (`success`, `giveup`, `error`) are automatically skipped on restart.
- **Seed collection:** If `-corpus` is specified, executed Syzkaller programs from the trajectories are stripped of fault-injection flags, deduplicated, and stored into the specified `corpus.db` file.

### Workflow Inputs

`syz-aflow` does not require a standard `syz-manager` configuration file. Instead, it takes a JSON file containing the arguments specific to the workflow you are running.

If the workflow needs to perform actions that interact with VMs (like reproducing a crash or testing a patch), it will expect fields in that input JSON that describe the environment (e.g., `Image`, `VM` type and config, `KernelSrc`, etc.). The workflow code then takes these individual arguments and builds the necessary manager configuration programmatically on the fly.

#### Example Input for `patching` Workflow

```json
{
  "Syzkaller": "/path/to/syzkaller",
  "Image": "/path/to/linux/image",
  "Type": "qemu",
  "VM": {
    "count": 1,
    "cpu": 2,
    "mem": 2048,
    "qemu_args": "-machine q35 -enable-kvm -smp 2,sockets=2,cores=1"
  },
  "ReproSyz": "syz_open$dir(0x0, 0x1) ...",
  "KernelConfig": "@/path/to/linux.config"
}
```

Any string field in the input JSON starting with `@` (e.g. `"@/path/to/file"` or `"@./relative/path"`) will be automatically expanded with the contents of that file. Relative paths are resolved relative to the directory of the `-input` JSON file. Literal leading `@` characters can be escaped with `@@` (e.g. `"@@literal"`).

### Flags

- `-workflow`: The name of the workflow to execute.
- `-input`: Path to a task JSON file or directory containing task input files.
- `-parallel`: Number of parallel workflows to run (default 1).
- `-workdir`: Directory where the workflow can perform checkouts, builds, and store trajectories and cache.
- `-corpus`: Path to `corpus.db` to collect executed syz programs.
- `-html`: Path to an HTML file where the execution trajectory will be rendered in real-time (single-task mode only).
- `-output`: Save final workflow output to this JSON file (single-task mode only).
- `-model`: Override the default LLM model.
- `-provider`: LLM provider to use (`gemini`, `vertex`, default `gemini`).
- `-cache-size`: Set the maximum cache size (default "10GB").
- `-download-bug`: Download bug details from the dashboard by ID or ExtID.
- `-auth`: Use gcloud auth token when downloading bugs.
- `-debug`: Enable runner debug logging.
- `-token-limit`: Maximum tokens allowed for the workflow run (0 = no limit).
