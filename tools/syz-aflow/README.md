# `syz-aflow` - AI Workflow Executor

`syz-aflow` is a CLI tool designed to execute `aflow` workflows locally for debugging and testing purposes.

## Building

To build `syz-aflow`, use the `syz-env` environment from the repository root:
```bash
./tools/syz-env go build ./tools/syz-aflow
```
This will create a `syz-aflow` binary in the repository root.

## Usage

### Basic Execution

To run a workflow, you need to specify the workflow name, an input JSON file, and a working directory:

```bash
./tools/syz-env ./syz-aflow -workflow <workflow_name> -input <input.json> -workdir <workdir>
```

### Batch Execution

If `-input` is a directory, each `*.json` file in it is executed as a separate task:

```bash
./tools/syz-env ./syz-aflow -workflow seed-gen-file-line -input ./tasks -workdir ./workdir -parallel 4
```

Results are saved to `<workdir>/trajectories/<state>/`. Completed tasks are skipped on restart.
Batch execution is currently only supported for the `seed-gen-file-line` workflow and cannot be combined
with `-html` and `-output`.

To spread the load over several Gemini API keys, put them one per line into `GOOGLE_API_KEY`
(e.g. `GOOGLE_API_KEY="$(cat keys.txt)"`). Each task sticks to one key. Keys only help with rate limits
if they belong to different projects.

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
- `-input`: Path to a JSON file containing the arguments for the workflow (or a directory of them).
- `-parallel`: Number of tasks to run concurrently in batch execution.
- `-workdir`: Directory where the workflow can perform checkouts, builds, etc.
- `-html`: Path to an HTML file where the execution trajectory will be rendered in real-time.
- `-model`: Override the default LLM model.
- `-cache-size`: Set the maximum cache size (default "10GB").
- `-download-bug`: Download bug details from the dashboard by ID or ExtID.
- `-auth`: Use gcloud auth token when downloading bugs.

### Live Trajectory Visualization

You can monitor the execution of the workflow in real-time by using the `-html` flag:
```bash
./tools/syz-env ./syz-aflow -workflow patching -input input.json -workdir ./workdir -html trajectory.html
```
Open the specified HTML file in your browser to see the charts and steps as they execute.
