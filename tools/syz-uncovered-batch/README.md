# `syz-uncovered-batch` - Uncovered Target Generator

`syz-uncovered-batch` extracts candidate uncovered functions and code locations from Syzkaller dashboard coverage data, and generates batch task input files for `syz-aflow`.

## Building

To build `syz-uncovered-batch`, run:
```bash
./tools/syz-env go build ./tools/syz-uncovered-batch
```

## Usage

See `main.go` (or run `./syz-uncovered-batch -help`) for all available flags.

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

Extract uncovered targets for a specific manager and subsystems (e.g. KVM and DRM) and generate 50 task files:

```bash
./tools/syz-env ./syz-uncovered-batch \
    -manager ci-upstream-kasan-gce-root \
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

Results and trajectories will be saved to `./workdir/trajectories/{success,giveup,unreached,error}/` and executed programs collected into `./workdir/corpus.db`.
