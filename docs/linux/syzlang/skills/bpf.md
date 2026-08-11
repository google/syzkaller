---
name: bpf
description: BPF, eBPF Program Loading, BTF ID Lookups and Hooks
---
# BPF & BTF Helpers
- BTF ID Lookup:
  * Use 'syz_btf_id_by_name(name)' to obtain BTF IDs for kernel hooks, LSM programs, or structs by symbol name.
- BPF Subsystem Operations:
  * When generating or fixing programs targeting eBPF maps, LSM hooks, or tracing, check existing test seeds
    (in the 'test/' directory) for corpus examples demonstrating BPF syscalls and BTF ID usage.
