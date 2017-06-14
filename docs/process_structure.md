# Process Structure

The process structure for the syzkaller system is shown in the following diagram;
red labels indicate corresponding configuration options.

![Process structure for syzkaller](process_structure.png?raw=true)

The `syz-manager` process starts, monitors and restarts several VM instances (support for
physical machines is not implemented yet), and starts a `syz-fuzzer` process inside of the VMs.
It is responsible for persistent corpus and crash storage. As opposed to `syz-fuzzer` processes,
it runs on a host with stable kernel which does not experience white-noise fuzzer load.

The `syz-fuzzer` process runs inside of presumably unstable VMs (or physical machines under test).
The `syz-fuzzer` guides fuzzing process itself (input generation, mutation, minimization, etc)
and sends inputs that trigger new coverage back to the `syz-manager` process via RPC.
It also starts transient `syz-executor` processes.

Each `syz-executor` process executes a single input (a sequence of syscalls).
It accepts the program to execute from the `syz-fuzzer` process and sends results back.
It is designed to be as simple as possible (to not interfere with fuzzing process),
written in C++, compiled as static binary and uses shared memory for communication.
