# Configuration

The operation of the syzkaller `syz-manager` process is governed by a configuration file, passed at
invocation time with the `-config` option.  This configuration can be based on the
[example](/syz-manager/mgrconfig/testdata/qemu.cfg); the file is in JSON format with the
following keys in its top-level object:

 - `http`: URL that will display information about the running `syz-manager` process.
 - `workdir`: Location of a working directory for the `syz-manager` process. Outputs here include:
     - `<workdir>/crashes/*`: crash output files (see [Crash Reports](#crash-reports))
     - `<workdir>/corpus.db`: corpus with interesting programs
     - `<workdir>/instance-x`: per VM instance temporary files
 - `syzkaller`: Location of the `syzkaller` checkout.
 - `vmlinux`: Location of the `vmlinux` file that corresponds to the kernel being tested
   (used for report symbolization and coverage reports, optional).
 - `procs`: Number of parallel test processes in each VM (4 or 8 would be a reasonable number).
 - `leak`: Detect memory leaks with kmemleak.
 - `image`: Location of the disk image file for the QEMU instance; a copy of this file is passed as the
   `-hda` option to `qemu-system-x86_64`.
 - `sshkey`: Location (on the host machine) of a root SSH identity to use for communicating with
   the virtual machine.
 - `sandbox` : Sandboxing mode, the following modes are supported:
     - "none": don't do anything special (has false positives, e.g. due to killing init)
     - "setuid": impersonate into user nobody (65534), default
     - "namespace": use namespaces to drop privileges
       (requires a kernel built with `CONFIG_NAMESPACES`, `CONFIG_UTS_NS`,
       `CONFIG_USER_NS`, `CONFIG_PID_NS` and `CONFIG_NET_NS`)
 - `enable_syscalls`: List of syscalls to test (optional).
 - `disable_syscalls`: List of system calls that should be treated as disabled (optional).
 - `suppressions`: List of regexps for known bugs.
 - `type`: Type of virtual machine to use, e.g. `qemu` or `adb`.
 - `vm`: object with VM-type-specific parameters; for example, for `qemu` type paramters include:
     - `count`: Number of VMs to run in parallel.
     - `kernel`: Location of the `bzImage` file for the kernel to be tested;
       this is passed as the `-kernel` option to `qemu-system-x86_64`.
     - `cmdline`: Additional command line options for the booting kernel, for example `root=/dev/sda1`.
     - `cpu`: Number of CPUs to simulate in the VM (*not currently used*).
     - `mem`: Amount of memory (in MiB) for the VM; this is passed as the `-m` option to `qemu-system-x86_64`.

See also [config.go](/syz-manager/mgrconfig/mgrconfig.go) for all config parameters.
