# Setup: Linux isolated host

These are the instructions on how to fuzz the kernel on isolated machines.
Isolated machines are separated in a way that limits remote management. They can
be interesting to fuzz due to specific hardware setups.

This syzkaller configuration uses only ssh to launch and monitor an isolated
machine.

## Setup reverse proxy support

Given only ssh may work, a reverse ssh proxy will be used to allow the fuzzing
instance and the manager to communicate.

Ensure the sshd configuration on the target machine has AllowTcpForwarding to yes.
```
machine:~# grep Forwarding /etc/ssh/sshd_config
AllowTcpForwarding yes
```

## Kernel

The isolated VM does not deploy kernel images so ensure the kernel on the target
machine is build with these options:
```
CONFIG_KCOV=y
CONFIG_DEBUG_INFO=y
CONFIG_KASAN=y
CONFIG_KASAN_INLINE=y
```

Code coverage works better when KASLR Is disabled too:
```
# CONFIG_RANDOMIZE_BASE is not set
```

## Optional: Reuse existing ssh connection

In most scenarios, you should use an ssh key to connect to the target machine.
The isolated configuration supports ssh keys as described in the generic
[setup](setup.md).

If you cannot use an ssh key, you should configure your manager machine to reuse
existing ssh connections.

Add these lines to your ~/.ssh/config file:
```
Host *
	ControlMaster auto
	ControlPath ~/.ssh/control:%h:%p:%r
```

Before fuzzing, connect to the machine and keep the connection open so all scp
and ssh usage will reuse it.

# Optional: Pstore support

If the device under test (DUT) has Pstore support, it is possible to configure syzkaller to
fetch crashlogs from /sys/fs/pstore. You can do this by setting `"pstore": true` within
the `vm` section of the syzkaller configuration file.

# Optional: Startup script

To execute commands on the DUT before fuzzing (re-)starts,
`startup_script` can be used.

## Syzkaller

Build syzkaller as described [here](/docs/linux/setup.md#go-and-syzkaller).

Use the following config:
```
{
	"target": "linux/amd64",
	"http": "127.0.0.1:56741",
	"rpc": "127.0.0.1:0",
	"sshkey" : "/path/to/optional/sshkey",
	"workdir": "/syzkaller/workdir",
	"kernel_obj": "/linux-next",
	"syzkaller": "/go/src/github.com/google/syzkaller",
	"sandbox": "setuid",
	"type": "isolated",
	"vm": {
		"targets" : [ "10.0.0.1" ],
		"pstore": false,
		"target_dir" : "/home/user/tmp/syzkaller",
                "target_reboot" : false
	}
}
```

Don't forget to update:
 - `target` (target OS/arch)
 - `workdir` (path to the workdir)
 - `kernel_obj` (path to kernel build directory)
 - `sshkey` You can setup an sshkey (optional)
 - `vm.targets` List of hosts to use for fufzzing
 - `vm.target_dir` Working directory on the target host
 - `vm.target_reboot` Reboot the machine if remote process hang (useful for wide fuzzing, false by default)

Run syzkaller manager:
``` bash
./bin/syz-manager -config=my.cfg
```

If you get issues after `syz-manager` starts, consider running it with the `-debug` flag.
Also see [this page](/docs/troubleshooting.md) for troubleshooting tips.
