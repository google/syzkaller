# gVisor

[gVisor](https://github.com/google/gvisor) is a user-space kernel, written in
Go, that implements a substantial portion of the Linux system surface.

`gVisor` uses `linux` OS, but the special `gvisor` VM type. There is nothing
special regarding `gVisor` besides that. Here is an example manager config:

```
{
	"name": "gvisor",
	"target": "linux/amd64",
	"http": ":12345",
	"workdir": "/workdir",
	"image": "/usr/local/bin/runsc",
	"syzkaller": "/gopath/src/github.com/google/syzkaller",
	"cover": false,
	"procs": 8,
	"type": "gvisor",
	"vm": {
		"count": 5,
		"runsc_args": "-platform=kvm"
	}
}
```

## Reproducing crashes

`syz-execprog` can be used inside gVisor to (hopefully) reproduce crashes.

To run a single program inside a minimal gVisor sandbox, do the following.

1. Build all of the syzkaller tools:

```bash
$ cd $SYZKALLER_DIR
$ make
```

2. Build runsc:

```bash
$ cd $GVISOR_DIR
$ bazel build //runsc
```

3. Create a `bundle/` directory with a config like the one below. Be sure to
   update the paths to the `linux_amd64` directory and input log/program file.

```bash
$ mkdir bundle
$ $EDITOR bundle/config.json
```

4. Run gVisor:

```bash
$ sudo bazel-bin/runsc/linux_amd64_pure_stripped/runsc \
    -platform=ptrace \
    -file-access=shared \
    -network=host \
    run \
    -bundle /PATH/TO/bundle/ \
    syzkaller
```

5. Remove container:

```bash
$ sudo bazel-bin/runsc/linux_amd64_pure_stripped/runsc delete -force syzkaller
```

Note that you'll want to adjust the `runsc` args to match the config in which
the crash was discovered. You may also want to add `-debug -strace` for more
debugging information.

You can also adjust the args to `syz-execprog` in `config.json`. e.g., add
`-repeat` to repeat the program.

### config.json

```json
{
	"root": {
		"path": "/PATH/TO/syzkaller/bin/linux_amd64",
		"readonly": true
	},
	"mounts": [
		{
			"destination": "/input",
			"source": "/PATH/TO/INPUT/LOG",
			"type": "bind",
			"options": ["ro"]
		}
	],
	"process":{
		"args": ["/syz-execprog", "-executor=/syz-executor", "-cover=false", "-sandbox=none", "/input"],
		"cwd": "/tmp",
		"capabilities": {
			"bounding": [
				"CAP_CHOWN",
				"CAP_DAC_OVERRIDE",
				"CAP_DAC_READ_SEARCH",
				"CAP_FOWNER",
				"CAP_FSETID",
				"CAP_KILL",
				"CAP_SETGID",
				"CAP_SETUID",
				"CAP_SETPCAP",
				"CAP_LINUX_IMMUTABLE",
				"CAP_NET_BIND_SERVICE",
				"CAP_NET_BROADCAST",
				"CAP_NET_ADMIN",
				"CAP_NET_RAW",
				"CAP_IPC_LOCK",
				"CAP_IPC_OWNER",
				"CAP_SYS_MODULE",
				"CAP_SYS_RAWIO",
				"CAP_SYS_CHROOT",
				"CAP_SYS_PTRACE",
				"CAP_SYS_PACCT",
				"CAP_SYS_ADMIN",
				"CAP_SYS_BOOT",
				"CAP_SYS_NICE",
				"CAP_SYS_RESOURCE",
				"CAP_SYS_TIME",
				"CAP_SYS_TTY_CONFIG",
				"CAP_MKNOD",
				"CAP_LEASE",
				"CAP_AUDIT_WRITE",
				"CAP_AUDIT_CONTROL",
				"CAP_SETFCAP",
				"CAP_MAC_OVERRIDE",
				"CAP_MAC_ADMIN",
				"CAP_SYSLOG",
				"CAP_WAKE_ALARM",
				"CAP_BLOCK_SUSPEND",
				"CAP_AUDIT_READ"
			],
			"effective": [
				"CAP_CHOWN",
				"CAP_DAC_OVERRIDE",
				"CAP_DAC_READ_SEARCH",
				"CAP_FOWNER",
				"CAP_FSETID",
				"CAP_KILL",
				"CAP_SETGID",
				"CAP_SETUID",
				"CAP_SETPCAP",
				"CAP_LINUX_IMMUTABLE",
				"CAP_NET_BIND_SERVICE",
				"CAP_NET_BROADCAST",
				"CAP_NET_ADMIN",
				"CAP_NET_RAW",
				"CAP_IPC_LOCK",
				"CAP_IPC_OWNER",
				"CAP_SYS_MODULE",
				"CAP_SYS_RAWIO",
				"CAP_SYS_CHROOT",
				"CAP_SYS_PTRACE",
				"CAP_SYS_PACCT",
				"CAP_SYS_ADMIN",
				"CAP_SYS_BOOT",
				"CAP_SYS_NICE",
				"CAP_SYS_RESOURCE",
				"CAP_SYS_TIME",
				"CAP_SYS_TTY_CONFIG",
				"CAP_MKNOD",
				"CAP_LEASE",
				"CAP_AUDIT_WRITE",
				"CAP_AUDIT_CONTROL",
				"CAP_SETFCAP",
				"CAP_MAC_OVERRIDE",
				"CAP_MAC_ADMIN",
				"CAP_SYSLOG",
				"CAP_WAKE_ALARM",
				"CAP_BLOCK_SUSPEND",
				"CAP_AUDIT_READ"
			],
			"inheritable": [
				"CAP_CHOWN",
				"CAP_DAC_OVERRIDE",
				"CAP_DAC_READ_SEARCH",
				"CAP_FOWNER",
				"CAP_FSETID",
				"CAP_KILL",
				"CAP_SETGID",
				"CAP_SETUID",
				"CAP_SETPCAP",
				"CAP_LINUX_IMMUTABLE",
				"CAP_NET_BIND_SERVICE",
				"CAP_NET_BROADCAST",
				"CAP_NET_ADMIN",
				"CAP_NET_RAW",
				"CAP_IPC_LOCK",
				"CAP_IPC_OWNER",
				"CAP_SYS_MODULE",
				"CAP_SYS_RAWIO",
				"CAP_SYS_CHROOT",
				"CAP_SYS_PTRACE",
				"CAP_SYS_PACCT",
				"CAP_SYS_ADMIN",
				"CAP_SYS_BOOT",
				"CAP_SYS_NICE",
				"CAP_SYS_RESOURCE",
				"CAP_SYS_TIME",
				"CAP_SYS_TTY_CONFIG",
				"CAP_MKNOD",
				"CAP_LEASE",
				"CAP_AUDIT_WRITE",
				"CAP_AUDIT_CONTROL",
				"CAP_SETFCAP",
				"CAP_MAC_OVERRIDE",
				"CAP_MAC_ADMIN",
				"CAP_SYSLOG",
				"CAP_WAKE_ALARM",
				"CAP_BLOCK_SUSPEND",
				"CAP_AUDIT_READ"
			],
			"permitted": [
				"CAP_CHOWN",
				"CAP_DAC_OVERRIDE",
				"CAP_DAC_READ_SEARCH",
				"CAP_FOWNER",
				"CAP_FSETID",
				"CAP_KILL",
				"CAP_SETGID",
				"CAP_SETUID",
				"CAP_SETPCAP",
				"CAP_LINUX_IMMUTABLE",
				"CAP_NET_BIND_SERVICE",
				"CAP_NET_BROADCAST",
				"CAP_NET_ADMIN",
				"CAP_NET_RAW",
				"CAP_IPC_LOCK",
				"CAP_IPC_OWNER",
				"CAP_SYS_MODULE",
				"CAP_SYS_RAWIO",
				"CAP_SYS_CHROOT",
				"CAP_SYS_PTRACE",
				"CAP_SYS_PACCT",
				"CAP_SYS_ADMIN",
				"CAP_SYS_BOOT",
				"CAP_SYS_NICE",
				"CAP_SYS_RESOURCE",
				"CAP_SYS_TIME",
				"CAP_SYS_TTY_CONFIG",
				"CAP_MKNOD",
				"CAP_LEASE",
				"CAP_AUDIT_WRITE",
				"CAP_AUDIT_CONTROL",
				"CAP_SETFCAP",
				"CAP_MAC_OVERRIDE",
				"CAP_MAC_ADMIN",
				"CAP_SYSLOG",
				"CAP_WAKE_ALARM",
				"CAP_BLOCK_SUSPEND",
				"CAP_AUDIT_READ"
			],
			"ambient": [
				"CAP_CHOWN",
				"CAP_DAC_OVERRIDE",
				"CAP_DAC_READ_SEARCH",
				"CAP_FOWNER",
				"CAP_FSETID",
				"CAP_KILL",
				"CAP_SETGID",
				"CAP_SETUID",
				"CAP_SETPCAP",
				"CAP_LINUX_IMMUTABLE",
				"CAP_NET_BIND_SERVICE",
				"CAP_NET_BROADCAST",
				"CAP_NET_ADMIN",
				"CAP_NET_RAW",
				"CAP_IPC_LOCK",
				"CAP_IPC_OWNER",
				"CAP_SYS_MODULE",
				"CAP_SYS_RAWIO",
				"CAP_SYS_CHROOT",
				"CAP_SYS_PTRACE",
				"CAP_SYS_PACCT",
				"CAP_SYS_ADMIN",
				"CAP_SYS_BOOT",
				"CAP_SYS_NICE",
				"CAP_SYS_RESOURCE",
				"CAP_SYS_TIME",
				"CAP_SYS_TTY_CONFIG",
				"CAP_MKNOD",
				"CAP_LEASE",
				"CAP_AUDIT_WRITE",
				"CAP_AUDIT_CONTROL",
				"CAP_SETFCAP",
				"CAP_MAC_OVERRIDE",
				"CAP_MAC_ADMIN",
				"CAP_SYSLOG",
				"CAP_WAKE_ALARM",
				"CAP_BLOCK_SUSPEND",
				"CAP_AUDIT_READ"
			]
		}
	}
}
```
