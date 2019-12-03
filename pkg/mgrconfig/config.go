// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package mgrconfig

import "encoding/json"

type Config struct {
	// Instance name (used for identification and as GCE instance prefix).
	Name string `json:"name"`
	// Target OS/arch, e.g. "linux/arm64" or "linux/amd64/386" (amd64 OS with 386 test process).
	Target string `json:"target"`
	// URL that will display information about the running syz-manager process (e.g. "localhost:50000").
	HTTP string `json:"http"`
	// TCP address to serve RPC for fuzzer processes (optional).
	RPC string `json:"rpc,omitempty"`
	// Location of a working directory for the syz-manager process. Outputs here include:
	// - <workdir>/crashes/*: crash output files
	// - <workdir>/corpus.db: corpus with interesting programs
	// - <workdir>/instance-x: per VM instance temporary files
	Workdir string `json:"workdir"`
	// Refers to a directory. Optional.
	// Each VM will get a recursive copy of the files that are present in workdir_template.
	// VM config can then use these private copies as needed. The copy directory
	// can be referenced with "{{TEMPLATE}}" string. This is different from using
	// the files directly in that each instance will get own clean, private,
	// scratch copy of the files. Currently supported only for qemu_args argument
	// of qemu VM type. Use example:
	// Create a template dir with necessary files:
	// $ mkdir /mytemplatedir
	// $ truncate -s 64K /mytemplatedir/fd
	// Then specify the dir in the manager config:
	//	"workdir_template": "/mytemplatedir"
	// Then use these files in VM config:
	//	"qemu_args": "-fda {{TEMPLATE}}/fd"
	WorkdirTemplate string `json:"workdir_template"`
	// Directory with kernel object files (e.g. `vmlinux` for linux)
	// (used for report symbolization and coverage reports, optional).
	KernelObj string `json:"kernel_obj"`
	// Kernel source directory (if not set defaults to KernelObj).
	KernelSrc string `json:"kernel_src,omitempty"`
	// Location of the driectory where the kernel was built (if not set defaults to KernelSrc)
	KernelBuildSrc string `json:"kernel_build_src"`
	// Arbitrary optional tag that is saved along with crash reports (e.g. branch/commit).
	Tag string `json:"tag,omitempty"`
	// Location of the disk image file.
	Image string `json:"image,omitempty"`
	// Location (on the host machine) of a root SSH identity to use for communicating with
	// the virtual machine (may be empty for some VM types).
	SSHKey string `json:"sshkey,omitempty"`
	// SSH user ("root" by default).
	SSHUser string `json:"ssh_user,omitempty"`

	HubClient string `json:"hub_client,omitempty"`
	HubAddr   string `json:"hub_addr,omitempty"`
	HubKey    string `json:"hub_key,omitempty"`

	// List of email addresses to receive notifications when bugs are encountered for the first time (optional).
	// Mailx is the only supported mailer. Please set it up prior to using this function.
	EmailAddrs []string `json:"email_addrs,omitempty"`

	DashboardClient string `json:"dashboard_client,omitempty"`
	DashboardAddr   string `json:"dashboard_addr,omitempty"`
	DashboardKey    string `json:"dashboard_key,omitempty"`

	// Location of the syzkaller checkout, syz-manager will look
	// for binaries in bin subdir (does not have to be syzkaller checkout as
	// long as it preserves `bin` dir structure)
	Syzkaller string `json:"syzkaller"`

	// Number of parallel test processes inside of each VM.
	// 1 by default, 4 or 8 would be reasonable numbers too.
	Procs int `json:"procs"`

	// Type of sandbox to use during fuzzing:
	// "none": don't do anything special beyond resource sandboxing, default
	// "setuid": impersonate into user nobody (65534). Supported only for some OSes.
	// "namespace": create a new namespace for fuzzer using CLONE_NEWNS/CLONE_NEWNET/CLONE_NEWPID/etc,
	//	requires building kernel with CONFIG_NAMESPACES, CONFIG_UTS_NS, CONFIG_USER_NS,
	//	CONFIG_PID_NS and CONFIG_NET_NS. Supported only for some OSes.
	// "android": (Android) Emulate permissions of an untrusted app.
	Sandbox string `json:"sandbox"`

	// Use KCOV coverage (default: true).
	Cover bool `json:"cover"`
	// Reproduce, localize and minimize crashers (default: true).
	Reproduce bool `json:"reproduce"`

	// List of syscalls to test (optional). For example:
	//	"enable_syscalls": [ "mmap", "openat$ashmem", "ioctl$ASHMEM*" ]
	EnabledSyscalls []string `json:"enable_syscalls,omitempty"`
	// List of system calls that should be treated as disabled (optional).
	DisabledSyscalls []string `json:"disable_syscalls,omitempty"`
	// List of regexps for known bugs.
	// Don't save reports matching these regexps, but reboot VM after them,
	// matched against whole report output.
	Suppressions []string `json:"suppressions,omitempty"`
	// Completely ignore reports matching these regexps (don't save nor reboot),
	// must match the first line of crash message.
	Ignores []string `json:"ignores,omitempty"`

	// Type of virtual machine to use, e.g. "qemu", "gce", "android", "isolated", etc.
	Type string `json:"type"`
	// VM-type-specific parameters.
	// Parameters for concrete types are in Config type in vm/TYPE/TYPE.go, e.g. vm/qemu/qemu.go.
	VM json.RawMessage `json:"vm"`

	// Implementation details beyond this point.
	// Parsed Target:
	TargetOS     string `json:"-"`
	TargetArch   string `json:"-"`
	TargetVMArch string `json:"-"`
	// Syzkaller binaries that we are going to use:
	SyzFuzzerBin   string `json:"-"`
	SyzExecprogBin string `json:"-"`
	SyzExecutorBin string `json:"-"`
}
