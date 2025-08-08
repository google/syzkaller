// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package mgrconfig

import (
	"encoding/json"

	"github.com/google/syzkaller/pkg/asset"
)

type Config struct {
	// Instance name (used for identification and as GCE instance prefix).
	Name string `json:"name"`
	// Target OS/arch, e.g. "linux/arm64" or "linux/amd64/386" (amd64 OS with 386 test process).
	RawTarget string `json:"target"`
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
	WorkdirTemplate string `json:"workdir_template,omitempty"`
	// Directory with kernel object files (e.g. `vmlinux` for linux)
	// (used for report symbolization, coverage reports and in tree modules finding, optional).
	KernelObj string `json:"kernel_obj"`
	// Directories with out-of-tree kernel module object files for coverage report generation (optional).
	// KernelObj is also scanned for in-tree kernel modules and does not need to be duplicated here.
	// Note: the modules need to be unstripped and contain debug info.
	ModuleObj []string `json:"module_obj,omitempty"`
	// Kernel source directory (if not set defaults to KernelObj).
	KernelSrc string `json:"kernel_src,omitempty"`
	// Location of the driectory where the kernel was built (if not set defaults to KernelSrc)
	KernelBuildSrc string `json:"kernel_build_src,omitempty"`
	// Is the kernel built separately from the modules? (Specific to Android builds)
	AndroidSplitBuild bool `json:"android_split_build"`
	// Kernel subsystem with paths to each subsystem, paths starting with "-" will be excluded
	//	"kernel_subsystem": [
	//		{ "name": "sound", "path": ["sound", "techpack/audio", "-techpack/audio/dsp"]},
	//		{ "name": "mydriver": "path": ["mydriver_path"]}
	//	]
	KernelSubsystem []Subsystem `json:"kernel_subsystem,omitempty"`
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
	// Hub input domain identifier (optional).
	// The domain is used to avoid duplicate work (input minimization, smashing)
	// across multiple managers testing similar kernels and connected to the same hub.
	// If two managers are in the same domain, they will not do input minimization after each other.
	// If additionally they are in the same smashing sub-domain, they will also not do smashing
	// after each other.
	// By default (empty domain) all managers testing the same OS are placed into the same domain,
	// this is a reasonable setting if managers test roughly the same kernel. In this case they
	// will not do minimization nor smashing after each other.
	// The setting can be either a single identifier (e.g. "foo") which will affect both minimization
	// and smashing; or two identifiers separated with '/' (e.g. "foo/bar"), in this case the first
	// identifier affects minimization and both affect smashing.
	// For example, if managers test different Linux kernel versions with different tools,
	// a reasonable use of domains on these managers can be:
	//  - "upstream/kasan"
	//  - "upstream/kmsan"
	//  - "upstream/kcsan"
	//  - "5.4/kasan"
	//  - "5.4/kcsan"
	//  - "4.19/kasan"
	HubDomain string `json:"hub_domain,omitempty"`

	// List of email addresses to receive notifications when bugs are encountered for the first time (optional).
	// Mailx is the only supported mailer. Please set it up prior to using this function.
	EmailAddrs []string `json:"email_addrs,omitempty"`

	DashboardClient    string `json:"dashboard_client,omitempty"`
	DashboardAddr      string `json:"dashboard_addr,omitempty"`
	DashboardKey       string `json:"dashboard_key,omitempty"`
	DashboardUserAgent string `json:"dashboard_user_agent,omitempty"`
	// If set, only consult dashboard if it needs reproducers for crashes,
	// but otherwise don't send any info to dashboard (default: false).
	DashboardOnlyRepro bool `json:"dashboard_only_repro,omitempty"`

	// Location of the syzkaller checkout, syz-manager will look
	// for binaries in bin subdir (does not have to be syzkaller checkout as
	// long as it preserves `bin` dir structure)
	Syzkaller string `json:"syzkaller"`

	// Number of parallel test processes inside of each VM.
	// Allowed values are 1-32, recommended range is ~4-8, default value is 6.
	// It should be chosen to saturate CPU inside of the VM and maximize number of test executions,
	// but to not oversubscribe CPU and memory too severe to not cause OOMs and false hangs/stalls.
	Procs int `json:"procs"`

	// Maximum number of logs to store per crash (default: 100).
	MaxCrashLogs int `json:"max_crash_logs"`

	// Type of sandbox to use during fuzzing:
	// "none": test under root;
	//      don't do anything special beyond resource sandboxing,
	//      gives the most coverage, default
	// "namespace": create a new user namespace for testing using CLONE_NEWUSER (supported only on Linux),
	//      the test process has CAP_ADMIN inside of the user namespace, but not in the init namespace,
	//      but the test process still has access to all /dev/ nodes owned by root,
	//      this is a compromise between coverage and bug impact,
	//	requires building kernel with CONFIG_USER_NS
	// "setuid": impersonate into user nobody (65534) (supported on Linux, FreeBSD, NetBSD, OpenBSD)
	//      this is the most restrictive sandbox
	// "android": emulate permissions of an untrusted Android app (supported only on Linux)
	Sandbox string `json:"sandbox"`

	// This value is passed as an argument to executor and allows to adjust sandbox behavior
	// via manager config. For example you can switch between system and user accounts based
	// on this value.
	SandboxArg int64 `json:"sandbox_arg"`

	// Enables snapshotting mode. In this mode VM is snapshotted and restarted from the snapshot
	// before executing each test program. This provides better reproducibility and avoids global
	// accumulated state. Currently only qemu VMs and Linux support this mode.
	Snapshot bool `json:"snapshot"`

	// Use KCOV coverage (default: true).
	Cover bool `json:"cover"`

	// CovFilter used to restrict the area of the kernel visible to syzkaller.
	// DEPRECATED! Use the FocusAreas parameter instead.
	CovFilter CovFilterCfg `json:"cover_filter,omitempty"`

	// For each prog in the corpus, remember the raw array of PCs obtained from the kernel.
	// It can be useful for debugging syzkaller descriptions and syzkaller itself.
	// Disabled by default as it slows down fuzzing.
	RawCover bool `json:"raw_cover"`

	// Reproduce, localize and minimize crashers (default: true).
	Reproduce bool `json:"reproduce"`

	// The number of VMs that are reserved to only perform fuzzing and nothing else.
	// Can be helpful e.g. to ensure that the pool of fuzzing VMs is never exhausted and
	// the manager continues fuzzing no matter how many new bugs are encountered.
	// By default the value is 0, i.e. all VMs can be used for all purposes.
	FuzzingVMs int `json:"fuzzing_vms,omitempty"`

	// Keep existing programs in the corpus even if they no longer pass syscall filters.
	// By default it is true, as this is the desired behavior when executing syzkaller
	// locally.
	PreserveCorpus bool `json:"preserve_corpus"`

	// List of syscalls to test (optional). For example:
	//	"enable_syscalls": [ "mmap", "openat$ashmem", "ioctl$ASHMEM*" ]
	EnabledSyscalls []string `json:"enable_syscalls,omitempty"`
	// List of system calls that should be treated as disabled (optional).
	DisabledSyscalls []string `json:"disable_syscalls,omitempty"`
	// List of syscalls that should not be mutated by the fuzzer (optional).
	NoMutateSyscalls []string `json:"no_mutate_syscalls,omitempty"`
	// List of regexps for known bugs.
	// Don't save reports matching these regexps, but reboot VM after them,
	// matched against whole report output.
	Suppressions []string `json:"suppressions,omitempty"`
	// Completely ignore reports matching these regexps (don't save nor reboot),
	// must match the first line of crash message.
	Ignores []string `json:"ignores,omitempty"`
	// List of regexps to select bugs of interest.
	// If this list is not empty and none of the regexps match a bug, it's suppressed.
	// Regexps are matched against bug title, guilty file and maintainer emails.
	Interests []string `json:"interests,omitempty"`

	// Path to the strace binary compiled for the target architecture.
	// If set, for each reproducer syzkaller will run it once more under strace and save
	// the output.
	StraceBin string `json:"strace_bin"`
	// If true, syzkaller will expect strace_bin to be part of the target
	// image instead of copying it from the host (default: false).
	StraceBinOnTarget bool `json:"strace_bin_on_target"`

	// File in PATH to syz-execprog/executor on the target. If set,
	// syzkaller will expect the execprog/executor binaries to be part of
	// the target image instead of copying them from the host.
	ExecprogBinOnTarget string `json:"execprog_bin_on_target"`
	ExecutorBinOnTarget string `json:"executor_bin_on_target"`

	// Whether to run fsck commands on file system images found in new crash
	// reproducers. The fsck logs get reported as assets in the dashboard.
	// Note: you may need to install 3rd-party dependencies for this to work.
	// fsck commands that can be run by syz-manager are specified in mount
	// syscall descriptions - typically in sys/linux/filesystem.txt.
	// Enabled by default.
	RunFsck bool `json:"run_fsck"`

	// Type of virtual machine to use, e.g. "qemu", "gce", "android", "isolated", etc.
	Type string `json:"type"`
	// VM-type-specific parameters.
	// Parameters for concrete types are in Config type in vm/TYPE/TYPE.go, e.g. vm/qemu/qemu.go.
	VM json.RawMessage `json:"vm"`

	// Asset storage configuration. There can be specified the upload location and crash assets
	// to upload.
	// A sample config:
	// {
	//    "upload_to": "gs://bucket",
	//    "public_access": true
	// }
	// More details can be found in pkg/asset/config.go.
	AssetStorage *asset.Config `json:"asset_storage"`

	// Experimental options.
	Experimental Experimental

	// Implementation details beyond this point. Filled after parsing.
	Derived `json:"-"`
}

// These options are not guaranteed to be backward/forward compatible and
// can be dropped at any moment.
type Experimental struct {
	// Don't let the VM state accumulate too much by restarting
	// syz-executor before most prog executions.
	ResetAccState bool `json:"reset_acc_state"`

	// Use KCOV remote coverage feature (default: true).
	RemoteCover bool `json:"remote_cover"`

	// Hash adjacent PCs to form fuzzing feedback signal, otherwise use PCs as signal (default: true).
	CoverEdges bool `json:"cover_edges"`

	// Use automatically (auto) generated or manually (manual) written descriptions or any (any) (default: manual)
	DescriptionsMode string `json:"descriptions_mode"`

	// FocusAreas configures what attention syzkaller should pay to the specific areas of the kernel.
	// The probability of selecting a program from an area is at least `Weight / sum of weights`.
	// If FocusAreas is non-empty, by default all kernel code not covered by any filter will be ignored.
	// To focus fuzzing on some areas, but to consider the rest of the code as well, add a record
	// with an empty Filter, but non-empty weight.
	// E.g. "focus_areas": [ {"filter": {"files": ["^net"]}, "weight": 10.0}, {"weight": 1.0} ].
	FocusAreas []FocusArea `json:"focus_areas,omitempty"`

	// The number of executions per proc before it's restarted.
	// Lower values may improve bug reproduction rates, but they slow down fuzzing considerably.
	// The default value is 600.
	ProcMaxExecs int `json:"proc_max_execs,omitempty"`
}

type FocusArea struct {
	// Name allows to display detailed statistics for every focus area.
	Name string `json:"name"`

	// A coverage filter.
	// Supported filter types:
	// "files": support specifying kernel source files, support regular expression.
	// eg. "files": ["^net/core/tcp.c$", "^net/sctp/", "tcp"].
	// "functions": support specifying kernel functions, support regular expression.
	// eg. "functions": ["^foo$", "^bar", "baz"].
	// "pcs": specify raw PC table files name.
	// Each line of the file should be: "64-bit-pc:32-bit-weight\n".
	// eg. "0xffffffff81000000:0x10\n"
	// If empty, it's assumed to match the whole kernel.
	Filter CovFilterCfg `json:"filter,omitempty"`

	// Weight is a positive number that determines how much focus should be put on this area.
	Weight float64 `json:"weight"`
}

type Subsystem struct {
	Name  string   `json:"name"`
	Paths []string `json:"path"`
}

type CovFilterCfg struct {
	Files     []string `json:"files,omitempty"`
	Functions []string `json:"functions,omitempty"`
	RawPCs    []string `json:"pcs,omitempty"`
}
