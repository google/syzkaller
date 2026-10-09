// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package fuzzconfig generates syz-manager configuration files customized for base and patched
// kernel fuzzing targets.
package fuzzconfig

import (
	_ "embed"
	"encoding/json"
	"fmt"

	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/syz-cluster/pkg/api"
)

//go:embed base.cfg
var baseConfigJSON []byte

//go:embed patched.cfg
var patchedConfigJSON []byte

// GenerateBase produces a syz-manager config for the base kernel.
// The caller must still invoke mgrconfig.Complete.
func GenerateBase(cfg *api.FuzzConfig) (*mgrconfig.Config, error) {
	var baseRaw json.RawMessage
	err := config.LoadData(baseConfigJSON, &baseRaw)
	if err != nil {
		return nil, fmt.Errorf("failed to read the base config: %w", err)
	}
	base, err := mgrconfig.LoadPartialData(baseRaw)
	if err != nil {
		return nil, fmt.Errorf("failed to load the config: %w", err)
	}
	err = applyFuzzConfig(base, cfg)
	if err != nil {
		return nil, err
	}
	return base, nil
}

// GeneratePatched produces a syz-manager config for the base kernel.
// The caller must still invoke mgrconfig.Complete.
func GeneratePatched(cfg *api.FuzzConfig) (*mgrconfig.Config, error) {
	var baseRaw, deltaRaw json.RawMessage
	err := config.LoadData(baseConfigJSON, &baseRaw)
	if err != nil {
		return nil, fmt.Errorf("failed to read the base config: %w", err)
	}
	err = config.LoadData(patchedConfigJSON, &deltaRaw)
	if err != nil {
		return nil, fmt.Errorf("failed to read the patched config: %w", err)
	}
	patchedRaw, err := config.MergeJSONs(baseRaw, deltaRaw)
	if err != nil {
		return nil, fmt.Errorf("failed to merge the configs: %w", err)
	}
	patched, err := mgrconfig.LoadPartialData(patchedRaw)
	if err != nil {
		return nil, fmt.Errorf("failed to load the config: %w", err)
	}
	err = applyFuzzConfig(patched, cfg)
	if err != nil {
		return nil, err
	}
	return patched, nil
}

func applyFuzzConfig(mgrCfg *mgrconfig.Config, cfg *api.FuzzConfig) error {
	haveFocus := map[string]bool{}
	for _, focus := range cfg.Focus {
		cb := setFocus[focus]
		if cb == nil {
			return fmt.Errorf("unknown focus: %s", focus)
		}
		err := cb(mgrCfg)
		if err != nil {
			return fmt.Errorf("failed to apply focus %s: %w", focus, err)
		}
		haveFocus[focus] = true
	}
	if len(haveFocus) == 0 {
		noFlakyFsCalls(mgrCfg)
		noFlakyTraceCalls(mgrCfg)
	}
	// This could have been done in a more generic ways, but so far
	// there are not too many such cases.
	if haveFocus[api.FocusNet] && !haveFocus[api.FocusBPF] {
		noFlakyTraceCalls(mgrCfg)
	}
	return nil
}

// nolint: lll
var setFocus = map[string]func(*mgrconfig.Config) error{
	api.FocusKVM: func(mgrCfg *mgrconfig.Config) error {
		mgrCfg.EnabledSyscalls = append(mgrCfg.EnabledSyscalls,
			"openat$kvm",
			"openat$sev",
			"close",
			"ioctl$KVM*",
			"syz_kvm*",
			"mmap$KVM_VCPU",
			"munmap",
			"syz_memcpy_off$KVM_EXIT_MMIO",
			"syz_memcpy_off$KVM_EXIT_HYPERCALL",
			"eventfd2",
			"write$eventfd",
		)
		var err error
		mgrCfg.VM, err = config.MergeJSONs(mgrCfg.VM, []byte(
			`{"qemu_args": "-machine q35,nvdimm=on,accel=kvm,kernel-irqchip=split -cpu max,migratable=off -enable-kvm -smp 2,sockets=2,cores=1"}`))
		return err
	},
	api.FocusNet: func(mgrCfg *mgrconfig.Config) error {
		mgrCfg.EnabledSyscalls = append(mgrCfg.EnabledSyscalls,
			"accept", "accept4", "bind", "close", "connect", "epoll_create",
			"epoll_create1", "epoll_ctl", "epoll_pwait", "epoll_wait",
			"getpeername", "getsockname", "getsockopt", "ioctl", "listen",
			"mmap", "poll", "ppoll", "pread64", "preadv", "pselect6",
			"pwrite64", "pwritev", "read", "readv", "recvfrom", "recvmmsg",
			"recvmsg", "select", "sendfile", "sendmmsg", "sendmsg", "sendto",
			"setsockopt", "shutdown", "socket", "socketpair", "splice",
			"vmsplice", "write", "writev", "tee", "bpf", "getpid",
			"getgid", "getuid", "gettid", "unshare", "pipe", "pipe2",
			"syz_emit_ethernet", "syz_extract_tcp_res",
			"syz_genetlink_get_family_id", "syz_init_net_socket",
			"syz_socket_connect_nvme_tcp",
			"mkdirat$cgroup*", "openat$cgroup*", "write$cgroup*",
			"clock_gettime", "openat$tun", "openat$ppp",
			"syz_open_procfs$namespace", "syz_80211_*", "nanosleep",
			"openat$nci", "openat$rfkill",
			"openat$6lowpan*", "openat$pidfd", "openat$tcp*", "openat$vhost_vsock",
			"openat$vsock", "openat$vnet",
			"openat$ptp*", "openat$qrtrtun", "openat$uverbs0",
			"openat$capi20", "openat$proc_capi20*", "openat$misdntimer",
			"openat$pfkey", "openat$ipvs", "openat$sysctl",
		)
		return nil
	},
	api.FocusFS: func(mgrCfg *mgrconfig.Config) error {
		mgrCfg.EnabledSyscalls = append(mgrCfg.EnabledSyscalls,
			"syz_mount_image", "open", "openat", "creat", "close", "read",
			"pread64", "readv", "preadv", "preadv2", "write", "pwrite64",
			"writev", "pwritev", "pwritev2", "lseek", "copy_file_range", "dup",
			"dup2", "dup3", "pipe", "pipe2", "tee", "splice", "vmsplice", "sendfile", "stat",
			"lstat", "fstat", "newfstatat", "statx", "poll", "clock_gettime",
			"ppoll", "select", "pselect6", "epoll_create", "epoll_create1",
			"epoll_ctl", "epoll_wait", "epoll_pwait", "epoll_pwait2", "mmap",
			"munmap", "mremap", "remap_file_pages", "mprotect", "msync", "madvise",
			"fadvise64", "readahead", "mincore", "cachestat", "memfd_create",
			"userfaultfd", "fcntl", "mknod", "mknodat",
			"chmod", "fchmod", "fchmodat", "chown", "lchown", "fchown",
			"fchownat", "fallocate", "faccessat", "faccessat2", "utime", "utimes",
			"futimesat", "utimensat", "link", "linkat", "symlinkat", "symlink",
			"unlink", "unlinkat", "readlink", "readlinkat", "rename", "renameat",
			"renameat2", "mkdir", "mkdirat", "rmdir", "truncate", "ftruncate",
			"flock", "fsync", "fdatasync", "sync", "syncfs", "sync_file_range",
			"getdents", "getdents64", "name_to_handle_at", "open_by_handle_at",
			"chroot", "getcwd", "chdir", "fchdir", "quotactl", "pivot_root",
			"statfs", "fstatfs", "syz_open_procfs", "syz_read_part_table",
			"syz_open_dev$loop",
			"mount", "fsopen", "fspick", "fsconfig", "fsmount", "move_mount",
			"open_tree", "mount_setattr", "ioctl$FS_*", "ioctl$BTRFS*",
			"ioctl$AUTOFS*", "ioctl$EXT4*", "ioctl$F2FS*", "ioctl$FAT*",
			"ioctl$VFAT*", "ioctl$FI*", "ioctl$LOOP*", "ioctl$BLK*",
			"ioctl$INCFS*", "ioctl$UFFDIO*",
		)
		mgrCfg.NoMutateSyscalls = append(mgrCfg.NoMutateSyscalls,
			"syz_mount_image$btrfs",
			"syz_mount_image$ext4",
			"syz_mount_image$f2fs",
			"syz_mount_image$ntfs",
			"syz_mount_image$ocfs2",
			"syz_mount_image$xfs",
		)
		return nil
	},
	api.FocusIoUring: func(mgrCfg *mgrconfig.Config) error {
		mgrCfg.EnabledSyscalls = append(mgrCfg.EnabledSyscalls,
			"io_uring_*", "syz_io_uring_*", "mmap", "madvise",
			"mprotect", "eventfd", "socket", "setsockopt", "accept", "open", "close",
			"clock_gettime", "ioctl$sock_SIOCGIFINDEX", "ioctl$IOCTL_GET_NCIDEV_IDX",
			"openat", "epoll_create",
		)
		return nil
	},
	api.FocusBPF: func(mgrCfg *mgrconfig.Config) error {
		mgrCfg.EnabledSyscalls = append(mgrCfg.EnabledSyscalls,
			"bpf", "mkdir", "mount$bpf", "unlink", "close",
			"perf_event_open*", "ioctl$PERF*", "getpid", "gettid",
			"socketpair", "sendmsg", "recvmsg", "setsockopt$sock_attach_bpf",
			"socket", "ioctl$sock_kcm*", "syz_clone",
			"mkdirat$cgroup*", "openat$cgroup*", "write$cgroup*",
			"openat$tun", "write$tun", "ioctl$TUN*", "ioctl$SIOCSIFHWADDR",
			"openat$ppp", "syz_open_procfs$namespace", "openat$pidfd", "fstat",
		)
		return nil
	},
	api.FocusUSB: func(mgrCfg *mgrconfig.Config) error {
		mgrCfg.EnabledSyscalls = append(mgrCfg.EnabledSyscalls,
			"syz_usb_connect", "syz_usb_connect_ath9k", "syz_usb_disconnect",
			"syz_usb_control_io", "syz_usb_ep_write", "syz_usb_ep_read",
			"syz_open_dev$char_usb", "read$char_usb", "write$char_usb",
			"syz_open_dev$hidraw", "write$hidraw", "read$hidraw",
			"syz_open_dev$hiddev", "read$hiddev", "ioctl$HIDIO*",
			"syz_open_dev$evdev", "write$evdev", "ioctl$EVIO*",
		)
		return nil
	},
	api.FocusMM: func(mgrCfg *mgrconfig.Config) error {
		mgrCfg.EnabledSyscalls = append(mgrCfg.EnabledSyscalls,
			"mmap", "munmap", "mremap", "remap_file_pages", "mprotect", "msync",
			"madvise", "process_madvise", "process_mrelease", "fadvise64", "readahead",
			"mincore", "mlock", "mlock2", "munlock", "mlockall", "munlockall", "brk",
			"membarrier", "pkey_alloc", "pkey_free", "pkey_mprotect", "syz_pkey_set",
			"process_vm_readv", "process_vm_writev", "ptrace",
			"memfd_create", "memfd_secret", "shmget", "shmat", "shmctl", "shmdt",
			"fallocate", "ftruncate", "truncate", "cachestat",
			"open", "openat", "creat", "close", "read", "write",
			"pread64", "pwrite64", "readv", "writev", "preadv", "pwritev",
			"preadv2", "pwritev2", "lseek", "dup", "dup2", "dup3",
			"splice", "vmsplice", "tee", "sendfile", "copy_file_range", "fcntl",
			"mount", "umount2", "fsopen", "fsconfig", "fsmount", "move_mount",
			"userfaultfd", "ioctl$UFFDIO*", "syz_open_procfs", "ioctl$PAGEMAP_SCAN",
			"mbind", "set_mempolicy", "set_mempolicy_home_node", "get_mempolicy",
			"move_pages", "migrate_pages",
			"swapon", "swapoff", "syz_open_dev$loop", "ioctl$LOOP*", "ioctl$BLK*",
			"mkdirat$cgroup*", "clock_gettime", "clone", "clone3", "unshare", "setns",
			"exit", "exit_group", "wait4", "waitid",
		)
		return nil
	},
}

func noFlakyFsCalls(mgrCfg *mgrconfig.Config) {
	mgrCfg.DisabledSyscalls = append(mgrCfg.DisabledSyscalls,
		"syz_mount_image$hfs", "syz_mount_image$gfs*")
}

func noFlakyTraceCalls(mgrCfg *mgrconfig.Config) {
	mgrCfg.DisabledSyscalls = append(mgrCfg.DisabledSyscalls,
		"perf_event_open*", "ioctl$PERF*", "bpf$BPF_RAW_TRACEPOINT_OPEN")
}
