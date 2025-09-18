// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

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
	if len(cfg.Focus) == 0 {
		noFocus(mgrCfg)
		return nil
	}
	for _, focus := range cfg.Focus {
		cb := setFocus[focus]
		if cb == nil {
			return fmt.Errorf("unknown focus: %s", focus)
		}
		err := cb(mgrCfg)
		if err != nil {
			return fmt.Errorf("failed to apply focus %s: %w", focus, err)
		}
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
			"getgid", "getuid", "gettid", "unshare", "pipe",
			"syz_emit_ethernet", "syz_extract_tcp_res",
			"syz_genetlink_get_family_id", "syz_init_net_socket",
			"mkdirat$cgroup*", "openat$cgroup*", "write$cgroup*",
			"clock_gettime", "bpf", "openat$tun", "openat$ppp",
			"syz_open_procfs$namespace", "syz_80211_*", "nanosleep",
			"openat$nci", "ioctl$IOCTL_GET_NCIDEV_IDX", "openat$rfkill",
			"openat$6lowpan*", "openat$pidfd", "openat$tcp*", "openat$vhost_vsock",
			"openat$ptp*", "ioctl$PTP*",
		)
		return nil
	},
	api.FocusFS: func(mgrCfg *mgrconfig.Config) error {
		mgrCfg.EnabledSyscalls = append(mgrCfg.EnabledSyscalls,
			"syz_mount_image", "open", "openat", "creat", "close", "read",
			"pread64", "readv", "preadv", "preadv2", "write", "pwrite64",
			"writev", "pwritev", "pwritev2", "lseek", "copy_file_range", "dup",
			"dup2", "dup3", "tee", "splice", "vmsplice", "sendfile", "stat",
			"lstat", "fstat", "newfstatat", "statx", "poll", "clock_gettime",
			"ppoll", "select", "pselect6", "epoll_create", "epoll_create1",
			"epoll_ctl", "epoll_wait", "epoll_pwait", "epoll_pwait2", "mmap",
			"munmap", "mremap", "msync", "readahead", "fcntl", "mknod", "mknodat",
			"chmod", "fchmod", "fchmodat", "chown", "lchown", "fchown",
			"fchownat", "fallocate", "faccessat", "faccessat2", "utime", "utimes",
			"futimesat", "utimensat", "link", "linkat", "symlinkat", "symlink",
			"unlink", "unlinkat", "readlink", "readlinkat", "rename", "renameat",
			"renameat2", "mkdir", "mkdirat", "rmdir", "truncate", "ftruncate",
			"flock", "fsync", "fdatasync", "sync", "syncfs", "sync_file_range",
			"getdents", "getdents64", "name_to_handle_at", "open_by_handle_at",
			"chroot", "getcwd", "chdir", "fchdir", "quotactl", "pivot_root",
			"statfs", "fstatfs", "syz_open_procfs", "syz_read_part_table",
			"mount", "fsopen", "fspick", "fsconfig", "fsmount", "move_mount",
			"open_tree", "mount_setattr", "ioctl$FS_*", "ioctl$BTRFS*",
			"ioctl$AUTOFS*", "ioctl$EXT4*", "ioctl$F2FS*", "ioctl$FAT*",
			"ioctl$VFAT*", "ioctl$FI*",
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
			"io_uring_*", "syz_io_uring_*", "syz_memcpy_off", "mmap", "madvise",
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
}

func noFocus(mgrCfg *mgrconfig.Config) {
	mgrCfg.DisabledSyscalls = []string{"perf_event_open*", "syz_mount_image$hfs", "syz_mount_image$gfs*"}
}
