// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"github.com/google/syzkaller/pkg/report/crash"
)

var titleToType = []struct {
	includePrefixes []string
	crashType       crash.Type
}{
	{
		includePrefixes: []string{
			"KMSAN: uninit-value",
		},
		crashType: crash.KMSANUninitValue,
	},
	{
		includePrefixes: []string{
			// keep-sorted start
			"KMSAN: kernel-infoleak-after-free",
			"KMSAN: kernel-usb-infoleak-after-free",
			"KMSAN: use-after-free",
			// keep-sorted end
		},
		crashType: crash.KMSANUseAfterFreeRead,
	},
	{
		includePrefixes: []string{
			"KMSAN: kernel-infoleak",
			"KMSAN: kernel-usb-infoleak",
		},
		crashType: crash.KMSANInfoLeak,
	},
	{
		includePrefixes: []string{
			// keep-sorting start
			"KASAN: global-out-of-bounds Write",
			"KASAN: null-ptr-deref Write",
			"KASAN: out-of-bounds Write",
			"KASAN: slab-out-of-bounds Write",
			"KASAN: stack-out-of-bounds Write",
			"KASAN: user-memory-access Write",
			"KASAN: vmalloc-out-of-bounds Write",
			"KASAN: wild-memory-access Write",
			// keep-sorting end
		},
		crashType: crash.KASANWrite,
	},
	{
		includePrefixes: []string{
			// keep-sorting start
			"KASAN: global-out-of-bounds Read",
			"KASAN: invalid-access Read",
			"KASAN: null-ptr-deref Read",
			"KASAN: out-of-bounds Read",
			"KASAN: slab-out-of-bounds Read",
			"KASAN: slab-out-of-bounds", // Read/Write is not clear. It is at least Read.
			"KASAN: stack-out-of-bounds Read",
			"KASAN: stack-out-of-bounds", // Read/Write is not clear. It is at least Read.
			"KASAN: unknown-crash Read",
			"KASAN: user-memory-access Read",
			"KASAN: vmalloc-out-of-bounds Read",
			"KASAN: wild-memory-access Read",
			"KASAN: wild-memory-access", // Read/Write is not clear. It is at least Read.
			// keep-sorting end
		},
		crashType: crash.KASANRead,
	},
	{
		includePrefixes: []string{
			"KASAN: double-free or invalid-free",
			"KASAN: invalid-free",
		},
		crashType: crash.KASANInvalidFree,
	},
	{
		includePrefixes: []string{
			"KASAN: slab-use-after-free Write",
			"KASAN: use-after-free Write",
		},
		crashType: crash.KASANUseAfterFreeWrite,
	},
	{
		includePrefixes: []string{
			"KASAN: slab-use-after-free Read",
			"KASAN: use-after-free Read",
			"KASAN: use-after-free", // Read/Write is not clear. It is at least Read.
		},
		crashType: crash.KASANUseAfterFreeRead,
	},
	{
		includePrefixes: []string{
			// keep-sorting start
			"BUG: corrupted list",
			"BUG: unable to handle kernel paging request",
			// keep-sorting end
		},
		crashType: crash.MemorySafetyBUG,
	},
	{
		includePrefixes: []string{
			"WARNING: refcount bug",
		},
		crashType: crash.MemorySafetyWARNING,
	},
	{
		includePrefixes: []string{
			"UBSAN: array-index",
		},
		crashType: crash.MemorySafetyUBSAN,
	},
	{
		includePrefixes: []string{"KCSAN: data-race"},
		crashType:       crash.KCSANDataRace,
	},
	{
		includePrefixes: []string{
			// keep-sorted start
			"BUG: bad unlock balance in",
			"BUG: held lock freed in",
			"BUG: rwlock",
			"BUG: spinlock",
			"BUG: still has locks held in",
			"BUG: using", // BUG: using ... in preemptible ...
			"WARNING: bad unlock balance in",
			"WARNING: held lock freed in",
			"WARNING: lock held",
			"WARNING: locking bug in",
			"WARNING: nested lock was not taken in",
			"WARNING: still has locks held in",
			"WARNING: suspicious RCU usage in",
			"inconsistent lock state in",
			"possible deadlock in",
			// keep-sorted end
		},
		crashType: crash.LockdepBug,
	},
	{
		includePrefixes: []string{
			// keep-sorted start
			"BUG: scheduling while atomic in",
			"BUG: sleeping function called from invalid context in",
			// keep-sorted end
		},
		crashType: crash.AtomicSleep,
	},
	{
		includePrefixes: []string{"memory leak in"},
		crashType:       crash.MemoryLeak,
	},
	{
		includePrefixes: []string{
			// keep-sorted start
			"BUG: bad usercopy in",
			"kernel BUG",
			// keep-sorted end
		},
		crashType: crash.Bug,
	},
	{
		includePrefixes: []string{"WARNING in"},
		crashType:       crash.Warning,
	},
	{
		includePrefixes: []string{
			// keep-sorted start
			"BUG: stack guard page was hit in",
			"WARNING: corrupted",
			"WARNING: kernel stack frame pointer has bad value",
			"WARNING: kernel stack regs has bad",
			// keep-sorter end
		},
		crashType: crash.UnknownType, // This is printk().
	},
	{
		includePrefixes: []string{
			// keep-sorted start
			"BUG: soft lockup in",
			"INFO: rcu detected stall in",
			"INFO: task can't die in",
			"INFO: task hung in",
			// keep-sorted end
		},
		crashType: crash.Hang,
	},
	{
		includePrefixes: []string{
			// keep-sorted start
			"Alignment trap in",
			"BUG: Object already free",
			"Internal error in",
			"PANIC: double fault",
			"Unhandled fault in",
			"VFS: Busy inodes after unmount (use-after-free)",
			"VFS: Close: file count is zero (use-after-free)",
			"divide error in",
			"general protection fault in",
			"go runtime error",
			"invalid opcode in",
			"kernel panic:",
			"kernel stack overflow",
			"panic:",
			"rust_kernel panicked",
			"stack segment fault in",
			"trusty:",
			"unregister_netdevice: waiting for DEV to become free",
			// keep-sorted end
		},
		crashType: crash.DoS,
	},
	{
		includePrefixes: []string{"unexpected kernel reboot"},
		crashType:       crash.UnexpectedReboot,
	},
	{
		includePrefixes: []string{
			"SYZFAIL",
			"SYZFATAL:",
		},
		crashType: crash.SyzFailure,
	},

	// DEFAULTS.
	{
		includePrefixes: []string{"WARNING:"},
		crashType:       crash.Warning,
	},
	{
		includePrefixes: []string{"BUG:"},
		crashType:       crash.UnknownType,
	},
	{
		includePrefixes: []string{"INFO:"},
		crashType:       crash.UnknownType,
	},
	{
		includePrefixes: []string{"KASAN:"},
		crashType:       crash.KASANUnknown,
	},
	{
		includePrefixes: []string{"KFENCE:"},
		crashType:       crash.KFENCE,
	},
	{
		includePrefixes: []string{"KMSAN:"},
		crashType:       crash.KMSANUnknown,
	},
	{
		includePrefixes: []string{"UBSAN:"},
		crashType:       crash.UBSAN,
	},
}
