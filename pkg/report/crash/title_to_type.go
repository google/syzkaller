// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package crash

var titleToType = []struct {
	includePrefixes []string
	crashType       Type
}{
	{
		includePrefixes: []string{
			"KFENCE: use-after-free write",
		},
		crashType: KFENCEUseAfterFreeWrite,
	},
	{
		includePrefixes: []string{
			"KFENCE: use-after-free read",
			"KFENCE: use-after-free", // Read/Write is not clear. It is at least Read.
		},
		crashType: KFENCEUseAfterFreeRead,
	},
	{
		includePrefixes: []string{
			"KFENCE: invalid write",
			"KFENCE: out-of-bounds write",
		},
		crashType: KFENCEWrite,
	},
	{
		includePrefixes: []string{
			// keep-sorted start
			"KFENCE: invalid read",
			"KFENCE: out-of-bounds read",
			"KFENCE: out-of-bounds", // Read/Write is not clear. It is at least Read.
			// keep-sorted end
		},
		crashType: KFENCERead,
	},
	{
		includePrefixes: []string{
			"KFENCE: memory corruption",
		},
		crashType: KFENCEMemoryCorruption,
	},
	{
		includePrefixes: []string{
			"KFENCE: invalid free",
		},
		crashType: KFENCEInvalidFree,
	},
	{
		includePrefixes: []string{
			"KMSAN: uninit-value",
		},
		crashType: KMSANUninitValue,
	},
	{
		includePrefixes: []string{
			// keep-sorted start
			"KMSAN: kernel-infoleak-after-free",
			"KMSAN: kernel-usb-infoleak-after-free",
			"KMSAN: use-after-free",
			// keep-sorted end
		},
		crashType: KMSANUseAfterFreeRead,
	},
	{
		includePrefixes: []string{
			"KMSAN: kernel-infoleak",
			"KMSAN: kernel-usb-infoleak",
		},
		crashType: KMSANInfoLeak,
	},
	{
		includePrefixes: []string{
			"KASAN: null-ptr-deref Write",
		},
		crashType: KASANNullPtrDerefWrite,
	},
	{
		includePrefixes: []string{
			"KASAN: null-ptr-deref Read",
		},
		crashType: KASANNullPtrDerefRead,
	},
	{
		includePrefixes: []string{
			"BUG: unable to handle kernel NULL pointer dereference in",
		},
		crashType: NullPtrDerefBUG,
	},
	{
		includePrefixes: []string{
			// keep-sorting start
			"KASAN: global-out-of-bounds Write",
			"KASAN: out-of-bounds Write",
			"KASAN: slab-out-of-bounds Write",
			"KASAN: stack-out-of-bounds Write",
			"KASAN: user-memory-access Write",
			"KASAN: vmalloc-out-of-bounds Write",
			"KASAN: wild-memory-access Write",
			// keep-sorting end
		},
		crashType: KASANWrite,
	},
	{
		includePrefixes: []string{
			// keep-sorting start
			"KASAN: global-out-of-bounds Read",
			"KASAN: invalid-access Read",
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
		crashType: KASANRead,
	},
	{
		includePrefixes: []string{
			"KASAN: double-free or invalid-free",
			"KASAN: invalid-free",
		},
		crashType: KASANInvalidFree,
	},
	{
		includePrefixes: []string{
			"KASAN: slab-use-after-free Write",
			"KASAN: use-after-free Write",
		},
		crashType: KASANUseAfterFreeWrite,
	},
	{
		includePrefixes: []string{
			"KASAN: slab-use-after-free Read",
			"KASAN: use-after-free Read",
			"KASAN: use-after-free", // Read/Write is not clear. It is at least Read.
		},
		crashType: KASANUseAfterFreeRead,
	},
	{
		includePrefixes: []string{
			// keep-sorting start
			"BUG: corrupted list",
			"BUG: unable to handle kernel paging request",
			// keep-sorting end
		},
		crashType: MemorySafetyBUG,
	},
	{
		includePrefixes: []string{
			"WARNING: refcount bug",
		},
		crashType: RefcountWARNING,
	},
	{
		includePrefixes: []string{
			"UBSAN: array-index-out-of-bounds",
		},
		crashType: MemorySafetyUBSAN,
	},
	{
		includePrefixes: []string{"KCSAN: data-race"},
		crashType:       KCSANDataRace,
	},
	{
		includePrefixes: []string{"KCSAN: assert: race in"},
		crashType:       KCSANAssert,
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
		crashType: LockdepBug,
	},
	{
		includePrefixes: []string{
			// keep-sorted start
			"BUG: scheduling while atomic in",
			"BUG: sleeping function called from invalid context in",
			// keep-sorted end
		},
		crashType: AtomicSleep,
	},
	{
		includePrefixes: []string{"memory leak in"},
		crashType:       MemoryLeak,
	},
	{
		includePrefixes: []string{
			// keep-sorted start
			"BUG: bad usercopy in",
			"kernel BUG",
			// keep-sorted end
		},
		crashType: Bug,
	},
	{
		includePrefixes: []string{"WARNING in"},
		crashType:       Warning,
	},
	{
		includePrefixes: []string{
			// keep-sorted start
			"BUG: stack guard page was hit in",
			"WARNING: corrupted",
			"WARNING: kernel stack frame pointer has bad value",
			"WARNING: kernel stack regs has bad",
			// keep-sorted end
		},
		crashType: UnknownType, // This is printk().
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
		crashType: Hang,
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
		crashType: DoS,
	},
	{
		includePrefixes: []string{"unexpected kernel reboot"},
		crashType:       UnexpectedReboot,
	},
	{
		includePrefixes: []string{
			"SYZFAIL",
			"SYZFATAL:",
		},
		crashType: SyzFailure,
	},

	// DEFAULTS.
	{
		includePrefixes: []string{"WARNING:"},
		crashType:       Warning,
	},
	{
		includePrefixes: []string{"BUG:"},
		crashType:       UnknownType,
	},
	{
		includePrefixes: []string{"INFO:"},
		crashType:       UnknownType,
	},
	{
		includePrefixes: []string{"KASAN:"},
		crashType:       KASANUnknown,
	},
	{
		includePrefixes: []string{"KFENCE:"},
		crashType:       KFENCEUnknown,
	},
	{
		includePrefixes: []string{"KMSAN:"},
		crashType:       KMSANUnknown,
	},
	{
		includePrefixes: []string{"UBSAN:"},
		crashType:       UBSAN,
	},
	{
		includePrefixes: []string{"KCSAN:"},
		crashType:       KCSANUnknown,
	},
}
