// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"strings"

	"github.com/google/syzkaller/pkg/report/crash"
)

var titleToType = []struct {
	includePrefix []string
	crashType     crash.Type
}{
	{
		includePrefix: []string{"KCSAN: data-race"},
		crashType:     crash.DataRace,
	},
	{
		includePrefix: []string{"KFENCE: "},
		crashType:     crash.UnknownType,
	},
	{
		includePrefix: []string{"BUG: spinlock", "BUG: rwlock"},
		crashType:     crash.LockdepBug,
	},
	{
		includePrefix: []string{"BUG: soft lockup in"},
		crashType:     crash.Hang,
	},
	{
		includePrefix: []string{"BUG: still has locks held in"},
		crashType:     crash.LockdepBug,
	},
	{
		includePrefix: []string{"BUG: scheduling while atomic in"},
		crashType:     crash.AtomicSleep,
	},
	{
		includePrefix: []string{"BUG: bad unlock balance in"},
		crashType:     crash.LockdepBug,
	},
	{
		includePrefix: []string{"BUG: held lock freed in"},
		crashType:     crash.LockdepBug,
	},
	{
		includePrefix: []string{"BUG: sleeping function called from invalid context in"},
		crashType:     crash.AtomicSleep,
	},
	{
		includePrefix: []string{"memory leak in"},
		crashType:     crash.MemoryLeak,
	},
	{
		includePrefix: []string{"BUG: stack guard page was hit in"},
		crashType:     crash.UnknownType, // This is a printk(), not a BUG_ON().
	},
	{
		includePrefix: []string{"WARNING: locking bug in"},
		crashType:     crash.LockdepBug,
	},
	{
		includePrefix: []string{"BUG: bad usercopy in"},
		crashType:     crash.Bug,
	},
	{
		includePrefix: []string{"BUG: corrupted list in"},
		crashType:     crash.Bug,
	},
	{
		includePrefix: []string{"kernel BUG "},
		crashType:     crash.Bug,
	},
	{
		includePrefix: []string{"WARNING in"},
		crashType:     crash.Warning,
	},
	{
		includePrefix: []string{"WARNING: locking bug in"},
		crashType:     crash.LockdepBug,
	},
	{
		includePrefix: []string{"WARNING: still has locks held in"},
		crashType:     crash.LockdepBug,
	},
	{
		includePrefix: []string{"WARNING: nested lock was not taken in"},
		crashType:     crash.LockdepBug,
	},
	{
		includePrefix: []string{"WARNING: lock held when returning to user space in"},
		crashType:     crash.LockdepBug,
	},
	{
		includePrefix: []string{"WARNING: lock heldpossible deadlock in"},
		crashType:     crash.LockdepBug,
	},
	{
		includePrefix: []string{"inconsistent lock state in"},
		crashType:     crash.LockdepBug,
	},
	{
		includePrefix: []string{"WARNING: suspicious RCU usage in"},
		crashType:     crash.LockdepBug,
	},
	{
		includePrefix: []string{"WARNING: kernel stack regs has bad"},
		crashType:     crash.UnknownType,
	},
	{
		includePrefix: []string{"WARNING: kernel stack frame pointer has bad value"},
		crashType:     crash.UnknownType,
	},
	{
		includePrefix: []string{"WARNING: bad unlock balance in"},
		crashType:     crash.LockdepBug,
	},
	{
		includePrefix: []string{"WARNING: held lock freed in"},
		crashType:     crash.LockdepBug,
	},
	{
		includePrefix: []string{"WARNING: kernel stack regs has bad value"},
		crashType:     crash.UnknownType, // This is printk().
	},
	{
		includePrefix: []string{"WARNING: corrupted"},
		crashType:     crash.UnknownType, // This is printk().
	},
	{
		includePrefix: []string{"possible deadlock in"},
		crashType:     crash.LockdepBug,
	},
	{
		includePrefix: []string{"inconsistent lock state in"},
		crashType:     crash.LockdepBug,
	},
	{
		includePrefix: []string{"INFO: rcu detected stall in"},
		crashType:     crash.Hang,
	},
	{
		includePrefix: []string{"INFO: task hung in"},
		crashType:     crash.Hang,
	},
	{
		includePrefix: []string{"INFO: task can't die in"},
		crashType:     crash.Hang,
	},
	{
		includePrefix: []string{"BUG: unable to handle kernel"},
		crashType:     crash.UnknownType,
	},
	{
		includePrefix: []string{"general protection fault in"},
		crashType:     crash.UnknownType,
	},
	{
		includePrefix: []string{"stack segment fault in"},
		crashType:     crash.UnknownType,
	},
	{
		includePrefix: []string{"kernel panic: "},
		crashType:     crash.UnknownType,
	},
	{
		includePrefix: []string{"kernel stack overflow"},
		crashType:     crash.UnknownType,
	},
	{
		includePrefix: []string{"PANIC: double fault"},
		crashType:     crash.UnknownType,
	},
	{
		includePrefix: []string{"rust_kernel panicked"},
		crashType:     crash.UnknownType,
	},
	{
		includePrefix: []string{"BUG: Object already free"},
		crashType:     crash.UnknownType,
	},
	{
		includePrefix: []string{"divide error in"},
		crashType:     crash.UnknownType,
	},
	{
		includePrefix: []string{"invalid opcode in"},
		crashType:     crash.UnknownType,
	},
	{
		includePrefix: []string{"unexpected kernel reboot"},
		crashType:     crash.UnexpectedReboot,
	},
	{
		includePrefix: []string{"unregister_netdevice: waiting for DEV to become free"},
		crashType:     crash.UnknownType,
	},
	{
		includePrefix: []string{"VFS: Close: file count is zero (use-after-free)"},
		crashType:     crash.UnknownType,
	},
	{
		includePrefix: []string{"VFS: Busy inodes after unmount (use-after-free)"},
		crashType:     crash.UnknownType,
	},
	{
		includePrefix: []string{"Internal error in"},
		crashType:     crash.UnknownType,
	},
	{
		includePrefix: []string{"Unhandled fault in"},
		crashType:     crash.UnknownType,
	},
	{
		includePrefix: []string{"Alignment trap in"},
		crashType:     crash.UnknownType,
	},
	{
		includePrefix: []string{"trusty:"},
		crashType:     crash.UnknownType,
	},
	{
		includePrefix: []string{"SYZFAIL"},
		crashType:     crash.SyzFailure,
	},
	{
		includePrefix: []string{"SYZFATAL:"},
		crashType:     crash.SyzFailure,
	},
	{
		includePrefix: []string{"panic:"},
		crashType:     crash.UnknownType,
	},
	{
		includePrefix: []string{"go runtime error"},
		crashType:     crash.UnknownType,
	},
	// DEFAULTS.
	{
		includePrefix: []string{"WARNING: "},
		crashType:     crash.Warning,
	},
	{
		includePrefix: []string{"BUG: "},
		crashType:     crash.UnknownType,
	},
	{
		includePrefix: []string{"INFO: "},
		crashType:     crash.UnknownType,
	},
	{
		includePrefix: []string{"KASAN: "},
		crashType:     crash.KASAN,
	},
	{
		includePrefix: []string{"KMSAN: "},
		crashType:     crash.KMSAN,
	},
	{
		includePrefix: []string{"UBSAN: "},
		crashType:     crash.UBSAN,
	},
}

func titleToCrashType(title string) crash.Type {
	for _, t := range titleToType {
		for _, prefix := range t.includePrefix {
			if strings.HasPrefix(title, prefix) {
				return t.crashType
			}
		}
	}
	return crash.UnknownType
}
