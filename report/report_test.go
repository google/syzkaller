// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"strings"
	"testing"
)

func TestFindCrash(t *testing.T) {
	tests := map[string]string{
		`
[   50.583499] something 
[   50.583499] BUG: unable to handle kernel paging request at 00000000ffffff8a
[   50.583499] IP: [<     inline     >] list_del include/linux/list.h:107 
`: "BUG: unable to handle kernel paging request at 00000000ffffff8a",
		`
[   50.583499] something
[   50.583499] INFO: rcu_sched self-detected stall on CPU
[   50.583499]         0: (20822 ticks this GP) idle=94b/140000000000001/0
`: "INFO: rcu_sched self-detected stall on CPU",
		`
[   50.583499] general protection fault: 0000 [#1] SMP KASAN
[   50.583499] Modules linked in: 
`: "general protection fault: 0000 [#1] SMP KASAN",
		`
[   50.583499] BUG: unable to handle kernel NULL pointer dereference at 000000000000003a
[   50.583499] Modules linked in: 
`: "BUG: unable to handle kernel NULL pointer dereference at 000000000000003a",
		`
[   50.583499] WARNING: CPU: 2 PID: 2636 at ipc/shm.c:162 shm_open+0x74/0x80()
[   50.583499] Modules linked in: 
`: "WARNING: CPU: 2 PID: 2636 at ipc/shm.c:162 shm_open+0x74/0x80()",
		`
[   50.583499] BUG: KASAN: use after free in remove_wait_queue+0xfb/0x120 at addr ffff88002db3cf50
[   50.583499] Write of size 8 by task syzkaller_execu/10568 
`: "BUG: KASAN: use after free in remove_wait_queue+0xfb/0x120 at addr ffff88002db3cf50",
		`
BUG UNIX (Not tainted): kasan: bad access detected
`: "",
		`
[   50.583499] [ INFO: possible circular locking dependency detected ]
[   50.583499] 4.3.0+ #30 Not tainted
`: "INFO: possible circular locking dependency detected ]",
		`
BUG: unable to handle kernel paging request at 00000000ffffff8a
IP: [<ffffffff810a376f>] __call_rcu.constprop.76+0x1f/0x280 kernel/rcu/tree.c:3046
`: "BUG: unable to handle kernel paging request at 00000000ffffff8a",
		`
==================================================================
BUG: KASAN: slab-out-of-bounds in memcpy+0x1d/0x40 at addr ffff88003a6bd110
Read of size 8 by task a.out/6260
`: "BUG: KASAN: slab-out-of-bounds in memcpy+0x1d/0x40 at addr ffff88003a6bd110",
		`
[   50.583499] unreferenced object 0xffff880039a55260 (size 64):
[   50.583499]   comm "executor", pid 11746, jiffies 4298984475 (age 16.078s)
`: "unreferenced object 0xffff880039a55260 (size 64):",
		`
[   50.583499] UBSAN: Undefined behaviour in kernel/time/hrtimer.c:310:16
[   50.583499] signed integer overflow:
`: "UBSAN: Undefined behaviour in kernel/time/hrtimer.c:310:16",
		`
------------[ cut here ]------------
kernel BUG at fs/buffer.c:1917!
invalid opcode: 0000 [#1] SMP
`: "kernel BUG at fs/buffer.c:1917!",
		`
BUG: sleeping function called from invalid context at include/linux/wait.h:1095 
in_atomic(): 1, irqs_disabled(): 0, pid: 3658, name: syz-fuzzer 
`: "BUG: sleeping function called from invalid context at include/linux/wait.h:1095 ",
		`
------------[ cut here ]------------
WARNING: CPU: 3 PID: 1975 at fs/locks.c:241
locks_free_lock_context+0x118/0x180()
`: "WARNING: CPU: 3 PID: 1975 at fs/locks.c:241",
	}
	for log, crash := range tests {
		if strings.Index(log, "\r\n") != -1 {
			continue
		}
		tests[strings.Replace(log, "\n", "\r\n", -1)] = crash
	}
	for log, crash := range tests {
		desc, _, _, found := FindCrash([]byte(log))
		//t.Logf("%v\nexpect '%v', found '%v'\n", log, crash, desc)
		if !found && crash != "" {
			t.Fatalf("did not find crash message '%v' in:\n%v", crash, log)
		}
		if found && crash == "" {
			t.Fatalf("found bogus crash message '%v' in:\n%v", desc, log)
		}
		if desc != crash {
			t.Fatalf("extracted bad crash message:\n%v\nwant:\n%v", desc, crash)
		}
	}
}
