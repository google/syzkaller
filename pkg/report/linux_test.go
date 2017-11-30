// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/google/syzkaller/pkg/symbolizer"
)

func TestLinuxParse(t *testing.T) {
	tests := []ParseTest{
		{
			`
[  772.918915] BUG: unable to handle kernel paging request at ffff88002bde1e40
unrelateed line
[  772.919010] IP: [<ffffffff82d4e304>] __memset+0x24/0x30
[  772.919010] PGD ae2c067 PUD ae2d067 PMD 7faa5067 PTE 800000002bde1060
[  772.919010] Oops: 0002 [#1] SMP DEBUG_PAGEALLOC KASAN
[  772.919010] Dumping ftrace buffer:
[  772.919010]    (ftrace buffer empty)
[  772.919010] Modules linked in:
[  772.919010] CPU: 1 PID: 4070 Comm: syz-executor Not tainted 4.8.0-rc3+ #33
[  772.919010] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS Bochs 01/01/2011
[  772.919010] task: ffff880066be2280 task.stack: ffff880066be8000
[  772.919010] RIP: 0010:[<ffffffff82d4e304>]  [<ffffffff82d4e304>] __memset+0x24/0x30
[  772.919010] RSP: 0018:ffff880066befc88  EFLAGS: 00010006
`, `BUG: unable to handle kernel paging request in __memset`, true,
		}, {
			`
[ 1019.110825] BUG: unable to handle kernel paging request at 000000010000001a
[ 1019.112065] IP: skb_release_data+0x258/0x470
`, `BUG: unable to handle kernel paging request in skb_release_data`, true,
		}, {
			`
[ 1019.110825] BUG: unable to handle kernel paging request at 00000000ffffff8a
[ 1019.110825] IP: [<ffffffff810a376f>] __call_rcu.constprop.76+0x1f/0x280 kernel/rcu/tree.c:3046
`, `BUG: unable to handle kernel paging request in __call_rcu`, true,
		}, {
			`
[ 1581.999813] BUG: unable to handle kernel paging request at ffffea0000f0e440
[ 1581.999824] IP: [<ffffea0000f0e440>] 0xffffea0000f0e440
`, `BUG: unable to handle kernel paging request`, true,
		}, {
			`
[ 1021.362826] kasan: CONFIG_KASAN_INLINE enabled
[ 1021.363613] kasan: GPF could be caused by NULL-ptr deref or user memory access
[ 1021.364461] general protection fault: 0000 [#1] SMP DEBUG_PAGEALLOC KASAN
[ 1021.365202] Dumping ftrace buffer:
[ 1021.365408]    (ftrace buffer empty)
[ 1021.366951] Modules linked in:
[ 1021.366951] CPU: 2 PID: 29350 Comm: syz-executor Not tainted 4.8.0-rc3+ #33
[ 1021.366951] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS Bochs 01/01/2011
[ 1021.366951] task: ffff88005b4347c0 task.stack: ffff8800634c0000
[ 1021.366951] RIP: 0010:[<ffffffff83408ca0>]  [<ffffffff83408ca0>] drm_legacy_newctx+0x190/0x290
[ 1021.366951] RSP: 0018:ffff8800634c7c50  EFLAGS: 00010246
[ 1021.366951] RAX: dffffc0000000000 RBX: ffff880068f28840 RCX: ffffc900021d0000
[ 1021.372626] RDX: 0000000000000000 RSI: ffff8800634c7cf8 RDI: ffff880064c0b600
[ 1021.374099] RBP: ffff8800634c7c70 R08: 0000000000000000 R09: 0000000000000000
[ 1021.374099] R10: 0000000000000000 R11: 0000000000000000 R12: 0000000000000000
[ 1021.375281] R13: ffff880067aa6000 R14: 0000000000000000 R15: 0000000000000000
`, `general protection fault in drm_legacy_newctx`, true,
		}, {
			`
[ 1722.509639] kasan: GPF could be caused by NULL-ptr deref or user memory access
[ 1722.510515] general protection fault: 0000 [#1] SMP DEBUG_PAGEALLOC KASAN
[ 1722.511227] Dumping ftrace buffer:
[ 1722.511384]    (ftrace buffer empty)
[ 1722.511384] Modules linked in:
[ 1722.511384] CPU: 3 PID: 6856 Comm: syz-executor Not tainted 4.8.0-rc3-next-20160825+ #8
[ 1722.511384] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS Bochs 01/01/2011
[ 1722.511384] task: ffff88005ea761c0 task.stack: ffff880050628000
[ 1722.511384] RIP: 0010:[<ffffffff8213c531>]  [<ffffffff8213c531>] logfs_init_inode.isra.6+0x111/0x470
[ 1722.511384] RSP: 0018:ffff88005062fb48  EFLAGS: 00010206
`, `general protection fault in logfs_init_inode`, true,
		}, {
			`
[ 1722.511384] general protection fault: 0000 [#1] SMP KASAN
[ 1722.511384] Dumping ftrace buffer:
[ 1722.511384]    (ftrace buffer empty)
[ 1722.511384] Modules linked in:
[ 1722.511384] CPU: 0 PID: 27388 Comm: syz-executor5 Not tainted 4.10.0-rc6+ #117
[ 1722.511384] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS Bochs 01/01/2011
[ 1722.511384] task: ffff88006252db40 task.stack: ffff880062090000
[ 1722.511384] RIP: 0010:__ip_options_echo+0x120a/0x1770
[ 1722.511384] RSP: 0018:ffff880062097530 EFLAGS: 00010206
[ 1722.511384] RAX: dffffc0000000000 RBX: ffff880062097910 RCX: 0000000000000000
[ 1722.511384] RDX: 0000000000000003 RSI: ffffffff83988dca RDI: 0000000000000018
[ 1722.511384] RBP: ffff8800620976a0 R08: ffff88006209791c R09: ffffed000c412f26
[ 1722.511384] R10: 0000000000000004 R11: ffffed000c412f25 R12: ffff880062097900
[ 1722.511384] R13: ffff88003a8c0a6c R14: 1ffff1000c412eb3 R15: 000000000000000d
[ 1722.511384] FS:  00007fd61b443700(0000) GS:ffff88003ec00000(0000) knlGS:0000000000000000
[ 1722.511384] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[ 1722.511384] CR2: 000000002095f000 CR3: 0000000062876000 CR4: 00000000000006f0
`, `general protection fault in __ip_options_echo`, true,
		}, {
			`
[ 1722.511384] ==================================================================
[ 1722.511384] BUG: KASAN: slab-out-of-bounds in memcpy+0x1d/0x40 at addr ffff88003a6bd110
[ 1722.511384] Read of size 8 by task a.out/6260
[ 1722.511384] BUG: KASAN: slab-out-of-bounds in memcpy+0x1d/0x40 at addr ffff88003a6bd110
[ 1722.511384] Write of size 4 by task a.out/6260
`, `KASAN: slab-out-of-bounds Read in memcpy`, true,
		}, {
			`
[   50.583499] BUG: KASAN: use-after-free in remove_wait_queue+0xfb/0x120 at addr ffff88002db3cf50
[   50.583499] Write of size 8 by task syzkaller_execu/10568 
`, `KASAN: use-after-free Write in remove_wait_queue`, true,
		}, {
			`
[  380.688570] BUG: KASAN: use-after-free in copy_from_iter+0xf30/0x15e0 at addr ffff880033f4b02a
[  380.688570] Read of size 4059 by task syz-executor/29957
`, `KASAN: use-after-free Read in copy_from_iter`, true,
		}, {
			`
[23818.431954] BUG: KASAN: null-ptr-deref on address           (null)

[23818.438140] Read of size 4 by task syz-executor/22534

[23818.443211] CPU: 3 PID: 22534 Comm: syz-executor Tainted: G     U         3.18.0 #78
`, `KASAN: null-ptr-deref Read`, true,
		}, {
			`
[ 1722.511384] ==================================================================
[ 1722.511384] BUG: KASAN: wild-memory-access on address ffe7087450a17000
[ 1722.511384] Read of size 205 by task syz-executor1/9018
`, `KASAN: wild-memory-access Read`, true,
		}, {
			`
[  149.188010] BUG: unable to handle kernel NULL pointer dereference at 000000000000058c
unrelateed line
[  149.188010] IP: [<ffffffff8148e81d>] __lock_acquire+0x2bd/0x3410
`, `BUG: unable to handle kernel NULL pointer dereference in __lock_acquire`, true,
		}, {
			`
[   55.112844] BUG: unable to handle kernel NULL pointer dereference at 000000000000001a
[   55.113569] IP: skb_release_data+0x258/0x470
`, `BUG: unable to handle kernel NULL pointer dereference in skb_release_data`, true,
		}, {
			`
[   50.583499] WARNING: CPU: 2 PID: 2636 at ipc/shm.c:162 shm_open.isra.5.part.6+0x74/0x80
[   50.583499] Modules linked in: 
`, `WARNING in shm_open`, true,
		}, {
			`
[  753.120788] WARNING: CPU: 0 PID: 0 at net/sched/sch_generic.c:316 dev_watchdog+0x648/0x770
[  753.122260] NETDEV WATCHDOG: eth0 (e1000): transmit queue 0 timed out
`, `WARNING in dev_watchdog`, true,
		}, {
			`
[ 1722.511384] ------------[ cut here ]------------
[ 1722.511384] WARNING: CPU: 3 PID: 1975 at fs/locks.c:241 locks_free_lock_context+0x118/0x180()
`, `WARNING in locks_free_lock_context`, true,
		}, {
			`
[ 1722.511384] WARNING: CPU: 3 PID: 23810 at /linux-src-3.18/net/netlink/genetlink.c:1037 genl_unbind+0x110/0x130()
`, `WARNING in genl_unbind`, true,
		}, {
			`
[  127.525803] ======================================================
[  127.532093] WARNING: possible circular locking dependency detected
[  127.538376] 4.14.0-rc1+ #1 Not tainted
[  127.542228] ------------------------------------------------------
[  127.548509] syz-executor0/22269 is trying to acquire lock:
[  127.554094]  (&bdev->bd_mutex){+.+.}, at: [<ffffffff8232bf0e>] blkdev_reread_part+0x1e/0x40
[  127.562560] 
[  127.562560] but task is already holding lock:
[  127.568495]  (&lo->lo_ctl_mutex#2){+.+.}, at: [<ffffffff83542c29>] lo_compat_ioctl+0x109/0x140
[  127.577221] 
[  127.577221] which lock already depends on the new lock.
[  127.577221] 
[  127.585502] 
[  127.585502] the existing dependency chain (in reverse order) is:
[  127.593087] 
[  127.593087] -> #1 (&lo->lo_ctl_mutex#2){+.+.}:
[  127.599124]        __lock_acquire+0x328f/0x4620
[  127.603759]        lock_acquire+0x1d5/0x580
[  127.608048]        __mutex_lock+0x16f/0x1870
[  127.612421]        mutex_lock_nested+0x16/0x20
[  127.616972]        lo_release+0x6b/0x180
[  127.621000]        __blkdev_put+0x602/0x7c0
[  127.625288]        blkdev_put+0x85/0x4f0
[  127.629314]        blkdev_close+0x91/0xc0
[  127.633425]        __fput+0x333/0x7f0
[  127.637192]        ____fput+0x15/0x20
[  127.640960]        task_work_run+0x199/0x270
[  127.645333]        exit_to_usermode_loop+0x2a6/0x300
[  127.650404]        syscall_return_slowpath+0x42f/0x500
[  127.655651]        entry_SYSCALL_64_fastpath+0xbc/0xbe
[  127.660888] 
[  127.660888] -> #0 (&bdev->bd_mutex){+.+.}:
[  127.666578]        check_prev_add+0x865/0x1520
[  127.671134]        __lock_acquire+0x328f/0x4620
[  127.675778]        lock_acquire+0x1d5/0x580
[  127.680067]        __mutex_lock+0x16f/0x1870
[  127.684441]        mutex_lock_nested+0x16/0x20
[  127.688991]        blkdev_reread_part+0x1e/0x40
[  127.693629]        loop_reread_partitions+0x12f/0x1a0
[  127.698783]        loop_set_status+0x9ba/0xf60
[  127.703333]        loop_set_status_compat+0x92/0xf0
[  127.708315]        lo_compat_ioctl+0x114/0x140
[  127.712863]        compat_blkdev_ioctl+0x3ba/0x1850
[  127.717848]        compat_SyS_ioctl+0x1da/0x3300
[  127.722570]        do_fast_syscall_32+0x3f2/0xeed
[  127.727378]        entry_SYSENTER_compat+0x51/0x60
[  127.732268] 
[  127.732268] other info that might help us debug this:
[  127.732268] 
[  127.740375]  Possible unsafe locking scenario:
[  127.740375] 
[  127.746396]        CPU0                    CPU1
[  127.751028]        ----                    ----
[  127.755664]   lock(&lo->lo_ctl_mutex#2);
[  127.759694]                                lock(&bdev->bd_mutex);
[  127.765892]                                lock(&lo->lo_ctl_mutex#2);
[  127.772438]   lock(&bdev->bd_mutex);
[  127.776120] 
[  127.776120]  *** DEADLOCK ***
[  127.776120] 
[  127.782144] 1 lock held by syz-executor0/22269:
[  127.786775]  #0:  (&lo->lo_ctl_mutex#2){+.+.}, at: [<ffffffff83542c29>] lo_compat_ioctl+0x109/0x140
[  127.795934] 
[  127.795934] stack backtrace:
[  127.800405] CPU: 0 PID: 22269 Comm: syz-executor0 Not tainted 4.14.0-rc1+ #1
[  127.807556] Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011
[  127.816876] Call Trace:
[  127.819433]  dump_stack+0x194/0x257
[  127.831436]  print_circular_bug+0x503/0x710
[  127.844570]  check_prev_add+0x865/0x1520
[  127.961665]  lock_acquire+0x1d5/0x580
...
[  128.182847]  entry_SYSENTER_compat+0x51/0x60
[  128.187221] RIP: 0023:0xf7fd5c79
[  128.190551] RSP: 002b:00000000f77d105c EFLAGS: 00000296 ORIG_RAX: 0000000000000036
[  128.198227] RAX: ffffffffffffffda RBX: 0000000000000016 RCX: 0000000000004c02
[  128.205464] RDX: 00000000202e3000 RSI: 0000000000000000 RDI: 0000000000000000
[  128.212700] RBP: 0000000000000000 R08: 0000000000000000 R09: 0000000000000000
[  128.219935] R10: 0000000000000000 R11: 0000000000000000 R12: 0000000000000000
`, `possible deadlock in blkdev_reread_part`, false,
		}, {
			`
[ 1722.511384] =======================================================
[ 1722.511384] [ INFO: possible circular locking dependency detected ]
[ 1722.511384] 2.6.32-rc6-00035-g8b17a4f #1
[ 1722.511384] -------------------------------------------------------
[ 1722.511384] kacpi_hotplug/246 is trying to acquire lock:
[ 1722.511384]  (kacpid){+.+.+.}, at: [<ffffffff8105bbd0>] flush_workqueue+0x0/0xb0
`, `possible deadlock in flush_workqueue`, true,
		}, {
			`
[ 1722.511384] WARNING: possible circular locking dependency detected
[ 1722.511384] 4.12.0-rc2-next-20170525+ #1 Not tainted
[ 1722.511384] ------------------------------------------------------
[ 1722.511384] kworker/u4:2/54 is trying to acquire lock:
[ 1722.511384]  (&buf->lock){+.+...}, at: [<ffffffff9edb41bb>] tty_buffer_flush+0xbb/0x3a0 drivers/tty/tty_buffer.c:221
[ 1722.511384] 
[ 1722.511384] but task is already holding lock:
[ 1722.511384]  (&o_tty->termios_rwsem/1){++++..}, at: [<ffffffff9eda4961>] isig+0xa1/0x4d0 drivers/tty/n_tty.c:1100
[ 1722.511384] 
[ 1722.511384] which lock already depends on the new lock.
`, `possible deadlock in tty_buffer_flush`, true,
		}, {
			`
[   44.025025] =========================================================
[   44.025025] [ INFO: possible irq lock inversion dependency detected ]
[   44.025025] 4.10.0-rc8+ #228 Not tainted
[   44.025025] ---------------------------------------------------------
[   44.025025] syz-executor6/1577 just changed the state of lock:
[   44.025025]  (&(&r->consumer_lock)->rlock){+.+...}, at: [<ffffffff82de6c86>] tun_queue_purge+0xe6/0x210
`, `possible deadlock in tun_queue_purge`, true,
		}, {
			`
[  121.451623] ======================================================
[  121.452013] [ INFO: SOFTIRQ-safe -> SOFTIRQ-unsafe lock order detected ]
[  121.452013] 4.10.0-rc8+ #228 Not tainted
[  121.453507] ------------------------------------------------------
[  121.453507] syz-executor1/19557 [HC0[0]:SC0[0]:HE0:SE1] is trying to acquire:
[  121.453507]  (&(&r->consumer_lock)->rlock){+.+...}, at: [<ffffffff82df4347>] tun_device_event+0x897/0xc70
`, `possible deadlock in tun_device_event`, true,
		}, {
			`
[   48.981019] =============================================
[   48.981019] [ INFO: possible recursive locking detected ]
[   48.981019] 4.11.0-rc4+ #198 Not tainted
[   48.981019] ---------------------------------------------
[   48.981019] kauditd/901 is trying to acquire lock:
[   48.981019]  (audit_cmd_mutex){+.+.+.}, at: [<ffffffff81585f59>] audit_receive+0x79/0x360
`, `possible deadlock in audit_receive`, true,
		}, {
			`
[  131.449768] ======================================================
[  131.449777] [ INFO: possible circular locking dependency detected ]
[  131.449789] 3.10.37+ #1 Not tainted
[  131.449797] -------------------------------------------------------
[  131.449807] swapper/2/0 is trying to acquire lock:
[  131.449859]  (&port_lock_key){-.-...}, at: [<c036a6dc>]     serial8250_console_write+0x108/0x134
[  131.449866] 
`, `possible deadlock in serial8250_console_write`, true,
		}, {
			`
[   52.261501] =================================
[   52.261501] [ INFO: inconsistent lock state ]
[   52.261501] 4.10.0+ #60 Not tainted
[   52.261501] ---------------------------------
[   52.261501] inconsistent {IN-SOFTIRQ-W} -> {SOFTIRQ-ON-W} usage.
[   52.261501] syz-executor3/5076 [HC0[0]:SC0[0]:HE1:SE1] takes:
[   52.261501]  (&(&hashinfo->ehash_locks[i])->rlock){+.?...}, at: [<ffffffff83a6a370>] inet_ehash_insert+0x240/0xad0
`, `inconsistent lock state in inet_ehash_insert`, true,
		}, {
			`
[ 1722.511384] [ INFO: suspicious RCU usage. ]
[ 1722.511384] 4.3.5-smp-DEV #101 Not tainted
[ 1722.511384] -------------------------------
[ 1722.511384] net/core/filter.c:1917 suspicious rcu_dereference_protected() usage!
[ 1722.511384] other info that might help us debug this:
`, `suspicious RCU usage at net/core/filter.c:LINE`, true,
		}, {
			`
[   37.540474] ===============================
[   37.540478] [ INFO: suspicious RCU usage. ]
[   37.540495] 4.9.0-rc4+ #47 Not tainted
2016/11/12 06:52:29 executing program 1:
r0 = ioctl$KVM_CREATE_VM(0xffffffffffffffff, 0xae01, 0x0)
[   37.540522] -------------------------------
[   37.540535] ./include/linux/kvm_host.h:536 suspicious rcu_dereference_check() usage!
[   37.540539] 
[   37.540539] other info that might help us debug this:
[   37.540539] 
[   37.540548] 
[   37.540548] rcu_scheduler_active = 1, debug_locks = 0
[   37.540557] 1 lock held by syz-executor/3985:
[   37.540566]  #0: 
[   37.540571]  (
[   37.540576] &vcpu->mutex
[   37.540580] ){+.+.+.}
[   37.540609] , at: 
[   37.540610] [<ffffffff81055862>] vcpu_load+0x22/0x70
`, `suspicious RCU usage at ./include/linux/kvm_host.h:LINE`, true,
		}, {
			`
[   80.586804] =====================================
[  734.270366] [ BUG: syz-executor/31761 still has locks held! ]
[  734.307462] 4.8.0+ #30 Not tainted
[  734.325126] -------------------------------------
[  734.417271] 1 lock held by syz-executor/31761:
[  734.442178]  #0:  (&pipe->mutex/1){+.+.+.}, at: [<ffffffff81844c6b>] pipe_lock+0x5b/0x70
[  734.451474] 
[  734.451474] stack backtrace:
[  734.521109] CPU: 0 PID: 31761 Comm: syz-executor Not tainted 4.8.0+ #30
[  734.527900] Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011
[  734.537256]  ffff8800458dfa38 ffffffff82d383a9 ffffffff00000000 fffffbfff1097248
[  734.545358]  ffff88005639a700 ffff88005639a700 dffffc0000000000 ffff88005639a700
[  734.553482]  ffff8800530148f8 ffff8800458dfa58 ffffffff81463cb5 0000000000000000
[  734.562654] Call Trace:
[  734.565257]  [<ffffffff82d383a9>] dump_stack+0x12e/0x185
[  734.570819]  [<ffffffff81463cb5>] debug_check_no_locks_held+0x125/0x140
[  734.577590]  [<ffffffff860bae47>] unix_stream_read_generic+0x1317/0x1b70
[  734.584440]  [<ffffffff860b9b30>] ? unix_getname+0x290/0x290
[  734.590238]  [<ffffffff8146870b>] ? __lock_acquire+0x7fb/0x3410
[  734.596306]  [<ffffffff81467f10>] ? debug_check_no_locks_freed+0x3c0/0x3c0
[  734.603322]  [<ffffffff81905282>] ? fsnotify+0xca2/0x1020
[  734.608874]  [<ffffffff81467f10>] ? debug_check_no_locks_freed+0x3c0/0x3c0
[  734.615894]  [<ffffffff814475b0>] ? prepare_to_wait_event+0x450/0x450
[  734.622486]  [<ffffffff860bb7fb>] unix_stream_splice_read+0x15b/0x1d0
[  734.629066]  [<ffffffff860bb6a0>] ? unix_stream_read_generic+0x1b70/0x1b70
[  734.636086]  [<ffffffff82b27c3a>] ? common_file_perm+0x15a/0x3a0
[  734.642242]  [<ffffffff860b52f0>] ? unix_accept+0x460/0x460
[  734.647963]  [<ffffffff82a5c02e>] ? security_file_permission+0x8e/0x1e0
[  734.654729]  [<ffffffff860bb6a0>] ? unix_stream_read_generic+0x1b70/0x1b70
[  734.661754]  [<ffffffff85afc54e>] sock_splice_read+0xbe/0x100
[  734.667649]  [<ffffffff85afc490>] ? kernel_sock_shutdown+0x80/0x80
[  734.673973]  [<ffffffff818d11ff>] do_splice_to+0x10f/0x170
[  734.679697]  [<ffffffff818d6acc>] SyS_splice+0x114c/0x15b0
[  734.685329]  [<ffffffff81506bf4>] ? SyS_futex+0x144/0x2e0
[  734.690961]  [<ffffffff818d5980>] ? compat_SyS_vmsplice+0x250/0x250
[  734.697375]  [<ffffffff8146750c>] ? trace_hardirqs_on_caller+0x44c/0x5e0
[  734.704230]  [<ffffffff8100501a>] ? trace_hardirqs_on_thunk+0x1a/0x1c
[  734.710821]  [<ffffffff86da6d05>] entry_SYSCALL_64_fastpath+0x23/0xc6
[  734.717436]  [<ffffffff816939e7>] ? perf_event_mmap+0x77/0xb20
`, `BUG: still has locks held in pipe_lock`, false,
		}, {
			`
[ 1722.511384] =====================================
[ 1722.511384] [ BUG: bad unlock balance detected! ]
[ 1722.511384] 4.10.0+ #179 Not tainted
[ 1722.511384] -------------------------------------
[ 1722.511384] syz-executor1/21439 is trying to release lock (sk_lock-AF_INET) at:
[ 1722.511384] [<ffffffff83f7ac8b>] sctp_sendmsg+0x2a3b/0x38a0 net/sctp/socket.c:2007
`, `BUG: bad unlock balance in sctp_sendmsg`, true,
		}, {
			`
[  633.049984] =========================
[  633.049987] [ BUG: held lock freed! ]
[  633.049993] 4.10.0+ #260 Not tainted
[  633.049996] -------------------------
[  633.050005] syz-executor7/27251 is freeing memory ffff8800178f8180-ffff8800178f8a77, with a lock still held there!
[  633.050009]  (slock-AF_INET6){+.-...}, at: [<ffffffff835f22c9>] sk_clone_lock+0x3d9/0x12c0
`, `BUG: held lock freed in sk_clone_lock`, true,
		}, {
			`
[ 2569.618120] BUG: Bad rss-counter state mm:ffff88005fac4300 idx:0 val:15
`, `BUG: Bad rss-counter state`, false,
		}, {
			`
[    4.556968] ================================================================================
[    4.556972] UBSAN: Undefined behaviour in drivers/usb/core/devio.c:1517:25
[    4.556975] shift exponent -1 is negative
[    4.556979] CPU: 2 PID: 3624 Comm: usb Not tainted 4.5.0-rc1 #252
[    4.556981] Hardware name: Apple Inc. MacBookPro10,2/Mac-AFD8A9D944EA4843, BIOS MBP102.88Z.0106.B0A.1509130955 09/13/2015
[    4.556984]  0000000000000000 0000000000000000 ffffffff845c6528 ffff8802493b3c68
[    4.556988]  ffffffff81b2e7d9 0000000000000007 ffff8802493b3c98 ffff8802493b3c80
[    4.556992]  ffffffff81bcb87d ffffffffffffffff ffff8802493b3d10 ffffffff81bcc1c1
[    4.556996] Call Trace:
[    4.557004]  [<ffffffff81b2e7d9>] dump_stack+0x45/0x6c
[    4.557010]  [<ffffffff81bcb87d>] ubsan_epilogue+0xd/0x40
[    4.557015]  [<ffffffff81bcc1c1>] __ubsan_handle_shift_out_of_bounds+0xf1/0x140
[    4.557030]  [<ffffffff822247af>] ? proc_do_submiturb+0x9af/0x2c30
[    4.557034]  [<ffffffff82226794>] proc_do_submiturb+0x2994/0x2c30
`, `UBSAN: Undefined behaviour in drivers/usb/core/devio.c:LINE`, false,
		}, {
			`
[    3.805449] ================================================================================
[    3.805453] UBSAN: Undefined behaviour in ./arch/x86/include/asm/atomic.h:156:2
[    3.805455] signed integer overflow:
[    3.805456] -1720106381 + -1531247276 cannot be represented in type 'int'
[    3.805460] CPU: 3 PID: 3235 Comm: cups-browsed Not tainted 4.5.0-rc1 #252
[    3.805461] Hardware name: Apple Inc. MacBookPro10,2/Mac-AFD8A9D944EA4843, BIOS MBP102.88Z.0106.B0A.1509130955 09/13/2015
[    3.805465]  0000000000000000 0000000000000000 ffffffffa4bb0554 ffff88025f2c37c8
[    3.805468]  ffffffff81b2e7d9 0000000000000001 ffff88025f2c37f8 ffff88025f2c37e0
[    3.805470]  ffffffff81bcb87d ffffffff84b16a74 ffff88025f2c3868 ffffffff81bcbc4d
[    3.805471] Call Trace:
[    3.805478]  <IRQ>  [<ffffffff81b2e7d9>] dump_stack+0x45/0x6c
[    3.805483]  [<ffffffff81bcb87d>] ubsan_epilogue+0xd/0x40
[    3.805485]  [<ffffffff81bcbc4d>] handle_overflow+0xbd/0xe0
[    3.805490]  [<ffffffff82b3409f>] ? csum_partial_copy_nocheck+0xf/0x20
[    3.805493]  [<ffffffff81d635df>] ? get_random_bytes+0x4f/0x100
[    3.805496]  [<ffffffff81bcbc7e>] __ubsan_handle_add_overflow+0xe/0x10
[    3.805500]  [<ffffffff82680a4a>] ip_idents_reserve+0x9a/0xd0
[    3.805503]  [<ffffffff826835e9>] __ip_select_ident+0xc9/0x160
`, `UBSAN: Undefined behaviour in ./arch/x86/include/asm/atomic.h:LINE`, false,
		}, {
			`
[   50.583499] UBSAN: Undefined behaviour in kernel/time/hrtimer.c:310:16
[   50.583499] signed integer overflow:
`, `UBSAN: Undefined behaviour in kernel/time/hrtimer.c:LINE`, true,
		}, {
			`
[ 1722.511384] ------------[ cut here ]------------
[ 1722.511384] kernel BUG at fs/buffer.c:1917!
[ 1722.511384] invalid opcode: 0000 [#1] SMP
[ 1722.511384] `, `kernel BUG at fs/buffer.c:LINE!`, true,
		}, {
			`
[   34.517718] ------------[ cut here ]------------
[   34.522456] kernel BUG at arch/x86/kvm/mmu.c:1284!
[   34.527367] invalid opcode: 0000 [#1] SMP KASAN
[   34.532361] Modules linked in:
[   34.535649] CPU: 0 PID: 3918 Comm: syz-executor5 Not tainted 4.3.5+ #6
[   34.542290] Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011
[   34.551627] task: ffff8800b3d1c580 ti: ffff8800b2c44000 task.ti: ffff8800b2c44000
[   34.559224] RIP: 0010:[<ffffffff810d9c93>]  [<ffffffff810d9c93>] pte_list_remove+0x3b3/0x3d0
[   34.567915] RSP: 0018:ffff8800b2c476c0  EFLAGS: 00010286
[   34.573342] RAX: 0000000000000028 RBX: ffff8800bce83080 RCX: 0000000000000000
[   34.580594] RDX: 0000000000000028 RSI: ffff8801db415fe8 RDI: ffffed0016588ecc
[   34.587876] RBP: ffff8800b2c47700 R08: 0000000000000001 R09: 0000000000000000
[   34.595125] R10: 0000000000000003 R11: 0000000000000001 R12: ffff8800b3efd028
[   34.602380] R13: 0000000000000000 R14: ffff8800b3c165b0 R15: ffff8800b3c165d8
[   34.609634] FS:  0000000000000000(0000) GS:ffff8801db400000(0000) knlGS:0000000000000000
[   34.617841] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[   34.623698] CR2: 00000000004c4b90 CR3: 00000001ce6eb000 CR4: 00000000001426f0
[   34.630951] Stack:
[   34.633064]  ffff8800bce83080 ffffffff00000012 ffff8800b3efd028 0000000000000005
[   34.641057]  ffff8800b3efd028 ffff8801d7ca0240 ffff8800b3c165b0 ffff8800b3c165d8
[   34.649045]  ffff8800b2c47740 ffffffff810ec8b2 0000000000000246 00000001c8d4cc77
[   34.657038] Call Trace:
[   34.659617]  [<ffffffff810ec8b2>] drop_spte+0x162/0x260
[   34.664960]  [<ffffffff810f46e2>] mmu_page_zap_pte+0x1d2/0x310
`, `kernel BUG at arch/x86/kvm/mmu.c:LINE!`, false,
		}, {
			`
[  167.347989] Disabling lock debugging due to kernel taint
[  167.353311] Unable to handle kernel paging request at virtual address dead000000000108
[  167.361225] pgd = ffffffc0a39a0000
[  167.364630] [dead000000000108] *pgd=0000000000000000, *pud=0000000000000000
[  167.371618] Internal error: Oops: 96000044 [#1] PREEMPT SMP
[  167.377205] CPU: 2 PID: 12170 Comm: syz-executor Tainted: G    BU         3.18.0 #78
[  167.384944] Hardware name: Google Tegra210 Smaug Rev 1,3+ (DT)
[  167.390780] task: ffffffc016e04e80 ti: ffffffc016110000 task.ti: ffffffc016110000
[  167.398267] PC is at _snd_timer_stop.constprop.9+0x184/0x2b0
[  167.403931] LR is at _snd_timer_stop.constprop.9+0x184/0x2b0
[  167.409593] pc : [<ffffffc000d394c4>] lr : [<ffffffc000d394c4>] pstate: 200001c5
[  167.416985] sp : ffffffc016113990
`, `unable to handle kernel paging request in _snd_timer_stop`, true,
		}, {
			`
[ 1722.511384] Unable to handle kernel paging request at virtual address 0c0c9ca0
[ 1722.511384] pgd = c0004000
[ 1722.511384] [0c0c9ca0] *pgd=00000000
[ 1722.511384] Internal error: Oops: 5 [#1] PREEMPT
[ 1722.511384] last sysfs file: /sys/devices/virtual/irqk/irqk/dev
[ 1722.511384] Modules linked in: cmemk dm365mmap edmak irqk
[ 1722.511384] CPU: 0    Not tainted  (2.6.32-17-ridgerun #22)
[ 1722.511384] PC is at blk_rq_map_sg+0x70/0x2c0
[ 1722.511384] LR is at mmc_queue_map_sg+0x2c/0xa4
[ 1722.511384] pc : [<c01751ac>]    lr : [<c025a42c>]    psr: 80000013
[ 1722.511384] sp : c23e1db0  ip : c3cf8848  fp : c23e1df4
`, `unable to handle kernel paging request in blk_rq_map_sg`, true,
		}, {
			`
[ 2713.133889] Kernel panic - not syncing: Attempted to kill init! exitcode=0x00000013
[ 2713.133889] 
[ 2713.136293] CPU: 2 PID: 1 Comm: init.sh Not tainted 4.8.0-rc3+ #35
[ 2713.138395] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS Bochs 01/01/2011
[ 2713.138395]  ffffffff884b8280 ffff88003e1f79b8 ffffffff82d1b1d9 ffffffff00000001
[ 2713.138395]  fffffbfff1097050 ffffffff86e90b20 ffff88003e1f7a90 dffffc0000000000
[ 2713.138395]  dffffc0000000000 ffff88006cc97af0 ffff88003e1f7a80 ffffffff816ab4e3
[ 2713.153531] Call Trace:
[ 2713.153531]  [<ffffffff82d1b1d9>] dump_stack+0x12e/0x185
[ 2713.153531]  [<ffffffff816ab4e3>] panic+0x1e4/0x3ef
[ 2713.153531]  [<ffffffff816ab2ff>] ? set_ti_thread_flag+0x1e/0x1e
[ 2713.153531]  [<ffffffff8138e51e>] ? do_exit+0x8ce/0x2c10
[ 2713.153531]  [<ffffffff86c24cc7>] ? _raw_write_unlock_irq+0x27/0x70
[ 2713.153531]  [<ffffffff8139012f>] do_exit+0x24df/0x2c10
[ 2713.153531]  [<ffffffff8138dc50>] ? mm_update_next_owner+0x640/0x640
`, `kernel panic: Attempted to kill init!`, false,
		}, {
			`
[  616.344091] Kernel panic - not syncing: Fatal exception in interrupt
`, `kernel panic: Fatal exception`, true,
		}, {
			`
[  616.309156] divide error: 0000 [#1] SMP DEBUG_PAGEALLOC KASAN
[  616.310026] Dumping ftrace buffer:
[  616.310085]    (ftrace buffer empty)
[  616.310085] Modules linked in:
[  616.310085] CPU: 1 PID: 22257 Comm: syz-executor Not tainted 4.8.0-rc3+ #35
[  616.310085] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS Bochs 01/01/2011
[  616.312546] task: ffff88002fe9e580 task.stack: ffff8800316a8000
[  616.312546] RIP: 0010:[<ffffffff8575b41c>]  [<ffffffff8575b41c>] snd_hrtimer_callback+0x1bc/0x3c0
[  616.312546] RSP: 0018:ffff88003ed07d98  EFLAGS: 00010006
`, `divide error in snd_hrtimer_callback`, true,
		}, {
			`
[ 1722.511384] divide error: 0000 [#1] SMP KASAN
[ 1722.511384] Dumping ftrace buffer:
[ 1722.511384]    (ftrace buffer empty)
[ 1722.511384] Modules linked in:
[ 1722.511384] CPU: 2 PID: 5664 Comm: syz-executor5 Not tainted 4.10.0-rc6+ #122
[ 1722.511384] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS Bochs 01/01/2011
[ 1722.511384] task: ffff88003a46adc0 task.stack: ffff880036a00000
[ 1722.511384] RIP: 0010:__tcp_select_window+0x6db/0x920
[ 1722.511384] RSP: 0018:ffff880036a07638 EFLAGS: 00010212
[ 1722.511384] RAX: 0000000000000480 RBX: ffff880036a077d0 RCX: ffffc900030db000
[ 1722.511384] RDX: 0000000000000000 RSI: 0000000000000000 RDI: ffff88003809c3b5
[ 1722.511384] RBP: ffff880036a077f8 R08: ffff880039de5dc0 R09: 0000000000000000
[ 1722.511384] R10: 0000000000000000 R11: 0000000000000000 R12: 0000000000000480
[ 1722.511384] R13: 0000000000000000 R14: ffff88003809bb00 R15: 0000000000000000
[ 1722.511384] FS:  00007f35ecf32700(0000) GS:ffff88006de00000(0000) knlGS:0000000000000000
[ 1722.511384] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[ 1722.511384] CR2: 00000000205fb000 CR3: 0000000032467000 CR4: 00000000000006e0
`, `divide error in __tcp_select_window`, true,
		}, {
			`
[ 1722.511384] unreferenced object 0xffff880039a55260 (size 64): 
[ 1722.511384]   comm "executor", pid 11746, jiffies 4298984475 (age 16.078s) 
[ 1722.511384]   hex dump (first 32 bytes): 
[ 1722.511384]     2f 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  /............... 
[ 1722.511384]     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................ 
[ 1722.511384]   backtrace: 
[ 1722.511384]     [<ffffffff848a2f5f>] sock_kmalloc+0x7f/0xc0 net/core/sock.c:1774 
[ 1722.511384]     [<ffffffff84e5bea0>] do_ipv6_setsockopt.isra.7+0x15d0/0x2830 net/ipv6/ipv6_sockglue.c:483 
[ 1722.511384]     [<ffffffff84e5d19b>] ipv6_setsockopt+0x9b/0x140 net/ipv6/ipv6_sockglue.c:885 
[ 1722.511384]     [<ffffffff8544616c>] sctp_setsockopt+0x15c/0x36c0 net/sctp/socket.c:3702 
[ 1722.511384]     [<ffffffff848a2035>] sock_common_setsockopt+0x95/0xd0 net/core/sock.c:2645 
[ 1722.511384]     [<ffffffff8489f1d8>] SyS_setsockopt+0x158/0x240 net/socket.c:1736 
`, `memory leak in ipv6_setsockopt (size 64)`, false,
		}, {
			`
[ 1722.511384] unreferenced object 0xffff8800342540c0 (size 1864): 
[ 1722.511384]   comm "a.out", pid 24109, jiffies 4299060398 (age 27.984s) 
[ 1722.511384]   hex dump (first 32 bytes): 
[ 1722.511384]     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................ 
[ 1722.511384]     0a 00 07 40 00 00 00 00 00 00 00 00 00 00 00 00  ...@............ 
[ 1722.511384]   backtrace: 
[ 1722.511384]     [<ffffffff85c73a22>] kmemleak_alloc+0x72/0xc0 mm/kmemleak.c:915 
[ 1722.511384]     [<ffffffff816cc14d>] kmem_cache_alloc+0x12d/0x2c0 mm/slub.c:2607 
[ 1722.511384]     [<ffffffff84b642c9>] sk_prot_alloc+0x69/0x340 net/core/sock.c:1344 
[ 1722.511384]     [<ffffffff84b6d36a>] sk_alloc+0x3a/0x6b0 net/core/sock.c:1419 
[ 1722.511384]     [<ffffffff850c6d57>] inet6_create+0x2d7/0x1000 net/ipv6/af_inet6.c:173 
[ 1722.511384]     [<ffffffff84b5f47c>] __sock_create+0x37c/0x640 net/socket.c:1162 
`, `memory leak in sk_prot_alloc (size 1864)`, false,
		}, {
			`
[ 1722.511384] unreferenced object 0xffff880133c63800 (size 1024):
[ 1722.511384]   comm "exe", pid 1521, jiffies 4294894652
[ 1722.511384]   backtrace:
[ 1722.511384]     [<ffffffff810f8f36>] create_object+0x126/0x2b0
[ 1722.511384]     [<ffffffff810f91d5>] kmemleak_alloc+0x25/0x60
[ 1722.511384]     [<ffffffff810f32a3>] __kmalloc+0x113/0x200
[ 1722.511384]     [<ffffffff811aa061>] ext4_mb_init+0x1b1/0x570
[ 1722.511384]     [<ffffffff8119b3d2>] ext4_fill_super+0x1de2/0x26d0
`, `memory leak in __kmalloc (size 1024)`, false,
		}, {
			`
[ 1722.511384] unreferenced object 0xc625e000 (size 2048):
[ 1722.511384]   comm "swapper", pid 1, jiffies 4294937521
[ 1722.511384]   backtrace:
[ 1722.511384]     [<c00c89f0>] create_object+0x11c/0x200
[ 1722.511384]     [<c00c6764>] __kmalloc_track_caller+0x138/0x178
[ 1722.511384]     [<c01d78c0>] __alloc_skb+0x4c/0x100
[ 1722.511384]     [<c01d8490>] dev_alloc_skb+0x18/0x3c
[ 1722.511384]     [<c0198b48>] eth_rx_fill+0xd8/0x3fc
[ 1722.511384]     [<c019ac74>] mv_eth_start_internals+0x30/0xf8
`, `memory leak in __alloc_skb (size 2048)`, false,
		}, {
			`
[ 1722.511384] unreferenced object 0xdb8040c0 (size 20):
[ 1722.511384]   comm "swapper", pid 0, jiffies 4294667296
[ 1722.511384]   backtrace:
[ 1722.511384]     [<c04fd8b3>] kmemleak_alloc+0x193/0x2b8
[ 1722.511384]     [<c04f5e73>] kmem_cache_alloc+0x11e/0x174
[ 1722.511384]     [<c0aae5a7>] debug_objects_mem_init+0x63/0x1d9
[ 1722.511384]     [<c0a86a62>] start_kernel+0x2da/0x38d
[ 1722.511384]     [<c0a86090>] i386_start_kernel+0x7f/0x98
[ 1722.511384]     [<ffffffff>] 0xffffffff
`, `memory leak in debug_objects_mem_init (size 20)`, false,
		}, {
			`
[ 1722.511384] BUG: sleeping function called from invalid context at include/linux/wait.h:1095 
[ 1722.511384] in_atomic(): 1, irqs_disabled(): 0, pid: 3658, name: syz-fuzzer 
`, `BUG: sleeping function called from invalid context at include/linux/wait.h:LINE `, true,
		}, {
			`
[  277.780013] INFO: rcu_sched self-detected stall on CPU
[  277.781045] INFO: rcu_sched detected stalls on CPUs/tasks:
[  277.781153] 	1-...: (65000 ticks this GP) idle=395/140000000000001/0 softirq=122875/122875 fqs=16248 
[  277.781197] 	(detected by 0, t=65002 jiffies, g=72940, c=72939, q=1777)
[  277.781212] Sending NMI from CPU 0 to CPUs 1:
[  277.782014] NMI backtrace for cpu 1
[  277.782014] CPU: 1 PID: 12579 Comm: syz-executor0 Not tainted 4.11.0-rc3+ #71
[  277.782014] Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011
[  277.782014] task: ffff8801d379e140 task.stack: ffff8801cd590000
[  277.782014] RIP: 0010:io_serial_in+0x6b/0x90
[  277.782014] RSP: 0018:ffff8801dbf066a0 EFLAGS: 00000002
[  277.782014] RAX: dffffc0000000000 RBX: 00000000000003fd RCX: 0000000000000000
[  277.782014] RDX: 00000000000003fd RSI: 0000000000000005 RDI: ffffffff87020018
[  277.782014] RBP: ffff8801dbf066b0 R08: 0000000000000003 R09: 0000000000000001
[  277.782014] R10: dffffc0000000000 R11: ffffffff867ba200 R12: ffffffff8701ffe0
[  277.782014] R13: 0000000000000020 R14: fffffbfff0e04041 R15: fffffbfff0e04005
[  277.782014] FS:  00007fce6fc10700(0000) GS:ffff8801dbf00000(0000) knlGS:0000000000000000
[  277.782014] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[  277.782014] CR2: 000000002084fffc CR3: 00000001c4500000 CR4: 00000000001406e0
[  277.782014] Call Trace:
[  277.782014]  <IRQ>
[  277.782014]  wait_for_xmitr+0x89/0x1c0
[  277.782014]  ? wait_for_xmitr+0x1c0/0x1c0
[  277.782014]  serial8250_console_putchar+0x1f/0x60
[  277.782014]  uart_console_write+0x57/0xe0
[  277.782014]  serial8250_console_write+0x423/0x840
[  277.782014]  ? check_noncircular+0x20/0x20
[  277.782014]  hrtimer_interrupt+0x1c2/0x5e0
[  277.782014]  local_apic_timer_interrupt+0x6f/0xe0
[  277.782014]  smp_apic_timer_interrupt+0x71/0xa0
[  277.782014]  apic_timer_interrupt+0x93/0xa0
[  277.782014] RIP: 0010:debug_lockdep_rcu_enabled.part.19+0xf/0x60
[  277.782014] RSP: 0018:ffff8801cd596778 EFLAGS: 00000202 ORIG_RAX: ffffffffffffff10
[  277.782014] RAX: dffffc0000000000 RBX: 1ffff10039ab2cf7 RCX: ffffc90001758000
[  277.782014] RDX: 0000000000000004 RSI: ffffffff840561f1 RDI: ffffffff852a75c0
[  277.782014] RBP: ffff8801cd596780 R08: 0000000000000001 R09: 0000000000000000
[  277.782014] R10: dffffc0000000000 R11: ffffffff867ba200 R12: 1ffff10039ab2d1b
[  277.782014] R13: ffff8801c44d1880 R14: ffff8801cd596918 R15: ffff8801d9b47840
[  277.782014]  </IRQ>
[  277.782014]  ? __sctp_write_space+0x5b1/0x920
[  277.782014]  debug_lockdep_rcu_enabled+0x77/0x90
[  277.782014]  __sctp_write_space+0x5b6/0x920
[  277.782014]  ? __sctp_write_space+0x3f7/0x920
[  277.782014]  ? sctp_transport_lookup_process+0x190/0x190
[  277.782014]  ? trace_hardirqs_on_thunk+0x1a/0x1c
`, `INFO: rcu detected stall in __sctp_write_space`, false,
		}, {
			`
[ 1722.511384] INFO: rcu_preempt detected stalls on CPUs/tasks: { 2} (detected by 0, t=65008 jiffies, g=48068, c=48067, q=7339)
`, `INFO: rcu detected stall`, true,
		}, {
			`
[  317.168127] INFO: rcu_sched detected stalls on CPUs/tasks: { 0} (detected by 1, t=2179 jiffies, g=740, c=739, q=1)
`, `INFO: rcu detected stall`, true,
		}, {
			`
[   50.583499] something
[   50.583499] INFO: rcu_preempt self-detected stall on CPU
[   50.583499]         0: (20822 ticks this GP) idle=94b/140000000000001/0
`, `INFO: rcu detected stall`, true,
		}, {
			`
[   50.583499] INFO: rcu_sched self-detected stall on CPU
`, `INFO: rcu detected stall`, true,
		}, {
			`
[  152.002376] INFO: rcu_bh detected stalls on CPUs/tasks:
`, `INFO: rcu detected stall`, true,
		}, {
			`
[   72.159680] INFO: rcu_sched detected expedited stalls on CPUs/tasks: {
`, `INFO: rcu detected stall`, true,
		}, {
			`
[   72.159680] BUG: spinlock lockup suspected on CPU#2, syz-executor/12636
`, `BUG: spinlock lockup suspected`, true,
		}, {
			`
[   72.159680] BUG: soft lockup - CPU#3 stuck for 11s! [syz-executor:643]
`, `BUG: soft lockup`, true,
		}, {
			`
[   72.159680] BUG: spinlock lockup suspected on CPU#2, syz-executor/12636
[   72.159680] BUG: soft lockup - CPU#3 stuck for 11s! [syz-executor:643]
`, `BUG: spinlock lockup suspected`, true,
		}, {
			`
[   72.159680] BUG: soft lockup - CPU#3 stuck for 11s! [syz-executor:643]
[   72.159680] BUG: spinlock lockup suspected on CPU#2, syz-executor/12636
`, `BUG: soft lockup`, true,
		}, {
			`
[  213.269287] BUG: spinlock recursion on CPU#0, syz-executor7/5032
[  213.281506]  lock: 0xffff88006c122d00, .magic: dead4ead, .owner: syz-executor7/5032, .owner_cpu: -1
[  213.285112] CPU: 0 PID: 5032 Comm: syz-executor7 Not tainted 4.9.0-rc7+ #58
[  213.285112] Hardware name: Google Google/Google, BIOS Google 01/01/2011
[  213.285112]  ffff880057c17538 ffffffff834c3ae9 ffffffff00000000 1ffff1000af82e3a
[  213.285112]  ffffed000af82e32 0000000041b58ab3 ffffffff89580db8 ffffffff834c37fb
[  213.285112]  ffff880068ad8858 ffff880068ad8860 1ffff1000af82e2c 0000000041b58ab3
[  213.285112] Call Trace:
[  213.285112]  [<ffffffff834c3ae9>] dump_stack+0x2ee/0x3f5
[  213.618060]  [<ffffffff834c37fb>] ? arch_local_irq_restore+0x53/0x53
[  213.618060]  [<ffffffff81576cd2>] spin_dump+0x152/0x280
[  213.618060]  [<ffffffff81577284>] do_raw_spin_lock+0x3f4/0x5d0
[  213.618060]  [<ffffffff881a2750>] _raw_spin_lock+0x40/0x50
[  213.618060]  [<ffffffff814b7615>] ? __task_rq_lock+0xf5/0x330
[  213.618060]  [<ffffffff814b7615>] __task_rq_lock+0xf5/0x330
[  213.618060]  [<ffffffff814c89b2>] wake_up_new_task+0x592/0x1000
`, `BUG: spinlock recursion`, false,
		}, {
			`
[  843.240752] INFO: task getty:2986 blocked for more than 120 seconds.
[  843.247365]       Not tainted 3.18.0-13280-g93f6785-dirty #12
[  843.253777] "echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message.
[  843.261764] getty           D ffffffff83e27d60 28152  2986      1 0x00000002
[  843.269316]  ffff88005bb6f908 0000000000000046 ffff880050b6ab70 ffff880061e1c5d0
[  843.277435]  fffffbfff07c4802 ffff880061e1cde8 ffffffff83e27d60 ffff88005cb71580
[  843.285515]  ffff88005bb6f968 0000000000000000 1ffff1000b76df2b ffff88005cb71580
[  843.293802] Call Trace:
[  843.296385]  [<ffffffff835bdeb4>] schedule+0x64/0x160
[  843.301593]  [<ffffffff835c9c1a>] schedule_timeout+0x2fa/0x5d0
[  843.307563]  [<ffffffff835c9920>] ? console_conditional_schedule+0x30/0x30
[  843.314790]  [<ffffffff811c1eb2>] ? pick_next_task_fair+0xeb2/0x1680
[  843.321296]  [<ffffffff81d9b3ed>] ? check_preemption_disabled+0x3d/0x210
[  843.328311]  [<ffffffff835cb4ec>] ldsem_down_write+0x1ac/0x357
[  843.334295]  [<ffffffff835cb340>] ? ldsem_down_read+0x3a0/0x3a0
[  843.340437]  [<ffffffff835bec62>] ? preempt_schedule+0x62/0xa0
[  843.346418]  [<ffffffff835cbdd2>] tty_ldisc_lock_pair_timeout+0xb2/0x160
[  843.353363]  [<ffffffff81f8b03f>] tty_ldisc_hangup+0x21f/0x720
`, `INFO: task hung in ldsem_down_write`, false,
		}, {
			`
[  615.391254] INFO: task syz-executor5:10045 blocked for more than 120 seconds.
[  615.398657]       Not tainted 4.13.0-rc1+ #4
[  615.403147] "echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message.
[  615.411181] syz-executor5   D23584 10045   3045 0x00000004
[  615.416901] Call Trace:
[  615.419521]  __schedule+0x8e8/0x2070
[  615.423294]  ? find_held_lock+0x35/0x1d0
[  615.452695]  schedule+0x108/0x440
[  615.456212]  ? wait_on_page_bit_common+0x4a9/0x7f0
[  615.482851]  io_schedule+0x1c/0x70
[  615.486414]  wait_on_page_bit_common+0x4c7/0x7f0
[  615.495766]  ? jbd2_log_wait_commit+0x345/0x420
[  615.530975]  ? pagevec_lookup_tag+0x3a/0x80
[  615.535375]  __filemap_fdatawait_range+0x23f/0x390
[  615.567092]  ? down_read+0x96/0x150
[  615.570758]  filemap_fdatawait_keep_errors+0x80/0x110
[  615.575974]  fdatawait_one_bdev+0x50/0x70
[  615.580151]  iterate_bdevs+0x109/0x260
[  615.584054]  ? sync_inodes_one_sb+0x50/0x50
[  615.588430]  sys_sync+0x122/0x1c0
[  615.591894]  ? sync_filesystem+0x2e0/0x2e0
[  615.601208]  ? trace_hardirqs_on_thunk+0x1a/0x1c
[  615.606028]  entry_SYSCALL_64_fastpath+0x1f/0xbe
[  615.610818] RIP: 0033:0x4512c9
[  615.614042] RSP: 002b:00007f4d6c47fc08 EFLAGS: 00000216 ORIG_RAX: 00000000000000a2
[  615.621807] RAX: ffffffffffffffda RBX: 0000000000718000 RCX: 00000000004512c9
[  615.629146] RDX: 0000000000000000 RSI: 0000000000000000 RDI: 0000000000000000
[  615.636484] RBP: 0000000000000086 R08: 0000000000000000 R09: 0000000000000000
[  615.643830] R10: 0000000000000000 R11: 0000000000000216 R12: 00000000004b6f8f
[  615.651186] R13: 00000000ffffffff R14: 0000000000000000 R15: 0000000000000000
`, `INFO: task hung in wait_on_page_bit_common`, false,
		}, {
			`
[  244.447743] INFO: task syz-executor2:14507 blocked for more than 120 seconds.
[  244.455167]       Not tainted 4.9.40-ged32335 #11
[  244.460033] "echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message.
[  244.468151] syz-executor2   D27168 14507   3322 0x00000002
[  244.473864]  ffff8801a51c4680 ffff88019c120fc0 ffff88019c1224c0 ffff88019f74c680
[  244.481834]  ffff8801db321498 ffff8801c844f778 ffffffff8388f2bb 0000000000000000
[  244.489886]  0000000000000007 00ff8801a51c4680 ffff8801db321db0 ffff8801db321dd8
[  244.497869] Call Trace:
[  244.500425]  [<ffffffff8388f2bb>] ? __schedule+0x67b/0x1ba0
[  244.506100]  [<ffffffff83890872>] schedule+0x92/0x1b0
[  244.511304]  [<ffffffff838911e3>] schedule_preempt_disabled+0x13/0x20
[  244.517906]  [<ffffffff838967f2>] mutex_lock_nested+0x312/0x870
[  244.523933]  [<ffffffff8162804a>] ? blkdev_put+0x2a/0x550
[  244.529459]  [<ffffffff838964e0>] ? mutex_lock_killable_nested+0x960/0x960
[  244.536445]  [<ffffffff8166e69b>] ? locks_remove_file+0x32b/0x420
[  244.542690]  [<ffffffff8163cab6>] ? fsnotify+0x86/0xf30
[  244.548048]  [<ffffffff81628570>] ? blkdev_put+0x550/0x550
[  244.553641]  [<ffffffff8162804a>] blkdev_put+0x2a/0x550
[  244.559031]  [<ffffffff81628570>] ? blkdev_put+0x550/0x550
[  244.564630]  [<ffffffff816285fb>] blkdev_close+0x8b/0xb0
[  244.570099]  [<ffffffff8156ee2c>] __fput+0x28c/0x6e0
[  244.575170]  [<ffffffff8156f305>] ____fput+0x15/0x20
[  244.580276]  [<ffffffff81195e25>] task_work_run+0x115/0x190
[  244.585960]  [<ffffffff8113cf76>] do_exit+0x826/0x2a40
[  244.622863]  [<ffffffff81143658>] do_group_exit+0x108/0x320
[  244.628582]  [<ffffffff8116628c>] get_signal+0x55c/0x1600
[  244.634086]  [<ffffffff81052b97>] do_signal+0x87/0x1960
[  244.674628]  [<ffffffff81003a35>] exit_to_usermode_loop+0xe5/0x130
[  244.680946]  [<ffffffff81006350>] syscall_return_slowpath+0x1a0/0x1e0
[  244.687490]  [<ffffffff838a0766>] entry_SYSCALL_64_fastpath+0xc4/0xc6
`, `INFO: task hung in blkdev_put`, false,
		}, {
			`
[  981.809015] INFO: task kworker/0:1:764 blocked for more than 120 seconds.
[  981.815945]       Not tainted 4.9.39-g72a0c9f #6
[  981.820716] "echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message.
[  981.828649] kworker/0:1     D27296   764      2 0x00000000
[  981.834477] Workqueue: events destroy_radio
[  981.838868]  ffff8801d7128000 0000000000000000 ffff88015c60b180 ffff8801d9e1af00
[  981.846841]  ffff8801db221498 ffff8801d71379e8 ffffffff83954b2b 0000000000000002
[  981.854812]  0000000000000007 00ff8801d7128000 ffff8801db221db0 ffff8801db221dd8
[  981.862773] Call Trace:
[  981.871021]  [<ffffffff839560e2>] schedule+0x92/0x1b0
[  981.876175]  [<ffffffff83956a53>] schedule_preempt_disabled+0x13/0x20
[  981.882795]  [<ffffffff8395bdaf>] mutex_lock_nested+0x2ff/0x830
[  981.914791]  [<ffffffff82f99187>] rtnl_lock+0x17/0x20
[  981.919959]  [<ffffffff8378b7e4>] ieee80211_unregister_hw+0x44/0x270
[  982.003971]  [<ffffffff83965c1a>] ret_from_fork+0x2a/0x40
`, `INFO: task hung in ieee80211_unregister_hw`, false,
		}, {
			`
[  863.200911] INFO: task syz-executor0:5676 blocked for more than 120 seconds.
[  863.203658]       Not tainted 4.14.0-rc8-44455-ge2105594a876 #110
[  863.205780] "echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message.
[  863.208544] syz-executor0   D27584  5676      1 0x00000004
[  863.210626] Call Trace:
[  863.211704]  __schedule+0x57e/0x1940
[  863.213000]  schedule+0x84/0x1c0
[  863.214031]  schedule_timeout+0xa8b/0xe80
[  863.215535]  ? mark_held_locks+0xc8/0x140
[  863.216878]  ? _raw_spin_unlock_irq+0x2c/0x60
[  863.218277]  ? trace_hardirqs_on_caller+0x2c8/0x390
[  863.219875]  wait_for_completion+0x192/0x340
[  863.221345]  ? wake_up_q+0xe0/0xe0
[  863.222517]  kthread_stop+0x105/0x650
[  863.223783]  set_current_rng+0x2b2/0x3b0
[  863.225073]  hwrng_unregister+0x1db/0x230
[  863.226341]  chaoskey_disconnect+0x1c8/0x210
[  863.227675]  usb_unbind_interface+0x1b6/0x950
[  863.250249]  SyS_ioctl+0xbb/0xe0
[  863.250857]  entry_SYSCALL_64_fastpath+0x23/0xc2
`, `INFO: task hung in set_current_rng`, false,
		}, {
			`
[  185.479466] BUG: scheduling while atomic: syz-executor0/19425/0x00000000
[  185.486365] INFO: lockdep is turned off.
[  185.490423] Modules linked in:
[  185.494289] CPU: 1 PID: 19425 Comm: syz-executor0 Tainted: G        W       4.3.5+ #11
[  185.502324] Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011
[  185.511657]  0000000000000001 ffff8801d614bd58 ffffffff81ca45ed ffff8801d12ce040
[  185.519687]  0000000000000000 000000000001f140 ffff8801d12ce040 0000000000000001
[  185.527710]  ffff8801d614bd78 ffffffff8133a690 ffff8801db51f140 ffff8801d12ce040
[  185.535769] Call Trace:
[  185.538344]  [<ffffffff81ca45ed>] dump_stack+0xc1/0x124
[  185.543718]  [<ffffffff8133a690>] __schedule_bug+0xc0/0xf0
[  185.549324]  [<ffffffff81000f22>] __schedule+0x8c2/0x13f0
[  185.554860]  [<ffffffff8135c9c7>] ? SyS_gsys_swg_wait+0x3c7/0xbd0
[  185.561075]  [<ffffffff8135ca3d>] ? SyS_gsys_swg_wait+0x43d/0xbd0
[  185.567281]  [<ffffffff81001aea>] schedule+0x9a/0x1b0
[  185.572445]  [<ffffffff8135ca47>] SyS_gsys_swg_wait+0x447/0xbd0
[  185.578480]  [<ffffffff8135c600>] ? SyS_gsys_swg_become_designate+0x290/0x290
[  185.585729]  [<ffffffff81017200>] ? trace_event_raw_event_sys_enter_tiny+0x2e0/0x2e0
[  185.593586]  [<ffffffff81018464>] ? prepare_exit_to_usermode+0x294/0x350
[  185.600416]  [<ffffffff81015198>] ? do_audit_syscall_entry+0xd8/0x240
[  185.606975]  [<ffffffff81017956>] ? syscall_trace_enter_phase2+0x216/0x9a0
[  185.613965]  [<ffffffff82c7b5f9>] tracesys_phase2+0x84/0x89
`, `BUG: scheduling while atomic: syz-executor/ADDR`, false,
		}, {
			`
[   72.159680] BUG UNIX (Not tainted): kasan: bad access detected
`, ``, false,
		}, {
			`
[901320.960000] INFO: lockdep is turned off.
`, ``, false,
		}, {
			`
[   72.159680] INFO: Stall ended before state dump start
`, ``, false,
		}, {
			`
[   72.159680] WARNING: /etc/ssh/moduli does not exist, using fixed modulus
`, ``, false,
		}, {
			`
[ 1579.244514] BUG: KASAN: slab-out-of-bounds in ip6_fragment+0x1052/0x2d80 at addr ffff88004ec29b58
`, `KASAN: slab-out-of-bounds in ip6_fragment at addr ADDR`, true,
		}, {
			`
[  982.271203] BUG: spinlock bad magic on CPU#0, syz-executor12/24932
`, `BUG: spinlock bad magic`, true,
		}, {
			`
[  374.860710] BUG: KASAN: use-after-free in do_con_write.part.23+0x1c50/0x1cb0 at addr ffff88000012c43a
`, `KASAN: use-after-free in do_con_write.part.23 at addr ADDR`, true,
		}, {
			`
[  163.314570] WARNING: kernel stack regs at ffff8801d100fea8 in syz-executor1:16059 has bad 'bp' value ffff8801d100ff28
`, `WARNING: kernel stack regs has bad 'bp' value`, false,
		}, {
			`
[   76.825838] BUG: using __this_cpu_add() in preemptible [00000000] code: syz-executor0/10076
`, `BUG: using __this_cpu_add() in preemptible [ADDR] code: syz-executor`, true,
		}, {
			`
[  367.131148] BUG kmalloc-8 (Tainted: G    B         ): Object already free
`, `BUG: Object already free`, true,
		}, {
			`
[   92.396607] APIC base relocation is unsupported by KVM
[   95.445015] INFO: NMI handler (perf_event_nmi_handler) took too long to run: 1.356 msecs
[   95.445015] perf: interrupt took too long (3985 > 3976), lowering kernel.perf_event_max_sample_rate to 50000
`, ``, false,
		}, {
			`
[   92.396607] general protection fault: 0000 [#1] [ 387.811073] audit: type=1326 audit(1486238739.637:135): auid=4294967295 uid=0 gid=0 ses=4294967295 pid=10020 comm="syz-executor1" exe="/root/syz-executor1" sig=31 arch=c000003e syscall=202 compat=0 ip=0x44fad9 code=0x0
`, `general protection fault`, true,
		}, {
			`
[   40.438790] BUG: Bad page map in process syz-executor6  pte:ffff8801a700ff00 pmd:1a700f067
[   40.447217] addr:00000000009ca000 vm_flags:00100073 anon_vma:ffff8801d16f20e0 mapping:          (null) index:9ca
[   40.457560] file:          (null) fault:          (null) mmap:          (null) readpage:          (null)
`, `BUG: Bad page map`, true,
		}, {
			`
[ 1722.511384] ======================================================
[ 1722.511384] WARNING: possible circular locking dependency detected
[ 1722.511384] 4.12.0-rc2-next-20170529+ #1 Not tainted
[ 1722.511384] ------------------------------------------------------
[ 1722.511384] kworker/u4:2/58 is trying to acquire lock:
[ 1722.511384]  (&buf->lock){+.+...}, at: [<ffffffffa41b4e5b>] tty_buffer_flush+0xbb/0x3a0 drivers/tty/tty_buffer.c:221
[ 1722.511384] 
[ 1722.511384] but task is already holding lock:
[ 1722.511384]  (&o_tty->termios_rwsem/1){++++..}, at: [<ffffffffa41a5601>] isig+0xa1/0x4d0 drivers/tty/n_tty.c:1100
[ 1722.511384] 
[ 1722.511384] which lock already depends on the new lock.
`, `possible deadlock in tty_buffer_flush`, true,
		}, {

			`
[ 1722.511384] Buffer I/O error on dev loop0, logical block 6, async page read
[ 1722.511384] BUG: Dentry ffff880175978600{i=8bb9,n=lo}  still in use (1) [unmount of proc proc]
[ 1722.511384] ------------[ cut here ]------------
[ 1722.511384] WARNING: CPU: 1 PID: 8922 at fs/dcache.c:1445 umount_check+0x246/0x2c0 fs/dcache.c:1436
[ 1722.511384] Kernel panic - not syncing: panic_on_warn set ...
`, `BUG: Dentry still in use [unmount of proc proc]`, true,
		}, {
			`
[   72.159680] WARNING: kernel stack frame pointer at ffff88003e1f7f40 in migration/1:14 has bad value ffffffff85632fb0
[   72.159680] unwind stack type:0 next_sp:          (null) mask:0x6 graph_idx:0
[   72.159680] ffff88003ed06ef0: ffff88003ed06f78 (0xffff88003ed06f78)
`, `WARNING: kernel stack frame pointer has bad value`, false,
		}, {
			`
[ 1722.511384] BUG: Bad page state in process syz-executor9  pfn:199e00
[ 1722.511384] page:ffffea00059a9000 count:0 mapcount:0 mapping:          (null) index:0x20a00
[ 1722.511384] TCP: request_sock_TCPv6: Possible SYN flooding on port 20032. Sending cookies.  Check SNMP counters.
[ 1722.511384] flags: 0x200000000040019(locked|uptodate|dirty|swapbacked)
[ 1722.511384] raw: 0200000000040019 0000000000000000 0000000000020a00 00000000ffffffff
[ 1722.511384] raw: dead000000000100 dead000000000200 0000000000000000
[ 1722.511384] page dumped because: PAGE_FLAGS_CHECK_AT_FREE flag(s)
`, `BUG: Bad page state`, true,
		}, {
			`
[ 1722.511384] Kernel panic - not syncing: Couldn't open N_TTY ldisc for ptm1 --- error -12.
[ 1722.511384] CPU: 1 PID: 14836 Comm: syz-executor5 Not tainted 4.12.0-rc4+ #15
[ 1722.511384] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS Bochs 01/01/2011
[ 1722.511384] Call Trace:
`, `kernel panic: Couldn't open N_TTY ldisc`, true,
		}, {
			`
[ 1722.511384] ===============================
[ 1722.511384] [ INFO: suspicious RCU usage. ]
[ 1722.511384] 4.3.5+ #8 Not tainted
[ 1722.511384] -------------------------------
[ 1722.511384] net/ipv6/ip6_flowlabel.c:544 suspicious rcu_dereference_check() usage!
[ 1722.511384] 
[ 1722.511384] other info that might help us debug this:
`, `suspicious RCU usage at net/ipv6/ip6_flowlabel.c:LINE`, true,
		}, {
			`
[   37.991733]  [4:SdpManagerServi: 3874] KEK_PACK[3874] __add_kek :: item ffffffc822340400
[   38.018742]  [4:  system_server: 3344] logger: !@Boot_DEBUG: start networkManagement
[   38.039013]  [2:    kworker/2:1: 1608] Trustonic TEE: c01|TL_TZ_KEYSTORE: Starting
`, ``, false,
		}, {
			`
[   16.761978] [syscamera][msm_companion_pll_init::526][BIN_INFO::0x0008]
[   16.762666] [syscamera][msm_companion_pll_init::544][WAFER_INFO::0xcf80]
[   16.763144] [syscamera][msm_companion_pll_init::594][BIN_INFO::0x0008][WAFER_INFO::0xcf80][voltage 0.775]
`, ``, false,
		}, {
			`
[   72.159680] BUG: workqueue lockup - pool cpus=0 node=0 flags=0x0 nice=0 stuck for 32s!
`, `BUG: workqueue lockup`, false,
		}, {
			`
[  108.620932] BUG: spinlock already unlocked on CPU#1, migration/1/12
[  108.627365]  lock: rcu_sched_state+0xb40/0xc20, .magic: dead4ead, .owner: <none>/-1, .owner_cpu: -1
[  108.636523] CPU: 1 PID: 12 Comm: migration/1 Not tainted 4.3.5+ #6
[  108.642815] Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011
[  108.652143]  0000000000000001 ffff8801d8f6fb30 ffffffff81d0010d ffffffff837b69c0
[  108.660142]  ffff8801d8f68340 0000000000000003 0000000000000001 0000000000000000
[  108.668095]  ffff8801d8f6fb70 ffffffff813fba22 0000000000000046 ffff8801d8f68b80
[  108.676053] Call Trace:
[  108.678614]  [<ffffffff81d0010d>] dump_stack+0xc1/0x124
[  108.683946]  [<ffffffff813fba22>] spin_dump+0x152/0x280
[  108.689274]  [<ffffffff813fc152>] do_raw_spin_unlock+0x1e2/0x240
[  108.695386]  [<ffffffff810108ec>] _raw_spin_unlock_irqrestore+0x2c/0x60
[  108.702102]  [<ffffffff813cd204>] __wake_up+0x44/0x50
[  108.707255]  [<ffffffff81429500>] ? rcu_barrier_func+0x90/0x90
[  108.713189]  [<ffffffff8142958a>] synchronize_sched_expedited_cpu_stop+0x8a/0xa0
[  108.720688]  [<ffffffff814dbfe8>] cpu_stopper_thread+0x1f8/0x400
[  108.726796]  [<ffffffff814dbdf0>] ? cpu_stop_create+0x90/0x90
[  108.732646]  [<ffffffff814db078>] ? cpu_stop_should_run+0x58/0xb0
[  108.738844]  [<ffffffff810108f6>] ? _raw_spin_unlock_irqrestore+0x36/0x60
[  108.745734]  [<ffffffff813ed79b>] ? trace_hardirqs_on_caller+0x38b/0x590
[  108.752541]  [<ffffffff813ed9ad>] ? trace_hardirqs_on+0xd/0x10
[  108.758476]  [<ffffffff814dbdf0>] ? cpu_stop_create+0x90/0x90
[  108.764326]  [<ffffffff8134237c>] smpboot_thread_fn+0x47c/0x880
[  108.770347]  [<ffffffff81341f00>] ? sort_range+0x40/0x40
[  108.775761]  [<ffffffff81001aea>] ? schedule+0x9a/0x1b0
[  108.781090]  [<ffffffff81337c9f>] ? __kthread_parkme+0x17f/0x250
[  108.787198]  [<ffffffff81338531>] kthread+0x231/0x2c0
[  108.792352]  [<ffffffff81341f00>] ? sort_range+0x40/0x40
[  108.797767]  [<ffffffff81338300>] ? kthread_create_on_node+0x460/0x460
[  108.804399]  [<ffffffff81338300>] ? kthread_create_on_node+0x460/0x460
[  108.811031]  [<ffffffff82d2fbac>] ret_from_fork+0x5c/0x90
[  108.816532]  [<ffffffff81338300>] ? kthread_create_on_node+0x460/0x460
 `, `BUG: spinlock already unlocked`, false,
		}, {
			`
[  128.792466] R10: 00000000000f4244 R11: 0000000000000217 R12: 00000000004bbb5d
[  128.792471] R13: 00000000ffffffff R14: 000000000000001a R15: 000000000000001b
[  128.792489] Code: 48 0f 44 da e8 c0 5b c4 ff 48 8b 85 28 ff ff ff 4d 89 f1 4c 89 e9 4c 89 e2 48 89 de 48 c7 c7 20 a3 f1 84 49 89 c0 e8 13 68 ae ff <0f> 0b 48 c7 c0 e0 a0 f1 84 eb 96 48 c7 c0 20 a1 f1 84 eb 8d 48 
[  128.792644] RIP: __check_object_size+0x3a2/0x4f0 RSP: ffff8801c15d7148
[  128.792706] ---[ end trace 794afb02691fabdc ]---
[  128.792710] Kernel panic - not syncing: Fatal exception
[  128.793235] Dumping ftrace buffer:
[  128.793239]    (ftrace buffer empty)
[  128.793242] Kernel Offset: disabled
[  129.380444] Rebooting in 86400 seconds..
`, `kernel panic: Fatal exception`, true,
		}, {
			`
[  238.092073] page:ffffea000712e200 count:1 mapcount:0 mapping:ffff8801c4b88c00 index:0x0 compound_mapcount: 0
[  238.102211] flags: 0x200000000008100(slab|head)
[  238.106859] raw: 0200000000008100 ffff8801c4b88c00 0000000000000000 0000000100000001
[  238.114718] raw: ffffea00072d2a20 ffffea0007110820 ffff8801dac02200 0000000000000000
[  238.122567] page dumped because: kasan: bad access detected
[  238.128296] Kernel panic - not syncing: panic_on_warn set ...
[  238.128296] 
[  238.135637] CPU: 1 PID: 577 Comm: syz-executor4 Tainted: G    B           4.14.0-rc5+ #141
[  238.144011] Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011
[  238.153335] Call Trace:
[  238.155900]  dump_stack+0x194/0x257
[  238.159499]  ? arch_local_irq_restore+0x53/0x53
[  238.164137]  ? kasan_end_report+0x32/0x50
[  238.168257]  ? lock_downgrade+0x990/0x990
[  238.172377]  ? __internal_add_timer+0x1f0/0x2d0
[  238.177023]  panic+0x1e4/0x417
[  238.180186]  ? __warn+0x1d9/0x1d9
[  238.183612]  ? add_taint+0x40/0x50
[  238.187128]  ? __internal_add_timer+0x275/0x2d0
[  238.191766]  kasan_end_report+0x50/0x50
[  238.195711]  kasan_report+0x144/0x340
`, `kernel panic: panic_on_warn set`, true,
		}, {
			`
[  308.130685] ======================================================
[  308.136979] WARNING: possible circular locking dependency detected
[  308.143266] 4.14.0-rc3+ #22 Not tainted
[  308.147204] ------------------------serialport: VM disconnected.
`, `possible deadlock`, true,
		}, {
			`
[ 1722.511384] BUG: unable to handle kernel 
[ 1722.511384] 
[ 1722.511384] paging request at ffffffff761cd3a8
[ 1722.511384] IP: node_state include/linux/nodemask.h:405 [inline]
[ 1722.511384] IP: map_create kernel/bpf/syscall.c:326 [inline]
[ 1722.511384] IP: SYSC_bpf kernel/bpf/syscall.c:1462 [inline]
[ 1722.511384] IP: SyS_bpf+0x3c9/0x4c40 kernel/bpf/syscall.c:1443
[ 1722.511384] PGD 5a25067 
[ 1722.511384] P4D 5a25067 
[ 1722.511384] PUD 0
`, `BUG: unable to handle kernel`, true,
		}, {
			`
[ 1722.511384] kasan: CONFIG_KASAN_INLINE enabled
[ 1722.511384] kasan: GPF could be caused by NULL-ptr deref or user memory access
[ 1722.511384] general protection fault: 0000 [#1] SMP KASAN
[ 1722.511384] Modules linked in:
[ 1722.511384] CPU: 1 PID: 18769 Comm: syz-executor2 Not tainted 4.3.5+ #10
`, `general protection fault`, true,
		}, {
			`
[  153.518371] device lo entered promiscuous mode
[  153.606199] kernel tried to execute NX-protected page - exploit attempt? (uid: 0)
[  153.613861] BUG: unable to handle kernel [  153.615435] deprecated getsockopt IP_VLAN used by syz-executor4!

[  153.623948] paging request at ffff8800b3d5ed58
[  153.628940] IP: [<ffff8800b3d5ed58>] 0xffff8800b3d5ed58
[  153.634416] PGD a0ab067 PUD 21ffff067 PMD 80000000b3c001e3 
[  153.640483] Oops: 0011 [#1] SMP KASAN
[  153.644615] Modules linked in:
`, `BUG: unable to handle kernel`, true,
		}, {
			`
[   46.415093] syz2: link speed 10 Mbps
[   46.572486] syz7: link speed 10 Mbps
[   46.573324] 
[   46.573325] =====================================
[   46.573327] [ BUG: bad unlock balance detected! ]
`, `BUG: bad unlock balance`, true,
		}, {
			`
[   89.659427] netlink: 13 bytes leftover after parsing attributes in process syz-executor5'.
[   89.668217] divide error: 0000 [#1] SMP KASAN
`, `divide error`, true,
		}, {
			`
[   59.534220] ==================================================================
[   59.541645] BUG: KASAN: slab-out-of-bounds in gup_huge_pmd+0x739/0x770 at addr ffff8800b46111c0
`, `KASAN: slab-out-of-bounds in gup_huge_pmd at addr ADDR`, true,
		}, {
			`
[   42.361487] ==================================================================
[   42.364412] BUG: KASAN: slab-out-of-bounds in ip6_fragment+0x11c8/0x3730
[   42.365471] Read of size 840 at addr ffff88000969e798 by task ip6_fragment-oo/3789
[   42.366469]
[   42.366696] CPU: 1 PID: 3789 Comm: ip6_fragment-oo Not tainted 4.11.0+ #41
[   42.367628] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.10.1-1ubuntu1 04/01/2014
[   42.368824] Call Trace:
[   42.369183]  dump_stack+0xb3/0x10b
[   42.369664]  print_address_description+0x73/0x290
[   42.370325]  kasan_report+0x252/0x370
[   42.371396]  check_memory_region+0x13c/0x1a0
[   42.371978]  memcpy+0x23/0x50
[   42.372395]  ip6_fragment+0x11c8/0x3730
...
[   42.390650]  SyS_sendto+0x40/0x50
[   42.391103]  entry_SYSCALL_64_fastpath+0x1f/0xbe
[   42.391731] RIP: 0033:0x7fbbb711e383
[   42.392217] RSP: 002b:00007ffff4d34f28 EFLAGS: 00000246 ORIG_RAX: 000000000000002c
[   42.393235] RAX: ffffffffffffffda RBX: 0000000000000000 RCX: 00007fbbb711e383
[   42.394195] RDX: 0000000000001000 RSI: 00007ffff4d34f60 RDI: 0000000000000003
[   42.395145] RBP: 0000000000000046 R08: 00007ffff4d34f40 R09: 0000000000000018
[   42.396056] R10: 0000000000000000 R11: 0000000000000246 R12: 0000000000400aad
[   42.396598] R13: 0000000000000066 R14: 00007ffff4d34ee0 R15: 00007fbbb717af00
[   42.397257]
[   42.397411] Allocated by task 3789:
[   42.397702]  save_stack_trace+0x16/0x20
[   42.398005]  save_stack+0x46/0xd0
[   42.398267]  kasan_kmalloc+0xad/0xe0
[   42.398548]  kasan_slab_alloc+0x12/0x20
[   42.398848]  __kmalloc_node_track_caller+0xcb/0x380
[   42.399224]  __kmalloc_reserve.isra.32+0x41/0xe0
[   42.399654]  __alloc_skb+0xf8/0x580
[   42.400003]  sock_wmalloc+0xab/0xf0
[   42.400346]  __ip6_append_data.isra.41+0x2472/0x33d0
[   42.400813]  ip6_append_data+0x1a8/0x2f0
[   42.401122]  rawv6_sendmsg+0x11ee/0x2db0
[   42.401505]  inet_sendmsg+0x123/0x500
[   42.401860]  sock_sendmsg+0xca/0x110
[   42.402209]  ___sys_sendmsg+0x7cb/0x930
[   42.402582]  __sys_sendmsg+0xd9/0x190
[   42.402941]  SyS_sendmsg+0x2d/0x50
[   42.403273]  entry_SYSCALL_64_fastpath+0x1f/0xbe
[   42.403718]
[   42.403871] Freed by task 1794:
[   42.404146]  save_stack_trace+0x16/0x20
[   42.404515]  save_stack+0x46/0xd0
[   42.404827]  kasan_slab_free+0x72/0xc0
[   42.405167]  kfree+0xe8/0x2b0
[   42.405462]  skb_free_head+0x74/0xb0
[   42.405806]  skb_release_data+0x30e/0x3a0
[   42.406198]  skb_release_all+0x4a/0x60
[   42.406563]  consume_skb+0x113/0x2e0
[   42.406910]  skb_free_datagram+0x1a/0xe0
[   42.407288]  netlink_recvmsg+0x60d/0xe40
[   42.407667]  sock_recvmsg+0xd7/0x110
[   42.408022]  ___sys_recvmsg+0x25c/0x580
[   42.408395]  __sys_recvmsg+0xd6/0x190
[   42.408753]  SyS_recvmsg+0x2d/0x50
[   42.409086]  entry_SYSCALL_64_fastpath+0x1f/0xbe
[   42.409513]
[   42.409665] The buggy address belongs to the object at ffff88000969e780
[   42.409665]  which belongs to the cache kmalloc-512 of size 512
[   42.410846] The buggy address is located 24 bytes inside of
[   42.410846]  512-byte region [ffff88000969e780, ffff88000969e980)
[   42.411941] The buggy address belongs to the page:
[   42.412405] page:ffffea000025a780 count:1 mapcount:0 mapping:          (null) index:0x0 compound_mapcount: 0
[   42.413298] flags: 0x100000000008100(slab|head)
[   42.413729] raw: 0100000000008100 0000000000000000 0000000000000000 00000001800c000c
[   42.414387] raw: ffffea00002a9500 0000000900000007 ffff88000c401280 0000000000000000
[   42.415074] page dumped because: kasan: bad access detected
[   42.415604]
[   42.415757] Memory state around the buggy address:
[   42.416222]  ffff88000969e880: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
[   42.416904]  ffff88000969e900: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
[   42.417591] >ffff88000969e980: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
[   42.418273]                    ^
[   42.418588]  ffff88000969ea00: fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
[   42.419273]  ffff88000969ea80: fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
[   42.419882] ==================================================================
`, `KASAN: slab-out-of-bounds Read in ip6_fragment`, false,
		}, {
			`
[   55.468844] ==================================================================
[   55.476243] BUG: KASAN: use-after-free in consume_skb+0x39f/0x530 at addr ffff8801cbeda574
[   55.484627] Read of size 4 by task syz-executor2/4676
[   55.490296] Object at ffff8801cbeda480, in cache skbuff_head_cache size: 248
[   55.497470] Allocated:
[   55.499957] PID = 4655
[   55.502578] Freed:
[   55.504709] PID = 4655
[   55.507369] Memory state around the buggy address:
`, `KASAN: use-after-free Read in consume_skb`, true,
		}, {
			`
[  322.909624] FAULT_FLAG_ALLOW_RETRY missing 30
[  322.914808] FAULT_FLAG_ALLOW_RETRY missing 30
[  322.914819] CPU: 0 PID: 23312 Comm: syz-executor7 Not tainted 4.9.60-gdfe0a9b #81
[  322.914824] Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011
[  322.914839]  ffff8801d58ff750 ffffffff81d91389 ffff8801d58ffa30 0000000000000000
[  322.914853]  ffff8801c456c710 ffff8801d58ff920 ffff8801c456c600 ffff8801d58ff948
[  322.914865]  ffffffff8165fc37 0000000000006476 ffff8801ca16b8f0 ffff8801ca16b8a0
[  322.914868] Call Trace:
[  322.914882]  [<ffffffff81d91389>] dump_stack+0xc1/0x128
** 93 printk messages dropped ** [  322.962139] BUG: KASAN: slab-out-of-bounds in do_raw_write_lock+0x1a3/0x1d0 at addr ffff8801c464b568
** 1987 printk messages dropped ** [  322.975979]  ffff8801c464b400: fb fb fb fb fb fb fb fb fb fb fb fb fc fc fc fc
`, `KASAN: slab-out-of-bounds in do_raw_write_lock at addr ADDR`, true,
		}, {
			`
[  208.131930] ==================================================================
[  208.139343] BUG: KMSAN: use of uninitialized memory in packet_set_ring+0x11b8/0x2ff0
[  208.147224] CPU: 0 PID: 12442 Comm: syz-executor0 Tainted: G    B           4.13.0+ #12
[  208.155359] Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011
[  208.164705] Call Trace:
[  208.167295]  dump_stack+0x172/0x1c0
[  208.170931]  ? packet_set_ring+0x11b8/0x2ff0
[  208.175334]  kmsan_report+0x145/0x3d0
[  208.179143]  __msan_warning_32+0x65/0xb0
[  208.183202]  packet_set_ring+0x11b8/0x2ff0
[  208.187429]  ? memcmp+0xbc/0x1a0
[  208.190799]  packet_setsockopt+0x1619/0x4e40
[  208.195205]  ? selinux_socket_setsockopt+0x2f1/0x330
[  208.200305]  ? __msan_load_shadow_origin_8+0x5d/0xe0
[  208.205390]  ? packet_ioctl+0x400/0x400
[  208.209340]  SYSC_setsockopt+0x36d/0x4b0
[  208.213383]  SyS_setsockopt+0x76/0xa0
[  208.217163]  entry_SYSCALL_64_fastpath+0x13/0x94
[  208.221889] RIP: 0033:0x4520a9
[  208.225056] RSP: 002b:00007f37efa32c08 EFLAGS: 00000216 ORIG_RAX: 0000000000000036
[  208.232740] RAX: ffffffffffffffda RBX: 00007f37efa33700 RCX: 00000000004520a9
[  208.239987] RDX: 0000000000000005 RSI: 0000000000000107 RDI: 000000000000001e
[  208.247230] RBP: 0000000000a6f870 R08: 000000000000047e R09: 0000000000000000
[  208.254485] R10: 0000000020001000 R11: 0000000000000216 R12: 0000000000000000
[  208.261729] R13: 0000000000a6f7ef R14: 00007f37efa339c0 R15: 000000000000000c
[  208.268977] origin description: ----req_u@packet_setsockopt
[  208.274656] local variable created at:
[  208.278520]  packet_setsockopt+0x133/0x4e40
`, `BUG: KMSAN: use of uninitialized memory in packet_set_ring`, false,
		}, {
			`
[  189.525626] ==================================================================
[  189.533112] BUG: KASAN: stack-out-of-bounds in xfrm_state_find+0x30fc/0x3230
[  189.540278] Read of size 4 at addr ffff8801ca7c7960 by task syz-executor3/12380
[  189.547691] 
[  189.549293] CPU: 0 PID: 12380 Comm: syz-executor3 Not tainted 4.14.0+ #100
[  189.556273] Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011
[  189.565597] Call Trace:
[  189.568167]  dump_stack+0x194/0x257
[  189.589216]  print_address_description+0x73/0x250
[  189.598424]  kasan_report+0x25b/0x340
[  189.602201]  __asan_report_load4_noabort+0x14/0x20
[  189.607099]  xfrm_state_find+0x30fc/0x3230
...
[  190.013732]  entry_SYSENTER_compat+0x51/0x60
[  190.018112] RIP: 0023:0xf7f8ec79
[  190.021458] RSP: 002b:00000000f778a01c EFLAGS: 00000296 ORIG_RAX: 0000000000000171
[  190.029137] RAX: ffffffffffffffda RBX: 0000000000000014 RCX: 0000000020cd8000
[  190.036385] RDX: 00000000000000f6 RSI: 0000000000004080 RDI: 000000002022d53c
[  190.043623] RBP: 0000000000000010 R08: 0000000000000000 R09: 0000000000000000
[  190.050863] R10: 0000000000000000 R11: 0000000000000000 R12: 0000000000000000
[  190.058106] R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000
[  190.065368] 
[  190.066964] The buggy address belongs to the page:
[  190.071865] page:ffffea000729f1c0 count:0 mapcount:0 mapping:          (null) index:0x0
[  190.079977] flags: 0x2fffc0000000000()
[  190.083840] raw: 02fffc0000000000 0000000000000000 0000000000000000 00000000ffffffff
[  190.091689] raw: 0000000000000000 0000000100000001 0000000000000000 0000000000000000
[  190.099536] page dumped because: kasan: bad access detected
[  190.105211] 
[  190.106806] Memory state around the buggy address:
[  190.111702]  ffff8801ca7c7800: f2 00 f2 f2 f2 f2 f2 f2 f2 00 00 00 f2 f2 f2 f2
[  190.119033]  ffff8801ca7c7880: f2 00 00 00 00 f2 f2 f2 f2 00 00 00 00 00 00 f2
[  190.126361] >ffff8801ca7c7900: f2 f2 f2 f2 f2 00 00 00 00 00 00 00 f2 f2 f2 f2
[  190.133687]                                                        ^
[  190.140148]  ffff8801ca7c7980: f2 00 00 00 00 00 00 00 00 00 f2 f2 f2 f3 f3 f3
[  190.147475]  ffff8801ca7c7a00: f3 00 00 00 00 00 00 00 00 00 00 f1 f1 f1 f1 00
[  190.154802] ==================================================================
`, `KASAN: stack-out-of-bounds Read in xfrm_state_find`, false,
		}, {
			`
[  190.154802] ==================================================================
[  190.154802] BUG: KASAN: slab-out-of-bounds in __lock_acquire+0x2eff/0x3640 at addr ffff8801a751e6f8
[  190.154802] Read of size 8 by task syz-executor7/18786
[  190.154802] CPU: 1 PID: 18786 Comm: syz-executor7 Not tainted 4.9.60-g4ca16e6 #83
[  190.154802] Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011
[  190.154802]  ffff8801cd20f810 ffffffff81d91389 ffff8801d74358c0 ffff8801a751e680
[  190.154802]  ffff8801a751e6e0 ffffed0034ea3cdf ffff8801a751e6f8 ffff8801cd20f838
[  190.154802]  ffffffff8153c1bc ffffed0034ea3cdf ffff8801d74358c0 0000000000000000
[  190.154802] Call Trace:
[  190.154802]  [<ffffffff81d91389>] dump_stack+0xc1/0x128
[  190.154802]  [<ffffffff8153c1bc>] kasan_object_err+0x1c/0x70
[  190.154802]  [<ffffffff8153c47c>] kasan_report.part.1+0x21c/0x500
[  190.154802]  [<ffffffff8153c819>] __asan_report_load8_noabort+0x29/0x30
[  190.154802]  [<ffffffff8123e9cf>] __lock_acquire+0x2eff/0x3640
[  190.154802]  [<ffffffff8123fb4e>] lock_acquire+0x12e/0x410
[  190.154802]  [<ffffffff838aa25e>] _raw_write_lock_irqsave+0x4e/0x62
[  190.154802]  [<ffffffff8265f840>] sg_remove_request+0x70/0x120
[  190.154802]  [<ffffffff8265fe55>] sg_finish_rem_req+0x295/0x340
[  190.154802]  [<ffffffff82661b8c>] sg_read+0x91c/0x1400
[  190.154802]  [<ffffffff8156c793>] __vfs_read+0x103/0x670
[  190.154802]  [<ffffffff8156dd27>] vfs_read+0x107/0x330
[  190.154802]  [<ffffffff815719c9>] SyS_read+0xd9/0x1b0
[  190.154802]  [<ffffffff838aa305>] entry_SYSCALL_64_fastpath+0x23/0xc6
[  190.154802] Object at ffff8801a751e680, in cache fasync_cache size: 96
[  190.154802] Allocated:
[  190.154802] PID = 18786
[  190.154802]  save_stack_trace+0x16/0x20
[  190.154802]  save_stack+0x43/0xd0
[  190.154802]  kasan_kmalloc+0xad/0xe0
[  190.154802]  kasan_slab_alloc+0x12/0x20
[  190.154802]  kmem_cache_alloc+0xba/0x290
[  190.154802]  fasync_helper+0x37/0xb0
[  190.154802]  sg_fasync+0x86/0xb0
[  190.154802]  do_vfs_ioctl+0x2d8/0x10c0
[  190.154802]  SyS_ioctl+0x8f/0xc0
[  190.154802]  entry_SYSCALL_64_fastpath+0x23/0xc6
[  190.154802] Freed:
[  190.154802] PID = 16494
[  190.154802]  save_stack_trace+0x16/0x20
[  190.154802]  save_stack+0x43/0xd0
[  190.154802]  kasan_slab_free+0x73/0xc0
[  190.154802]  kmem_cache_free+0xb2/0x2e0
[  190.154802]  fasync_free_rcu+0x1d/0x20
[  190.154802]  rcu_process_callbacks+0x871/0x12c0
[  190.154802]  __do_softirq+0x206/0x951
[  190.154802] Memory state around the buggy address:
[  190.154802]  ffff8801a751e580: fb fb fb fb fb fb fb fb fb fb fb fb fc fc fc fc
[  190.154802]  ffff8801a751e600: fb fb fb fb fb fb fb fb fb fb fb fb fc fc fc fc
[  190.154802] >ffff8801a751e680: 00 00 00 00 00 00 00 00 00 00 00 00 fc fc fc fc
[  190.154802]                                                                 ^
[  190.154802]  ffff8801a751e700: 00 00 00 00 00 00 00 00 00 00 00 00 fc fc fc fc
[  190.154802]  ffff8801a751e780: 00 00 00 00 00 00 00 00 00 00 00 00 fc fc fc fc
[  190.154802] ==================================================================
`, `KASAN: slab-out-of-bounds Read in __lock_acquire`, false,
		}, {
			`
[  190.154802] md: Autodetecting RAID arrays.
[  190.154802] md: autorun ...
[  190.154802] md: ... autorun DONE.
[  190.154802] EXT4-fs (sda1): couldn't mount as ext3 due to feature incompatibilities
[  190.154802] EXT4-fs (sda1): couldn't mount as ext2 due to feature incompatibilities
[  190.154802] EXT4-fs (sda1): INFO: recovery required on readonly filesystem
[  190.154802] EXT4-fs (sda1): write access will be enabled during recovery
[  190.154802] clocksource: Switched to clocksource tsc
[  190.154802] EXT4-fs (sda1): recovery complete
[  190.154802] EXT4-fs (sda1): mounted filesystem with ordered data mode. Opts: (null)
[  190.154802] VFS: Mounted root (ext4 filesystem) readonly on device 8:1.
[  190.154802] devtmpfs: mounted
[  190.154802] Freeing unused kernel memory: 3496K
[  190.154802] Kernel memory protection disabled.
[  190.154802] random: crng init done
[  190.154802] stty (1471) used greatest stack depth: 25080 bytes left
[  190.154802] EXT4-fs (sda1): re-mounted. Opts: (null)
`, `INFO: recovery required on readonly filesystem`, false,
		}, {
			`
[  190.154802] ==================================================================
[  190.154802] BUG: KASAN: slab-out-of-bounds in sg_remove_request+0x103/0x120 at addr ffff8801a85de8c0
[  190.154802] Read of size 8 by task syz-executor0/6860
[  190.154802] CPU: 0 PID: 6860 Comm: syz-executor0 Not tainted 4.9.58-g27155df #71
[  190.154802] Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011
[  190.154802]  ffff8801a2bf7a80 ffffffff81d91149 ffff8801d77fd3c0 ffff8801a85de880
[  190.154802]  ffff8801a85de8e0 ffffed00350bbd18 ffff8801a85de8c0 ffff8801a2bf7aa8
[  190.154802]  ffffffff8153c01c ffffed00350bbd18 ffff8801d77fd3c0 0000000000000000
[  190.154802] Call Trace:
[  190.154802]  [<ffffffff81d91149>] dump_stack+0xc1/0x128
[  190.154802]  [<ffffffff8153c01c>] kasan_object_err+0x1c/0x70
[  190.154802]  [<ffffffff8153c2dc>] kasan_report.part.1+0x21c/0x500
[  190.154802]  [<ffffffff8153c679>] __asan_report_load8_noabort+0x29/0x30
[  190.154802]  [<ffffffff8265fad3>] sg_remove_request+0x103/0x120
[  190.154802]  [<ffffffff82660055>] sg_finish_rem_req+0x295/0x340
[  190.154802]  [<ffffffff82661d8c>] sg_read+0x91c/0x1400
[  190.154802]  [<ffffffff8156c5f3>] __vfs_read+0x103/0x670
[  190.154802]  [<ffffffff8156db87>] vfs_read+0x107/0x330
[  190.154802]  [<ffffffff81571829>] SyS_read+0xd9/0x1b0
[  190.154802]  [<ffffffff838aa0c5>] entry_SYSCALL_64_fastpath+0x23/0xc6
[  190.154802] Object at ffff8801a85de880, in cache fasync_cache size: 96
[  190.154802] Allocated:
[  190.154802] PID = 0
[  190.154802] (stack is not available)
[  190.154802] Freed:
[  190.154802] PID = 0
[  190.154802] (stack is not available)
[  190.154802] Memory state around the buggy address:
[  190.154802]  ffff8801a85de780: 00 00 00 00 00 00 00 00 00 00 00 00 fc fc fc fc
[  190.154802]  ffff8801a85de800: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
[  190.154802] >ffff8801a85de880: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
[  190.154802]                                            ^
[  190.154802]  ffff8801a85de900: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
[  190.154802]  ffff8801a85de980: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
[  190.154802] ==================================================================
`, `KASAN: slab-out-of-bounds Read in sg_remove_request`, false,
		}, {
			`
[  190.154802] BUG: unable to handle kernel NULL pointer dereference at 0000000000000286
[  190.154802] IP: 0x286
[  190.154802] PGD 1d8d6a067 
[  190.154802] P4D 1d8d6a067 
[  190.154802] PUD 1d925e067 
[  190.154802] PMD 0 
[  190.154802] 
[  190.154802] Oops: 0010 [#1] SMP KASAN
[  190.154802] Dumping ftrace buffer:
[  190.154802]    (ftrace buffer empty)
[  190.154802] Modules linked in:
[  190.154802] CPU: 1 PID: 3289 Comm: kworker/u4:7 Not tainted 4.13.0-rc5-next-20170817+ #5
[  190.154802] Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011
[  190.154802] Workqueue: kstrp strp_work
[  190.154802] task: ffff8801c9d16540 task.stack: ffff8801ca570000
[  190.154802] RIP: 0010:0x286
[  190.154802] RSP: 0018:ffff8801ca577540 EFLAGS: 00010246
[  190.154802] RAX: dffffc0000000000 RBX: ffff8801cbbfad60 RCX: 0000000000000000
[  190.154802] RDX: 1ffff1003977f5bd RSI: ffffffff85b34380 RDI: ffff8801cbbfac48
[  190.154802] RBP: ffff8801ca577558 R08: 0000000000000000 R09: 0000000000000000
[  190.154802] R10: ffff8801ca577438 R11: dffffc0000000000 R12: ffff8801cbbfac48
[  190.154802] R13: ffff8801cb7ede18 R14: ffff8801ca577980 R15: ffff8801cb7ede00
[  190.154802] FS:  0000000000000000(0000) GS:ffff8801db300000(0000) knlGS:0000000000000000
[  190.154802] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[  190.154802] CR2: 0000000000000286 CR3: 00000001d91cf000 CR4: 00000000001426e0
[  190.154802] Call Trace:
[  190.154802]  process_one_work+0xbf3/0x1bc0
[  190.154802]  worker_thread+0x223/0x1860
[  190.154802]  kthread+0x35e/0x430
[  190.154802]  ret_from_fork+0x2a/0x40
[  190.154802] Code:  Bad RIP value.
[  190.154802] RIP: 0x286 RSP: ffff8801ca577540
[  190.154802] CR2: 0000000000000286
[  190.154802] ---[ end trace 05ef833e13705a0a ]---
[  190.154802] Kernel panic - not syncing: Fatal exception
[  190.154802] Dumping ftrace buffer:
[  190.154802]    (ftrace buffer empty)
[  190.154802] Kernel Offset: disabled
[  190.154802] Rebooting in 86400 seconds..
`, `BUG: unable to handle kernel NULL pointer dereference`, false,
		}, {
			`
[  292.653596] ------------[ cut here ]------------
[  292.658378] kernel BUG at ./include/linux/skbuff.h:2069!
[  292.664014] invalid opcode: 0000 [#1] SMP KASAN
[  292.668674] Dumping ftrace buffer:
[  292.672199]    (ftrace buffer empty)
[  292.675889] Modules linked in:
[  292.679059] CPU: 1 PID: 22157 Comm: syz-executor5 Not tainted 4.14.0+ #129
[  292.686052] Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011
[  292.695387] task: ffff8801d2fa8500 task.stack: ffff8801d9fd8000
[  292.701436] RIP: 0010:skb_pull+0xd5/0xf0
[  292.705473] RSP: 0018:ffff8801d9fdf270 EFLAGS: 00010216
[  292.710817] RAX: 0000000000010000 RBX: ffff8801d53b96c0 RCX: ffffffff84179df5
[  292.718070] RDX: 00000000000001d8 RSI: ffffc90001fce000 RDI: ffff8801d53b973c
[  292.725322] RBP: ffff8801d9fdf288 R08: 0000000000000002 R09: 0000000000000002
[  292.732568] R10: 0000000000000000 R11: ffffffff8747dd60 R12: 0000000000000028
[  292.739812] R13: 0000000000000064 R14: dffffc0000000000 R15: ffff8801d9e9588a
[  292.742848] sctp: [Deprecated]: syz-executor0 (pid 22154) Use of int in max_burst socket option deprecated.
[  292.742848] Use struct sctp_assoc_value instead
[  292.760875] sctp: [Deprecated]: syz-executor0 (pid 22154) Use of int in max_burst socket option deprecated.
[  292.760875] Use struct sctp_assoc_value instead
[  292.763163] ICMPv6: NA: bb:bb:bb:bb:bb:01 advertised our address fe80::1aa on syz1!
[  292.783582] FS:  00007ff4a3f4e700(0000) GS:ffff8801db500000(0000) knlGS:0000000000000000
[  292.791797] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[  292.797665] CR2: 0000000020000000 CR3: 00000001ca0fe000 CR4: 00000000001406e0
[  292.804920] DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
[  292.812170] DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
[  292.816510] ICMPv6: NA: bb:bb:bb:bb:bb:01 advertised our address fe80::1aa on syz1!
[  292.817577] sctp: [Deprecated]: syz-executor0 (pid 22198) Use of int in max_burst socket option deprecated.
[  292.817577] Use struct sctp_assoc_value instead
[  292.837972] sctp: [Deprecated]: syz-executor2 (pid 22199) Use of int in max_burst socket option deprecated.
[  292.837972] Use struct sctp_assoc_value instead
[  292.844964] sctp: [Deprecated]: syz-executor0 (pid 22198) Use of int in max_burst socket option deprecated.
[  292.844964] Use struct sctp_assoc_value instead
[  292.850158] sctp: [Deprecated]: syz-executor2 (pid 22199) Use of int in max_burst socket option deprecated.
[  292.850158] Use struct sctp_assoc_value instead
[  292.878797] sctp: [Deprecated]: syz-executor0 (pid 22205) Use of int in max_burst socket option deprecated.
[  292.878797] Use struct sctp_assoc_value instead
[  292.889594] sctp: [Deprecated]: syz-executor0 (pid 22205) Use of int in max_burst socket option deprecated.
[  292.889594] Use struct sctp_assoc_value instead
[  292.913387] Call Trace:
[  292.914495] sctp: [Deprecated]: syz-executor0 (pid 22212) Use of int in max_burst socket option deprecated.
[  292.914495] Use struct sctp_assoc_value instead
[  292.927906] sctp: [Deprecated]: syz-executor0 (pid 22212) Use of int in max_burst socket option deprecated.
[  292.927906] Use struct sctp_assoc_value instead
[  292.944692]  esp6_gro_receive+0xb4/0xbe0
...
[  293.162223]  SyS_writev+0x27/0x30
[  293.165649]  entry_SYSCALL_64_fastpath+0x1f/0x96
[  293.170388] RIP: 0033:0x452751
[  293.173544] RSP: 002b:00007ff4a3f4db10 EFLAGS: 00000293 ORIG_RAX: 0000000000000014
[  293.181220] RAX: ffffffffffffffda RBX: 0000000020000000 RCX: 0000000000452751
[  293.188464] RDX: 0000000000000002 RSI: 00007ff4a3f4db60 RDI: 0000000000000012
[  293.195706] RBP: 0000000000000086 R08: 0000000000000000 R09: 0000000000000000
[  293.202944] R10: 000000000000009a R11: 0000000000000293 R12: 00000000006f2608
[  293.210183] R13: 00000000ffffffff R14: 00007ff4a3f4e6d4 R15: 0000000000000000
[  293.217426] Code: a3 d0 00 00 00 e8 0c 55 58 fd 4c 89 e0 5b 41 5c 41 5d 5d c3 45 31 e4 e8 fa 54 58 fd 4c 89 e0 5b 41 5c 41 5d 5d c3 e8 eb 54 58 fd <0f> 0b e8 f4 d0 8e fd eb 9a e8 ed d0 8e fd e9 51 ff ff ff e8 03 
[  293.236495] RIP: skb_pull+0xd5/0xf0 RSP: ffff8801d9fdf270
[  293.242035] ---[ end trace d2d6da9d918cb453 ]---
`, `kernel BUG at ./include/linux/skbuff.h:LINE!`, false,
		}, {
			`
[  161.498638] =============================
[  161.506098] device gre0 entered promiscuous mode
[  161.575261] WARNING: suspicious RCU usage
[  161.587306] 4.14.0-next-20171127+ #53 Not tainted
[  161.631389] BUG: unable to handle kernel NULL pointer dereference at 0000000000000074
[  161.631414] IP: kfree+0xb2/0x250
[  161.631417] PGD 1cd9be067 P4D 1cd9be067 PUD 1c646d067 PMD 0 
[  161.631433] Oops: 0000 [#1] SMP KASAN
[  161.631440] Dumping ftrace buffer:
[  161.631445]    (ftrace buffer empty)
[  161.631448] Modules linked in:
[  161.631459] CPU: 1 PID: 17319 Comm: syz-executor7 Not tainted 4.14.0-next-20171127+ #53
[  161.631463] Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011
[  161.631468] task: ffff8801c5442040 task.stack: ffff8801c7ed8000
[  161.631478] RIP: 0010:kfree+0xb2/0x250
[  161.631482] RSP: 0018:ffff8801c7edf780 EFLAGS: 00010046
[  161.631489] RAX: 0000000000000000 RBX: ffff8801c7edf948 RCX: ffffffffffffffff
[  161.631494] RDX: ffffea00071fb7c0 RSI: 0000000000000000 RDI: ffff8801c7edf948
[  161.631499] RBP: ffff8801c7edf7a0 R08: ffffed003b02866c R09: 0000000000000000
[  161.631503] R10: 0000000000000001 R11: ffffed003b02866b R12: 0000000000000286
[  161.631508] R13: 0000000000000000 R14: ffff8801c7edf948 R15: ffff8801c7edf8b0
[  161.631514] FS:  00007ff14d179700(0000) GS:ffff8801db500000(0000) knlGS:0000000000000000
[  161.631519] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[  161.631524] CR2: 0000000000000074 CR3: 00000001c6768000 CR4: 00000000001426e0
[  161.631529] Call Trace:
[  161.631545]  blkcipher_walk_done+0x72b/0xde0
[  161.631565]  encrypt+0x50a/0xaf0
...
[  161.631991]  SyS_recvmsg+0x2d/0x50
[  161.632001]  entry_SYSCALL_64_fastpath+0x1f/0x96
[  161.632007] RIP: 0033:0x4529d9
[  161.632011] RSP: 002b:00007ff14d178c58 EFLAGS: 00000212 ORIG_RAX: 000000000000002f
[  161.632018] RAX: ffffffffffffffda RBX: 0000000000758190 RCX: 00000000004529d9
[  161.632022] RDX: 0000000000010000 RSI: 0000000020d63fc8 RDI: 0000000000000018
[  161.632026] RBP: 0000000000000086 R08: 0000000000000000 R09: 0000000000000000
[  161.632031] R10: 0000000000000000 R11: 0000000000000212 R12: 00000000006f2728
[  161.632035] R13: 00000000ffffffff R14: 00007ff14d1796d4 R15: 0000000000000000
[  161.632057] Code: c2 48 b8 00 00 00 00 00 ea ff ff 48 89 df 48 c1 ea 0c 48 c1 e2 06 48 01 c2 48 8b 42 20 48 8d 48 ff a8 01 48 0f 45 d1 4c 8b 6a 30 <49> 63 75 74 e8 b5 5c af ff 48 89 de 4c 89 ef 4c 8b 75 08 e8 76 
[  161.632230] RIP: kfree+0xb2/0x250 RSP: ffff8801c7edf780
[  161.632233] CR2: 0000000000000074
[  161.632243] ---[ end trace e3c719a9c9d01886 ]---
`, `suspicious RCU usage`, true,
		}, {
			`
[   76.640408] binder: undelivered TRANSACTION_ERROR: 29189
[   76.649866] [ BUG: bad unlock balance detected! ]
[   76.654695] 4.9.65-g8ae26d1 #98 Not tainted
[   76.658991] -------------------------------------
[   76.661695] FAULT_FLAG_ALLOW_RETRY missing 30
[   76.661705] CPU: 0 PID: 14413 Comm: syz-executor0 Not tainted 4.9.65-g8ae26d1 #98
[   76.661710] Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011
[   76.661725]  ffff8801ce46f9a0 ffffffff81d90469 ffff8801ce46fc80 0000000000000000
[   76.661737]  ffff8801ccd7ad10 ffff8801ce46fb70 ffff8801ccd7ac00 ffff8801ce46fb98
[   76.661749]  ffffffff8165e417 0000000000000282 ffff8801ce46faf0 00000001c52a4067
[   76.661751] Call Trace:
[   76.661765]  [<ffffffff81d90469>] dump_stack+0xc1/0x128
...
[   76.661991]  [<ffffffff838a9745>] entry_SYSCALL_64_fastpath+0x23/0xc6
[   76.693507] binder: 14407:14442 BC_DEAD_BINDER_DONE 0000000000000000 not found
[   76.694637] binder: 14407:14426 transaction failed 29189/-22, size 0-0 line 3007
[   76.882228] syz-executor2/14420 is trying to release lock (mrt_lock) at:
[   76.889259] [<ffffffff834dea24>] ipmr_mfc_seq_stop+0xe4/0x140
[   76.895105] but there are no more locks to release!
[   76.900080] 
[   76.900080] other info that might help us debug this:
[   76.906710] 2 locks held by syz-executor2/14420:
[   76.911425]  #0:  (&f->f_pos_lock){+.+.+.}, at: [<ffffffff815cf9ef>] __fdget_pos+0x9f/0xc0
[   76.920249]  #1:  (&p->lock){+.+.+.}, at: [<ffffffff815e4ded>] seq_read+0xdd/0x1290
[   76.928457] 
[   76.928457] stack backtrace:
[   76.932918] CPU: 1 PID: 14420 Comm: syz-executor2 Not tainted 4.9.65-g8ae26d1 #98
[   76.940499] Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011
[   76.949817]  ffff8801cef3f8e8 ffffffff81d90469 ffffffff849ae8b8 ffff8801c8344800
[   76.957769]  ffffffff834dea24 ffffffff849ae8b8 ffff8801c8345088 ffff8801cef3f918
[   76.965718]  ffffffff81235524 dffffc0000000000 ffffffff849ae8b8 00000000ffffffff
[   76.973663] Call Trace:
[   76.976220]  [<ffffffff81d90469>] dump_stack+0xc1/0x128
...
[   77.180814]  [<ffffffff838a9745>] entry_SYSCALL_64_fastpath+0x23/0xc6
`, `BUG: bad unlock balance in dump_stack`, true,
		}, {
			`
[  264.305036] =====================================
[  264.309846] [ BUG: bad unlock balance detected! ]
[  264.314656] 4.9.65-gea83e4a #95 Not tainted
[  264.318945] -------------------------------------
[  264.323751] syz-executor1/1081 is trying to release lock (mrt_lock) at:
[  264.330694] [<ffffffff834dea24>] ipmr_mfc_seq_stop+0xe4/0x140
[  264.336540] but there are no more locks to release!
[  264.341515] 
[  264.341515] other info that might help us debug this:
[  264.348145] 1 lock held by syz-executor1/1081:
[  264.352688]  #0:  (&p->lock){+.+.+.}, at: [<ffffffff815e4ded>] seq_read+0xdd/0x1290
[  264.360901] 
[  264.360901] stack backtrace:
[  264.365364] CPU: 1 PID: 1081 Comm: syz-executor1 Not tainted 4.9.65-gea83e4a #95
[  264.372860] Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011
[  264.382178]  ffff8801bd87f948 ffffffff81d90469 ffffffff849ae8b8 ffff8801be6c1800
[  264.390127]  ffffffff834dea24 ffffffff849ae8b8 ffff8801be6c2088 ffff8801bd87f978
[  264.398073]  ffffffff81235524 dffffc0000000000 ffffffff849ae8b8 00000000ffffffff
[  264.406014] Call Trace:
[  264.408566]  [<ffffffff81d90469>] dump_stack+0xc1/0x128
...
[  264.592630]  [<ffffffff838a9745>] entry_SYSCALL_64_fastpath+0x23/0xc6
`, `BUG: bad unlock balance in ipmr_mfc_seq_stop`, false,
		}, {
			`
syzkaller login: [   16.305150] INFO: trying to register non-static key.
[   16.305671] the code is fine but needs lockdep annotation.
[   16.306408] turning off the locking correctness validator.
[   16.306956] CPU: 0 PID: 2990 Comm: syzkaller460037 Not tainted 4.14.0-rc7-next-20171103+ #10
[   16.307782] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS Bochs 01/01/2011
[   16.308571] Call Trace:
[   16.308831]  dump_stack+0x194/0x257
[   16.309192]  ? arch_local_irq_restore+0x53/0x53
[   16.309657]  register_lock_class+0x55e/0x2c70
[   16.310347]  ? __lock_acquire+0x739/0x4770
[   16.315564]  ? find_held_lock+0x39/0x1d0
[   16.315964]  __lock_acquire+0x203/0x4770
[   16.316366]  ? find_held_lock+0x39/0x1d0
[   16.328281]  ? rcu_pm_notify+0xc0/0xc0
[   16.328665]  lock_acquire+0x1d5/0x580
[   16.330805]  ? tcp_fastopen_reset_cipher+0x194/0x580
[   16.331306]  _raw_spin_lock_bh+0x31/0x40
[   16.331707]  ? tcp_fastopen_reset_cipher+0x194/0x580
[   16.332206]  tcp_fastopen_reset_cipher+0x194/0x580
[   16.332690]  ? tcp_fastopen_ctx_destroy+0x220/0x220
[   16.342778]  entry_SYSCALL_64_fastpath+0x1f/0xbe
[   16.343239] RIP: 0033:0x434e69
[   16.343553] RSP: 002b:00007ffebc51ad98 EFLAGS: 00000203 ORIG_RAX: 0000000000000036
[   16.344298] RAX: ffffffffffffffda RBX: 00000000004002b0 RCX: 0000000000434e69
[   16.345003] RDX: 0000000000000021 RSI: 0000000000000006 RDI: 0000000000000003
[   16.345704] RBP: 0000000000000086 R08: 0000000000000010 R09: 0000000000000000
[   16.346826] R10: 0000000020f2b000 R11: 0000000000000203 R12: 0000000000000000
[   16.347531] R13: 00000000004017e0 R14: 0000000000401870 R15: 0000000000000000
`, `INFO: trying to register non-static key in tcp_fastopen_reset_cipher`, false,
		}, {
			`
[   47.711290] ==================================================================
[   47.712178] INFO: trying to register non-static key.
[   47.712195] the code is fine but needs lockdep annotation.
[   47.712204] turning off the locking correctness validator.
[   47.712264] CPU: 1 PID: 0 Comm: swapper/1 Not tainted 4.13.0-rc6-next-20170825+ #9
[   47.712270] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS Bochs 01/01/2011
[   47.712271] Call Trace:
[   47.712273]  <IRQ>
[   47.712281]  dump_stack+0x194/0x257
[   47.712441]  register_lock_class+0x55e/0x2c70
[   47.712696]  __lock_acquire+0x203/0x4620
[   47.713005]  lock_acquire+0x1d5/0x580
[   47.713035]  _raw_spin_lock_bh+0x31/0x40
[   47.713045]  tun_flow_cleanup+0xf4/0x300
`, `INFO: trying to register non-static key in tun_flow_cleanup`, false,
		},
	}
	testParse(t, "linux", tests)
}

func TestLinuxIgnores(t *testing.T) {
	reporter, err := NewReporter("linux", "", "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ignores1 := []*regexp.Regexp{
		regexp.MustCompile("BUG: bug3"),
	}
	reporter1, err := NewReporter("linux", "", "", nil, ignores1)
	if err != nil {
		t.Fatal(err)
	}
	ignores2 := []*regexp.Regexp{
		regexp.MustCompile("BUG: bug3"),
		regexp.MustCompile("BUG: bug1"),
	}
	reporter2, err := NewReporter("linux", "", "", nil, ignores2)
	if err != nil {
		t.Fatal(err)
	}
	ignores3 := []*regexp.Regexp{
		regexp.MustCompile("BUG: bug3"),
		regexp.MustCompile("BUG: bug1"),
		regexp.MustCompile("BUG: bug2"),
	}
	reporter3, err := NewReporter("linux", "", "", nil, ignores3)
	if err != nil {
		t.Fatal(err)
	}

	const log = `
[    0.000000] BUG: bug1
[    0.000000] BUG: bug2
	`
	if !reporter.ContainsCrash([]byte(log)) {
		t.Fatalf("no crash")
	}
	if rep := reporter.Parse([]byte(log)); rep.Title != "BUG: bug1" {
		t.Fatalf("want `BUG: bug1`, found `%v`", rep.Title)
	}

	if !reporter1.ContainsCrash([]byte(log)) {
		t.Fatalf("no crash")
	}
	if rep := reporter1.Parse([]byte(log)); rep.Title != "BUG: bug1" {
		t.Fatalf("want `BUG: bug1`, found `%v`", rep.Title)
	}

	if !reporter2.ContainsCrash([]byte(log)) {
		t.Fatalf("no crash")
	}
	if rep := reporter2.Parse([]byte(log)); rep.Title != "BUG: bug2" {
		t.Fatalf("want `BUG: bug2`, found `%v`", rep.Title)
	}

	if reporter3.ContainsCrash([]byte(log)) {
		t.Fatalf("found crash, should be ignored")
	}
	if rep := reporter3.Parse([]byte(log)); rep != nil {
		t.Fatalf("found `%v`, should be ignored", rep.Title)
	}
}

func TestLinuxParseText(t *testing.T) {
	tests := map[string]string{
		`mmap(&(0x7f00008dd000/0x1000)=nil, (0x1000), 0x3, 0x32, 0xffffffffffffffff, 0x0)
getsockopt$NETROM_N2(r2, 0x103, 0x3, &(0x7f00008de000-0x4)=0x1, &(0x7f00008dd000)=0x4)
[  522.560667] nla_parse: 5 callbacks suppressed
[  522.565344] netlink: 3 bytes leftover after parsing attributes in process 'syz-executor5'.
[  536.429346] NMI watchdog: BUG: soft lockup - CPU#1 stuck for 11s! [syz-executor7:16813]
mmap(&(0x7f0000557000/0x2000)=nil, (0x2000), 0x1, 0x11, r2, 0x1b)
[  536.437530] Modules linked in:
[  536.440808] CPU: 1 PID: 16813 Comm: syz-executor7 Not tainted 4.3.5-smp-DEV #119`: `nla_parse: 5 callbacks suppressed
netlink: 3 bytes leftover after parsing attributes in process 'syz-executor5'.
NMI watchdog: BUG: soft lockup - CPU#1 stuck for 11s! [syz-executor7:16813]
Modules linked in:
CPU: 1 PID: 16813 Comm: syz-executor7 Not tainted 4.3.5-smp-DEV #119
`,

		// Raw 'dmesg -r' and /proc/kmsg output.
		`<6>[   85.501187] WARNING: foo
<6>[   85.501187] nouveau  [     DRM] suspending kernel object tree...
executing program 1:
<6>[   85.525111] nouveau  [     DRM] nouveau suspended
<14>[   85.912347] init: computing context for service 'clear-bcb'`: `WARNING: foo
nouveau  [     DRM] suspending kernel object tree...
nouveau  [     DRM] nouveau suspended
init: computing context for service 'clear-bcb'
`,

		`[   94.864848] line 0
[   94.864848] line 1
[   94.864848] line 2
[   94.864848] line 3
[   94.864848] line 4
[   94.864848] line 5
[   95.145581] ==================================================================
[   95.152992] BUG: KASAN: use-after-free in snd_seq_queue_alloc+0x670/0x690 at addr ffff8801d0c6b080
[   95.162080] Read of size 4 by task syz-executor2/5764`: `line 2
line 3
line 4
line 5
==================================================================
BUG: KASAN: use-after-free in snd_seq_queue_alloc+0x670/0x690 at addr ffff8801d0c6b080
Read of size 4 by task syz-executor2/5764
`,
	}
	reporter, err := NewReporter("linux", "", "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for log, text0 := range tests {
		if rep := reporter.Parse([]byte(log)); string(rep.Report) != text0 {
			t.Logf("log:\n%s", log)
			t.Logf("want text:\n%s", text0)
			t.Logf("got text:\n%s", rep.Report)
			t.Fatalf("bad text, desc: '%v'", rep.Title)
		}
	}
}

func TestLinuxSymbolizeLine(t *testing.T) {
	tests := []struct {
		line   string
		result string
	}{
		// Normal symbolization.
		{
			"[ 2713.153531]  [<ffffffff82d1b1d9>] foo+0x101/0x185\n",
			"[ 2713.153531]  [<ffffffff82d1b1d9>] foo+0x101/0x185 foo.c:555\n",
		},
		{
			"RIP: 0010:[<ffffffff8188c0e6>]  [<ffffffff8188c0e6>]  foo+0x101/0x185\n",
			"RIP: 0010:[<ffffffff8188c0e6>]  [<ffffffff8188c0e6>]  foo+0x101/0x185 foo.c:555\n",
		},
		// Strip "./" file prefix.
		{
			"[ 2713.153531]  [<ffffffff82d1b1d9>] foo+0x111/0x185\n",
			"[ 2713.153531]  [<ffffffff82d1b1d9>] foo+0x111/0x185 foo.h:111\n",
		},
		// Needs symbolization, but symbolizer returns nothing.
		{
			"[ 2713.153531]  [<ffffffff82d1b1d9>] foo+0x121/0x185\n",
			"[ 2713.153531]  [<ffffffff82d1b1d9>] foo+0x121/0x185\n",
		},
		// Needs symbolization, but symbolizer returns error.
		{
			"[ 2713.153531]  [<ffffffff82d1b1d9>] foo+0x131/0x185\n",
			"[ 2713.153531]  [<ffffffff82d1b1d9>] foo+0x131/0x185\n",
		},
		// Needs symbolization, but symbol is missing.
		{
			"[ 2713.153531]  [<ffffffff82d1b1d9>] bar+0x131/0x185\n",
			"[ 2713.153531]  [<ffffffff82d1b1d9>] bar+0x131/0x185\n",
		},
		// Bad offset.
		{
			"[ 2713.153531]  [<ffffffff82d1b1d9>] bar+0xffffffffffffffffffff/0x185\n",
			"[ 2713.153531]  [<ffffffff82d1b1d9>] bar+0xffffffffffffffffffff/0x185\n",
		},
		// Should not be symbolized.
		{
			"WARNING: CPU: 2 PID: 2636 at ipc/shm.c:162 foo+0x101/0x185\n",
			"WARNING: CPU: 2 PID: 2636 at ipc/shm.c:162 foo+0x101/0x185 foo.c:555\n",
		},
		// Tricky function name.
		{
			"    [<ffffffff84e5bea0>] do_ipv6_setsockopt.isra.7.part.3+0x101/0x2830 \n",
			"    [<ffffffff84e5bea0>] do_ipv6_setsockopt.isra.7.part.3+0x101/0x2830 net.c:111 \n",
		},
		// Old KASAN frame format (with tab).
		{
			"[   50.419727] 	baz+0x101/0x200\n",
			"[   50.419727] 	baz+0x101/0x200 baz.c:100\n",
		},
		// Inlined frames.
		{
			"    [<ffffffff84e5bea0>] foo+0x141/0x185\n",
			"    [<ffffffff84e5bea0>] inlined1 net.c:111 [inline]\n" +
				"    [<ffffffff84e5bea0>] inlined2 mm.c:222 [inline]\n" +
				"    [<ffffffff84e5bea0>] foo+0x141/0x185 kasan.c:333\n",
		},
		// Several symbols with the same name.
		{
			"[<ffffffff82d1b1d9>] baz+0x101/0x200\n",
			"[<ffffffff82d1b1d9>] baz+0x101/0x200 baz.c:100\n",
		},
	}
	symbols := map[string][]symbolizer.Symbol{
		"foo": []symbolizer.Symbol{
			{Addr: 0x1000000, Size: 0x190},
		},
		"do_ipv6_setsockopt.isra.7.part.3": []symbolizer.Symbol{
			{Addr: 0x2000000, Size: 0x2830},
		},
		"baz": []symbolizer.Symbol{
			{Addr: 0x3000000, Size: 0x100},
			{Addr: 0x4000000, Size: 0x200},
			{Addr: 0x5000000, Size: 0x300},
		},
	}
	symb := func(bin string, pc uint64) ([]symbolizer.Frame, error) {
		if bin != "vmlinux" {
			return nil, fmt.Errorf("unknown pc 0x%x", pc)
		}
		switch pc {
		case 0x1000100:
			return []symbolizer.Frame{
				{
					File: "/linux/foo.c",
					Line: 555,
				},
			}, nil
		case 0x1000110:
			return []symbolizer.Frame{
				{
					File: "/linux/./foo.h",
					Line: 111,
				},
			}, nil
		case 0x1000120:
			return nil, nil
		case 0x1000130:
			return nil, fmt.Errorf("unknown pc 0x%x", pc)
		case 0x2000100:
			return []symbolizer.Frame{
				{
					File: "/linux/net.c",
					Line: 111,
				},
			}, nil
		case 0x1000140:
			return []symbolizer.Frame{
				{
					Func:   "inlined1",
					File:   "/linux/net.c",
					Line:   111,
					Inline: true,
				},
				{
					Func:   "inlined2",
					File:   "/linux/mm.c",
					Line:   222,
					Inline: true,
				},
				{
					Func:   "noninlined3",
					File:   "/linux/kasan.c",
					Line:   333,
					Inline: false,
				},
			}, nil
		case 0x4000100:
			return []symbolizer.Frame{
				{
					File: "/linux/baz.c",
					Line: 100,
				},
			}, nil
		default:
			return nil, fmt.Errorf("unknown pc 0x%x", pc)
		}
	}
	for i, test := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			result := symbolizeLine(symb, symbols, "vmlinux", "/linux/", []byte(test.line))
			if test.result != string(result) {
				t.Errorf("want %q\n\t     get %q", test.result, string(result))
			}
		})
	}
}

func TestLinuxParseReport(t *testing.T) {
	reporter, err := NewReporter("linux", "", "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i, test := range parseReportTests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			rep := reporter.Parse([]byte(test.in))
			if test.out != string(rep.Report) {
				t.Logf("expect:\n%v", test.out)
				t.Logf("got:\n%v", string(rep.Report))
				t.Fail()
			}
		})
	}
}

var parseReportTests = []struct {
	in  string
	out string
}{
	// Test that we strip the report after "Kernel panic - not syncing" line.
	{
		in: `clock_gettime(0x0, &(0x7f0000475000-0x10)={<r2=>0x0, <r3=>0x0})
write$sndseq(0xffffffffffffffff, &(0x7f0000929000-0x150)=[{0x3197a6bf, 0x0, 0x4, 0x100, @tick=0x6, {0x7, 0x6c}, {0x2, 0x9}, @connect={{0x1ff, 0x1}, {0x3ff, 0x118c}}}, {0x100000000, 0x2, 0xfffffffffffffffa, 0x2, @tick=0x5d0, {0xf556, 0x7}, {0x3, 0x1000}, @quote={{0x5, 0xfffffffffffffff7}, 0x401, &(0x7f000084a000)={0x10000, 0x9d, 0x8, 0x4, @tick=0x336f, {0x5, 0x1d}, {0x8, 0x7}, @time=@time={0x0, 0x989680}}}}, {0x200, 0x0, 0x99a, 0x6, @tick=0x1, {0x1, 0x158}, {0x200, 0x5}, @connect={{0x8, 0x4}, {0xf2, 0x100000000}}}, {0x40, 0xfffffffffffffffa, 0x100000000, 0x5, @time={r2, r3+10000000}, {0x7, 0x5}, {0x3, 0x0}, @raw32={[0x2, 0x225, 0x1]}}, {0x75f, 0x8, 0x80, 0x80, @tick=0x6, {0x9, 0x9}, {0x1, 0x6}, @queue={0x7, {0x7, 0x6}}}, {0x80, 0x6, 0x3f, 0x80000001, @time={0x0, 0x0}, {0x3f, 0x9}, {0x96, 0xfffffffffffff800}, @raw8={"e5660e9238e6f58b35448e94"}}, {0x6, 0x6f8, 0x3, 0x6, @time={0x77359400, 0x0}, {0x100000001, 0x0}, {0xe870, 0x7}, @connect={{0x4, 0x80}, {0x7ff, 0xfffffffffffffffa}}}], 0x150)
open$dir(&(0x7f0000265000-0x8)="2e2f66696c653000", 0x400, 0x44)
[   96.237449] blk_update_request: I/O error, dev loop0, sector 0
[   96.255274] ==================================================================
[   96.262735] BUG: KASAN: double-free or invalid-free in selinux_tun_dev_free_security+0x15/0x20
[   96.271481] 
[   96.273098] CPU: 0 PID: 11514 Comm: syz-executor5 Not tainted 4.12.0-rc7+ #2
[   96.280268] Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011
[   96.289602] Call Trace:
[   96.292180]  dump_stack+0x194/0x257
[   96.295796]  ? arch_local_irq_restore+0x53/0x53
[   96.300454]  ? load_image_and_restore+0x10f/0x10f
[   96.305299]  ? selinux_tun_dev_free_security+0x15/0x20
[   96.310565]  print_address_description+0x7f/0x260
[   96.315393]  ? selinux_tun_dev_free_security+0x15/0x20
[   96.320656]  ? selinux_tun_dev_free_security+0x15/0x20
[   96.325919]  kasan_report_double_free+0x55/0x80
[   96.330577]  kasan_slab_free+0xa0/0xc0
[   96.334450]  kfree+0xd3/0x260
[   96.337545]  selinux_tun_dev_free_security+0x15/0x20
[   96.342636]  security_tun_dev_free_security+0x48/0x80
[   96.347822]  __tun_chr_ioctl+0x2cc1/0x3d60
[   96.352054]  ? tun_chr_close+0x60/0x60
[   96.355925]  ? lock_downgrade+0x990/0x990
[   96.360059]  ? lock_release+0xa40/0xa40
[   96.364025]  ? __lock_is_held+0xb6/0x140
[   96.368213]  ? check_same_owner+0x320/0x320
[   96.372530]  ? tun_chr_compat_ioctl+0x30/0x30
[   96.377005]  tun_chr_ioctl+0x2a/0x40
[   96.380701]  ? tun_chr_ioctl+0x2a/0x40
[   96.385099]  do_vfs_ioctl+0x1b1/0x15c0
[   96.388981]  ? ioctl_preallocate+0x2d0/0x2d0
[   96.393378]  ? selinux_capable+0x40/0x40
[   96.397430]  ? SyS_futex+0x2b0/0x3a0
[   96.401147]  ? security_file_ioctl+0x89/0xb0
[   96.405547]  SyS_ioctl+0x8f/0xc0
[   96.408912]  entry_SYSCALL_64_fastpath+0x1f/0xbe
[   96.413651] RIP: 0033:0x4512c9
[   96.416824] RSP: 002b:00007fc65827bc08 EFLAGS: 00000216 ORIG_RAX: 0000000000000010
[   96.424603] RAX: ffffffffffffffda RBX: 0000000000718000 RCX: 00000000004512c9
[   96.431863] RDX: 000000002053c000 RSI: 00000000400454ca RDI: 0000000000000005
[   96.439133] RBP: 0000000000000082 R08: 0000000000000000 R09: 0000000000000000
[   96.446389] R10: 0000000000000000 R11: 0000000000000216 R12: 00000000004baa97
[   96.453647] R13: 00000000ffffffff R14: 0000000020124ff3 R15: 0000000000000000
[   96.460931] 
[   96.462552] Allocated by task 11514:
[   96.466258]  save_stack_trace+0x16/0x20
[   96.470212]  save_stack+0x43/0xd0
[   96.473649]  kasan_kmalloc+0xaa/0xd0
[   96.477347]  kmem_cache_alloc_trace+0x101/0x6f0
[   96.481995]  selinux_tun_dev_alloc_security+0x49/0x170
[   96.487250]  security_tun_dev_alloc_security+0x6d/0xa0
[   96.492508]  __tun_chr_ioctl+0x16bc/0x3d60
[   96.496722]  tun_chr_ioctl+0x2a/0x40
[   96.500417]  do_vfs_ioctl+0x1b1/0x15c0
[   96.504282]  SyS_ioctl+0x8f/0xc0
[   96.507630]  entry_SYSCALL_64_fastpath+0x1f/0xbe
[   96.512367] 
[   96.513973] Freed by task 11514:
[   96.517323]  save_stack_trace+0x16/0x20
[   96.521276]  save_stack+0x43/0xd0
[   96.524709]  kasan_slab_free+0x6e/0xc0
[   96.528577]  kfree+0xd3/0x260
[   96.531666]  selinux_tun_dev_free_security+0x15/0x20
[   96.536747]  security_tun_dev_free_security+0x48/0x80
[   96.541918]  tun_free_netdev+0x13b/0x1b0
[   96.545959]  register_netdevice+0x8d0/0xee0
[   96.550260]  __tun_chr_ioctl+0x1bae/0x3d60
[   96.554475]  tun_chr_ioctl+0x2a/0x40
[   96.558169]  do_vfs_ioctl+0x1b1/0x15c0
[   96.562035]  SyS_ioctl+0x8f/0xc0
[   96.565385]  entry_SYSCALL_64_fastpath+0x1f/0xbe
[   96.570116] 
[   96.571724] The buggy address belongs to the object at ffff8801d5961a40
[   96.571724]  which belongs to the cache kmalloc-32 of size 32
[   96.584186] The buggy address is located 0 bytes inside of
[   96.584186]  32-byte region [ffff8801d5961a40, ffff8801d5961a60)
[   96.595775] The buggy address belongs to the page:
[   96.600686] page:ffffea00066b8d38 count:1 mapcount:0 mapping:ffff8801d5961000 index:0xffff8801d5961fc1
[   96.610118] flags: 0x200000000000100(slab)
[   96.614335] raw: 0200000000000100 ffff8801d5961000 ffff8801d5961fc1 000000010000003f
[   96.622292] raw: ffffea0006723300 ffffea00066738b8 ffff8801dbc00100
[   96.628675] page dumped because: kasan: bad access detected
[   96.634373] 
[   96.635978] Memory state around the buggy address:
[   96.640884]  ffff8801d5961900: 00 00 01 fc fc fc fc fc 00 00 00 fc fc fc fc fc
[   96.648222]  ffff8801d5961980: 00 00 00 00 fc fc fc fc fb fb fb fb fc fc fc fc
[   96.655567] >ffff8801d5961a00: 00 00 00 fc fc fc fc fc fb fb fb fb fc fc fc fc
[   96.663255]                                            ^
[   96.668685]  ffff8801d5961a80: fb fb fb fb fc fc fc fc 00 00 00 fc fc fc fc fc
[   96.676022]  ffff8801d5961b00: 04 fc fc fc fc fc fc fc fb fb fb fb fc fc fc fc
[   96.683357] ==================================================================
[   96.690692] Disabling lock debugging due to kernel taint
[   96.696117] Kernel panic - not syncing: panic_on_warn set ...
[   96.696117] 
[   96.703470] CPU: 0 PID: 11514 Comm: syz-executor5 Tainted: G    B           4.12.0-rc7+ #2
[   96.711847] Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011
[   96.721354] Call Trace:
[   96.723926]  dump_stack+0x194/0x257
[   96.727539]  ? arch_local_irq_restore+0x53/0x53
[   96.732366]  ? kasan_end_report+0x32/0x50
[   96.736497]  ? lock_downgrade+0x990/0x990
[   96.740631]  panic+0x1e4/0x3fb
[   96.743807]  ? percpu_up_read_preempt_enable.constprop.38+0xae/0xae
[   96.750194]  ? add_taint+0x40/0x50
[   96.753723]  ? selinux_tun_dev_free_security+0x15/0x20
[   96.758976]  ? selinux_tun_dev_free_security+0x15/0x20
[   96.764233]  kasan_end_report+0x50/0x50
[   96.768192]  kasan_report_double_free+0x72/0x80
[   96.772843]  kasan_slab_free+0xa0/0xc0
[   96.776711]  kfree+0xd3/0x260
[   96.779802]  selinux_tun_dev_free_security+0x15/0x20
[   96.784886]  security_tun_dev_free_security+0x48/0x80
[   96.790061]  __tun_chr_ioctl+0x2cc1/0x3d60
[   96.794285]  ? tun_chr_close+0x60/0x60
[   96.798152]  ? lock_downgrade+0x990/0x990
[   96.802803]  ? lock_release+0xa40/0xa40
[   96.806763]  ? __lock_is_held+0xb6/0x140
[   96.810829]  ? check_same_owner+0x320/0x320
[   96.815137]  ? tun_chr_compat_ioctl+0x30/0x30
[   96.819611]  tun_chr_ioctl+0x2a/0x40
[   96.823306]  ? tun_chr_ioctl+0x2a/0x40
[   96.827181]  do_vfs_ioctl+0x1b1/0x15c0
[   96.831057]  ? ioctl_preallocate+0x2d0/0x2d0
[   96.835450]  ? selinux_capable+0x40/0x40
[   96.839494]  ? SyS_futex+0x2b0/0x3a0
[   96.843200]  ? security_file_ioctl+0x89/0xb0
[   96.847590]  SyS_ioctl+0x8f/0xc0
[   96.850941]  entry_SYSCALL_64_fastpath+0x1f/0xbe
[   96.855676] RIP: 0033:0x4512c9
[   96.859020] RSP: 002b:00007fc65827bc08 EFLAGS: 00000216 ORIG_RAX: 0000000000000010
[   96.866708] RAX: ffffffffffffffda RBX: 0000000000718000 RCX: 00000000004512c9
[   96.873956] RDX: 000000002053c000 RSI: 00000000400454ca RDI: 0000000000000005
[   96.881208] RBP: 0000000000000082 R08: 0000000000000000 R09: 0000000000000000
[   96.888461] R10: 0000000000000000 R11: 0000000000000216 R12: 00000000004baa97
[   96.895708] R13: 00000000ffffffff R14: 0000000020124ff3 R15: 0000000000000000
[   96.903943] Dumping ftrace buffer:
[   96.907460]    (ftrace buffer empty)
[   96.911148] Kernel Offset: disabled
[   96.914753] Rebooting in 86400 seconds..`,
		out: `blk_update_request: I/O error, dev loop0, sector 0
==================================================================
BUG: KASAN: double-free or invalid-free in selinux_tun_dev_free_security+0x15/0x20

CPU: 0 PID: 11514 Comm: syz-executor5 Not tainted 4.12.0-rc7+ #2
Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011
Call Trace:
 dump_stack+0x194/0x257
 print_address_description+0x7f/0x260
 kasan_report_double_free+0x55/0x80
 kasan_slab_free+0xa0/0xc0
 kfree+0xd3/0x260
 selinux_tun_dev_free_security+0x15/0x20
 security_tun_dev_free_security+0x48/0x80
 __tun_chr_ioctl+0x2cc1/0x3d60
 tun_chr_ioctl+0x2a/0x40
 do_vfs_ioctl+0x1b1/0x15c0
 SyS_ioctl+0x8f/0xc0
 entry_SYSCALL_64_fastpath+0x1f/0xbe
RIP: 0033:0x4512c9
RSP: 002b:00007fc65827bc08 EFLAGS: 00000216 ORIG_RAX: 0000000000000010
RAX: ffffffffffffffda RBX: 0000000000718000 RCX: 00000000004512c9
RDX: 000000002053c000 RSI: 00000000400454ca RDI: 0000000000000005
RBP: 0000000000000082 R08: 0000000000000000 R09: 0000000000000000
R10: 0000000000000000 R11: 0000000000000216 R12: 00000000004baa97
R13: 00000000ffffffff R14: 0000000020124ff3 R15: 0000000000000000

Allocated by task 11514:
 save_stack_trace+0x16/0x20
 save_stack+0x43/0xd0
 kasan_kmalloc+0xaa/0xd0
 kmem_cache_alloc_trace+0x101/0x6f0
 selinux_tun_dev_alloc_security+0x49/0x170
 security_tun_dev_alloc_security+0x6d/0xa0
 __tun_chr_ioctl+0x16bc/0x3d60
 tun_chr_ioctl+0x2a/0x40
 do_vfs_ioctl+0x1b1/0x15c0
 SyS_ioctl+0x8f/0xc0
 entry_SYSCALL_64_fastpath+0x1f/0xbe

Freed by task 11514:
 save_stack_trace+0x16/0x20
 save_stack+0x43/0xd0
 kasan_slab_free+0x6e/0xc0
 kfree+0xd3/0x260
 selinux_tun_dev_free_security+0x15/0x20
 security_tun_dev_free_security+0x48/0x80
 tun_free_netdev+0x13b/0x1b0
 register_netdevice+0x8d0/0xee0
 __tun_chr_ioctl+0x1bae/0x3d60
 tun_chr_ioctl+0x2a/0x40
 do_vfs_ioctl+0x1b1/0x15c0
 SyS_ioctl+0x8f/0xc0
 entry_SYSCALL_64_fastpath+0x1f/0xbe

The buggy address belongs to the object at ffff8801d5961a40
 which belongs to the cache kmalloc-32 of size 32
The buggy address is located 0 bytes inside of
 32-byte region [ffff8801d5961a40, ffff8801d5961a60)
The buggy address belongs to the page:
page:ffffea00066b8d38 count:1 mapcount:0 mapping:ffff8801d5961000 index:0xffff8801d5961fc1
flags: 0x200000000000100(slab)
raw: 0200000000000100 ffff8801d5961000 ffff8801d5961fc1 000000010000003f
raw: ffffea0006723300 ffffea00066738b8 ffff8801dbc00100
page dumped because: kasan: bad access detected

Memory state around the buggy address:
 ffff8801d5961900: 00 00 01 fc fc fc fc fc 00 00 00 fc fc fc fc fc
 ffff8801d5961980: 00 00 00 00 fc fc fc fc fb fb fb fb fc fc fc fc
>ffff8801d5961a00: 00 00 00 fc fc fc fc fc fb fb fb fb fc fc fc fc
                                           ^
 ffff8801d5961a80: fb fb fb fb fc fc fc fc 00 00 00 fc fc fc fc fc
 ffff8801d5961b00: 04 fc fc fc fc fc fc fc fb fb fb fb fc fc fc fc
==================================================================
`,
	},

	// Test that we don't strip the report after "Kernel panic - not syncing" line
	// because we have too few lines before it.
	{
		in: `2017/06/30 10:13:30 executing program 1:
mmap(&(0x7f0000000000/0xd000)=nil, (0xd000), 0x2000001, 0x4012, 0xffffffffffffffff, 0x0)
r0 = socket$inet6_sctp(0xa, 0x205, 0x84)
mmap(&(0x7f000000d000/0x1000)=nil, (0x1000), 0x3, 0x32, 0xffffffffffffffff, 0x0)
r1 = openat$autofs(0xffffffffffffff9c, &(0x7f000000d000)="2f6465762f6175746f667300", 0x472440, 0x0)
mmap(&(0x7f000000d000/0x1000)=nil, (0x1000), 0x3, 0x32, 0xffffffffffffffff, 0x0)
ioctl$KVM_CREATE_DEVICE(r1, 0xc00caee0, &(0x7f000000d000)={0x3, r0, 0x0})
setsockopt$inet_sctp6_SCTP_I_WANT_MAPPED_V4_ADDR(r0, 0x84, 0xc, &(0x7f0000007000)=0x1, 0x4)
setsockopt$inet_sctp6_SCTP_ASSOCINFO(r0, 0x84, 0x1, &(0x7f0000ece000)={0x0, 0x20, 0x0, 0x7, 0x0, 0x0}, 0x14)
[   55.950418] ------------[ cut here ]------------
[   55.967976] WARNING: CPU: 1 PID: 8377 at arch/x86/kvm/x86.c:7209 kvm_arch_vcpu_ioctl_run+0x1f7/0x5a00
[   56.041277] Kernel panic - not syncing: panic_on_warn set ...
[   56.041277] 
[   56.048693] CPU: 1 PID: 8377 Comm: syz-executor6 Not tainted 4.12.0-rc7+ #2
[   56.055794] Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011
[   56.065137] Call Trace:
[   56.067707]  dump_stack+0x194/0x257
[   56.071334]  ? arch_local_irq_restore+0x53/0x53
[   56.076017]  panic+0x1e4/0x3fb
[   56.079188]  ? percpu_up_read_preempt_enable.constprop.38+0xae/0xae
[   56.085571]  ? load_image_and_restore+0x10f/0x10f
[   56.090396]  ? __warn+0x1a9/0x1e0
[   56.093850]  ? kvm_arch_vcpu_ioctl_run+0x1f7/0x5a00
[   56.098863]  __warn+0x1c4/0x1e0
[   56.102131]  ? kvm_arch_vcpu_ioctl_run+0x1f7/0x5a00
[   56.107126]  report_bug+0x211/0x2d0
[   56.110735]  fixup_bug+0x40/0x90
[   56.114123]  do_trap+0x260/0x390
[   56.117481]  do_error_trap+0x120/0x390
[   56.121352]  ? do_trap+0x390/0x390
[   56.124875]  ? kvm_arch_vcpu_ioctl_run+0x1f7/0x5a00
[   56.129868]  ? fpu__activate_curr+0xed/0x650
[   56.134251]  ? futex_wait_setup+0x14a/0x3d0
[   56.138551]  ? fpstate_init+0x160/0x160
[   56.142510]  ? trace_hardirqs_off_thunk+0x1a/0x1c
[   56.147324]  ? vcpu_load+0x1c/0x70
[   56.150845]  do_invalid_op+0x1b/0x20
[   56.154533]  invalid_op+0x1e/0x30
[   56.157961] RIP: 0010:kvm_arch_vcpu_ioctl_run+0x1f7/0x5a00
[   56.163554] RSP: 0018:ffff8801c5e37720 EFLAGS: 00010212
[   56.168891] RAX: 0000000000010000 RBX: ffff8801c8baa000 RCX: ffffc90004763000
[   56.176134] RDX: 0000000000000052 RSI: ffffffff810de507 RDI: ffff8801c6358f60
[   56.183377] RBP: ffff8801c5e37a80 R08: 1ffffffff097c151 R09: 0000000000000001
[   56.190621] R10: 0000000000000000 R11: ffffffff81066ddc R12: 0000000000000000
[   56.197865] R13: ffff8801c52be780 R14: ffff8801c65be600 R15: ffff8801c6358d40
[   56.205118]  ? vcpu_load+0x1c/0x70
[   56.208636]  ? kvm_arch_vcpu_ioctl_run+0x1f7/0x5a00
[   56.213644]  ? debug_check_no_locks_freed+0x3c0/0x3c0
[   56.218815]  ? drop_futex_key_refs.isra.12+0x63/0xb0
[   56.223894]  ? futex_wait+0x6cf/0xa00
[   56.227671]  ? kvm_arch_vcpu_runnable+0x520/0x520
[   56.232513]  ? vmcs_load+0xb3/0x180
[   56.236115]  ? kvm_arch_has_assigned_device+0x57/0xe0
[   56.241280]  ? kvm_arch_end_assignment+0x20/0x20
[   56.246008]  ? futex_wait_setup+0x3d0/0x3d0
[   56.250303]  ? lock_downgrade+0x990/0x990
[   56.254430]  ? vmx_vcpu_load+0x63f/0xa30
[   56.258468]  ? handle_invept+0x5f0/0x5f0
[   56.262505]  ? get_futex_key+0x1c10/0x1c10
[   56.266721]  ? kvm_arch_vcpu_load+0x4b0/0x8f0
[   56.271193]  ? kvm_arch_dev_ioctl+0x490/0x490
[   56.275663]  ? task_rq_unlock+0x90/0x90
[   56.279615]  ? up_write+0x6b/0x120
[   56.283141]  kvm_vcpu_ioctl+0x627/0x1110
[   56.287176]  ? kvm_vcpu_ioctl+0x627/0x1110
[   56.291393]  ? vcpu_stat_get_per_vm_open+0x30/0x30
[   56.296298]  ? find_held_lock+0x35/0x1d0
[   56.300342]  ? __fget+0x333/0x570
[   56.303777]  ? lock_downgrade+0x990/0x990
[   56.307907]  ? lock_release+0xa40/0xa40
[   56.311866]  ? __lock_is_held+0xb6/0x140
[   56.315916]  ? __fget+0x35c/0x570
[   56.319349]  ? iterate_fd+0x3f0/0x3f0
[   56.323135]  ? vcpu_stat_get_per_vm_open+0x30/0x30
[   56.328041]  do_vfs_ioctl+0x1b1/0x15c0
[   56.331907]  ? ioctl_preallocate+0x2d0/0x2d0
[   56.336292]  ? selinux_capable+0x40/0x40
[   56.340332]  ? SyS_futex+0x2b0/0x3a0
[   56.344032]  ? security_file_ioctl+0x89/0xb0
[   56.348420]  SyS_ioctl+0x8f/0xc0
[   56.351776]  entry_SYSCALL_64_fastpath+0x1f/0xbe
[   56.356509] RIP: 0033:0x4512c9
[   56.359673] RSP: 002b:00007f7e59d4fc08 EFLAGS: 00000216 ORIG_RAX: 0000000000000010
[   56.367353] RAX: ffffffffffffffda RBX: 0000000000718000 RCX: 00000000004512c9
[   56.374598] RDX: 0000000000000000 RSI: 000000000000ae80 RDI: 0000000000000016
[   56.381841] RBP: 0000000000000082 R08: 0000000000000000 R09: 0000000000000000
[   56.389084] R10: 0000000000000000 R11: 0000000000000216 R12: 00000000004b93f0
[   56.396328] R13: 00000000ffffffff R14: 0000000020000000 R15: 0000000000ffa000
[   56.404665] Dumping ftrace buffer:
[   56.408256]    (ftrace buffer empty)
[   56.411940] Kernel Offset: disabled
[   56.415543] Rebooting in 86400 seconds..
`,
		out: `------------[ cut here ]------------
WARNING: CPU: 1 PID: 8377 at arch/x86/kvm/x86.c:7209 kvm_arch_vcpu_ioctl_run+0x1f7/0x5a00
Kernel panic - not syncing: panic_on_warn set ...

CPU: 1 PID: 8377 Comm: syz-executor6 Not tainted 4.12.0-rc7+ #2
Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011
Call Trace:
 dump_stack+0x194/0x257
 panic+0x1e4/0x3fb
 __warn+0x1c4/0x1e0
 report_bug+0x211/0x2d0
 fixup_bug+0x40/0x90
 do_trap+0x260/0x390
 do_error_trap+0x120/0x390
 do_invalid_op+0x1b/0x20
 invalid_op+0x1e/0x30
RIP: 0010:kvm_arch_vcpu_ioctl_run+0x1f7/0x5a00
RSP: 0018:ffff8801c5e37720 EFLAGS: 00010212
RAX: 0000000000010000 RBX: ffff8801c8baa000 RCX: ffffc90004763000
RDX: 0000000000000052 RSI: ffffffff810de507 RDI: ffff8801c6358f60
RBP: ffff8801c5e37a80 R08: 1ffffffff097c151 R09: 0000000000000001
R10: 0000000000000000 R11: ffffffff81066ddc R12: 0000000000000000
R13: ffff8801c52be780 R14: ffff8801c65be600 R15: ffff8801c6358d40
 kvm_vcpu_ioctl+0x627/0x1110
 do_vfs_ioctl+0x1b1/0x15c0
 SyS_ioctl+0x8f/0xc0
 entry_SYSCALL_64_fastpath+0x1f/0xbe
RIP: 0033:0x4512c9
RSP: 002b:00007f7e59d4fc08 EFLAGS: 00000216 ORIG_RAX: 0000000000000010
RAX: ffffffffffffffda RBX: 0000000000718000 RCX: 00000000004512c9
RDX: 0000000000000000 RSI: 000000000000ae80 RDI: 0000000000000016
RBP: 0000000000000082 R08: 0000000000000000 R09: 0000000000000000
R10: 0000000000000000 R11: 0000000000000216 R12: 00000000004b93f0
R13: 00000000ffffffff R14: 0000000020000000 R15: 0000000000ffa000
Dumping ftrace buffer:
   (ftrace buffer empty)
Kernel Offset: disabled
Rebooting in 86400 seconds..
`,
	},
}

func TestLinuxGuilty(t *testing.T) {
	tests := map[string]string{
		`
==================================================================
BUG: KASAN: use-after-free in ip6_send_skb+0x2f5/0x330 net/ipv6/ip6_output.c:1748
Read of size 8 at addr ffff88004fab1858 by task syz-executor0/30168

CPU: 0 PID: 30168 Comm: syz-executor0 Not tainted 4.12.0-rc3+ #3
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS Bochs 01/01/2011
Call Trace:
 __dump_stack lib/dump_stack.c:16 [inline]
 dump_stack+0x292/0x395 lib/dump_stack.c:52
 print_address_description+0x78/0x280 mm/kasan/report.c:252
 kasan_report_error mm/kasan/report.c:351 [inline]
 kasan_report+0x230/0x340 mm/kasan/report.c:408
 __asan_report_load8_noabort+0x19/0x20 mm/kasan/report.c:429
 ip6_send_skb+0x2f5/0x330 net/ipv6/ip6_output.c:1748
 ip6_push_pending_frames+0xb8/0xe0 net/ipv6/ip6_output.c:1763
 rawv6_push_pending_frames net/ipv6/raw.c:613 [inline]
 rawv6_sendmsg+0x2ede/0x4400 net/ipv6/raw.c:932
 inet_sendmsg+0x169/0x5c0 net/ipv4/af_inet.c:762
 sock_sendmsg_nosec net/socket.c:633 [inline]
 sock_sendmsg+0xcf/0x110 net/socket.c:643
 SYSC_sendto+0x660/0x810 net/socket.c:1696
 SyS_sendto+0x45/0x60 net/socket.c:1664
 entry_SYSCALL_64_fastpath+0x1f/0xbe
RIP: 0033:0x446179
RSP: 002b:00007f1f48124c08 EFLAGS: 00000286 ORIG_RAX: 000000000000002c
RAX: ffffffffffffffda RBX: 0000000000004350 RCX: 0000000000446179
RDX: 0000000000000873 RSI: 0000000020fd878d RDI: 0000000000000016
RBP: 00000000ffffffff R08: 00000000204e8fe4 R09: 000000000000001c
R10: 0000000000000840 R11: 0000000000000286 R12: 0000000000000016
R13: 0000000000000000 R14: 00007f1f481259c0 R15: 00007f1f48125700
`: `net/ipv6/ip6_output.c`,
		`
DEBUG_LOCKS_WARN_ON(class_idx > MAX_LOCKDEP_KEYS)
------------[ cut here ]------------
WARNING: CPU: 2 PID: 24023 at kernel/locking/lockdep.c:3344 __lock_acquire+0x10e5/0x3690 kernel/locking/lockdep.c:3344
Kernel panic - not syncing: panic_on_warn set ...

CPU: 2 PID: 24023 Comm: syz-executor1 Not tainted 4.12.0-rc3+ #370
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS Bochs 01/01/2011
Call Trace:
 __dump_stack lib/dump_stack.c:16 [inline]
 dump_stack+0x292/0x395 lib/dump_stack.c:52
 panic+0x1cb/0x3a9 kernel/panic.c:180
 __warn+0x1c4/0x1e0 kernel/panic.c:541
 report_bug+0x211/0x2d0 lib/bug.c:183
 fixup_bug arch/x86/kernel/traps.c:190 [inline]
 do_trap_no_signal arch/x86/kernel/traps.c:224 [inline]
 do_trap+0x32c/0x410 arch/x86/kernel/traps.c:273
 do_error_trap+0x15a/0x3e0 arch/x86/kernel/traps.c:310
 do_invalid_op+0x1b/0x20 arch/x86/kernel/traps.c:323
 invalid_op+0x1e/0x30 arch/x86/entry/entry_64.S:844
RIP: 0010:__lock_acquire+0x10e5/0x3690 kernel/locking/lockdep.c:3344
RSP: 0018:ffff88005aba6100 EFLAGS: 00010086
RAX: 0000000000000031 RBX: ffff880058995b40 RCX: 0000000000000000
RDX: 0000000000000031 RSI: ffffffff81458577 RDI: ffffed000b574c12
RBP: ffff88005aba6640 R08: 0000000000000001 R09: 0000000000000001
R10: ffff8800589963a0 R11: fffffbfff0e0fc7a R12: 0000000000000000
R13: 0000000000000010 R14: 0000000000000001 R15: 0000000000000010
 lock_acquire+0x22d/0x560 kernel/locking/lockdep.c:3855
 seqcount_lockdep_reader_access include/linux/seqlock.h:80 [inline]
 read_seqcount_begin include/linux/seqlock.h:163 [inline]
 read_seqbegin include/linux/seqlock.h:433 [inline]
 neigh_hh_output include/net/neighbour.h:456 [inline]
 neigh_output include/net/neighbour.h:477 [inline]
 ip6_finish_output2+0x109a/0x2540 net/ipv6/ip6_output.c:123
 ip6_finish_output+0x302/0x930 net/ipv6/ip6_output.c:149
 NF_HOOK_COND include/linux/netfilter.h:246 [inline]
 ip6_output+0x1c2/0x8a0 net/ipv6/ip6_output.c:163
 ip6_xmit+0xd38/0x21c0 include/net/dst.h:492
 inet6_csk_xmit+0x331/0x600 net/ipv6/inet6_connection_sock.c:139
 tcp_transmit_skb+0x1ad8/0x3460 net/ipv4/tcp_output.c:1055
 tcp_connect+0x2195/0x2f30 net/ipv4/tcp_output.c:3381
 tcp_v6_connect+0x1c0b/0x20f0 net/ipv6/tcp_ipv6.c:304
 __inet_stream_connect+0x2ee/0xf90 net/ipv4/af_inet.c:618
 inet_stream_connect+0x58/0xa0 net/ipv4/af_inet.c:682
 SYSC_connect+0x251/0x590 net/socket.c:1588
 SyS_connect+0x24/0x30 net/socket.c:1569
 entry_SYSCALL_64_fastpath+0x1f/0xbe
RIP: 0033:0x446179
RSP: 002b:00007fb738f47c08 EFLAGS: 00000286 ORIG_RAX: 000000000000002a
RAX: ffffffffffffffda RBX: 0000000000000400 RCX: 0000000000446179
RDX: 000000000000001c RSI: 0000000020411000 RDI: 0000000000000005
RBP: 00000000ffffffff R08: 0000000000000000 R09: 0000000000000000
R10: 0000000000000000 R11: 0000000000000286 R12: 0000000000000005
R13: 0000000000000000 R14: 00007fb738f489c0 R15: 00007fb738f48700
Dumping ftrace buffer:
   (ftrace buffer empty)
Kernel Offset: disabled
Rebooting in 86400 seconds..
`: `net/ipv6/ip6_output.c`,
		`
kasan: CONFIG_KASAN_INLINE enabled
kasan: GPF could be caused by NULL-ptr deref or user memory access
general protection fault: 0000 [#1] SMP KASAN
Dumping ftrace buffer:
   (ftrace buffer empty)
Modules linked in:
CPU: 2 PID: 10785 Comm: kworker/2:4 Not tainted 4.12.0-rc3+ #370
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS Bochs 01/01/2011
Workqueue: events bpf_map_free_deferred
task: ffff880061ce9700 task.stack: ffff880060b40000
RIP: 0010:pcpu_addr_to_page mm/percpu-vm.c:358 [inline]
RIP: 0010:pcpu_chunk_addr_search mm/percpu.c:852 [inline]
RIP: 0010:free_percpu+0x189/0x4a0 mm/percpu.c:1264
RSP: 0018:ffff880060b47188 EFLAGS: 00010002
RAX: 0000000000000000 RBX: 1ffff1000c168e34 RCX: 0000000000000002
RDX: dffffc0000000000 RSI: 000000000ca9ca67 RDI: 0000000000000010
RBP: ffff880060b47328 R08: 0000000000000002 R09: 8a21721700000000
R10: ffff880061ce9f38 R11: dffffc0000000000 R12: ffff88007ffee210
R13: ffff880060b47300 R14: ffff88003ec00000 R15: ffffe8fcd0a1c608
FS:  0000000000000000(0000) GS:ffff88006de00000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 00000000006e7680 CR3: 000000002e973000 CR4: 00000000000006e0
Call Trace:
 htab_free_elems+0x191/0x250 kernel/bpf/hashtab.c:112
 prealloc_destroy+0x17/0x90 kernel/bpf/hashtab.c:191
 htab_map_free+0xe6/0x650 kernel/bpf/hashtab.c:1093
 bpf_map_free_deferred+0xac/0xd0 kernel/bpf/syscall.c:124
 process_one_work+0xc03/0x1bd0 kernel/workqueue.c:2097
 worker_thread+0x223/0x1860 kernel/workqueue.c:2231
 kthread+0x35e/0x430 kernel/kthread.c:231
 ret_from_fork+0x2a/0x40 arch/x86/entry/entry_64.S:424
Code: 80 3c 02 00 0f 85 e0 02 00 00 49 8b 3c 24 4c 01 ff e8 ec be 06 00 48 8d 78 10 48 ba 00 00 00 00 00 fc ff df 48 89 f9 48 c1 e9 03 <80> 3c 11 00 0f 85 c2 02 00 00 4c 8b 60 10 48 b8 00 00 00 00 00 
RIP: pcpu_addr_to_page mm/percpu-vm.c:358 [inline] RSP: ffff880060b47188
RIP: pcpu_chunk_addr_search mm/percpu.c:852 [inline] RSP: ffff880060b47188
RIP: free_percpu+0x189/0x4a0 mm/percpu.c:1264 RSP: ffff880060b47188
---[ end trace 2faa26575ba6ca1f ]---
Kernel panic - not syncing: Fatal exception
Dumping ftrace buffer:
   (ftrace buffer empty)
Kernel Offset: disabled
Rebooting in 86400 seconds..
`: `kernel/bpf/hashtab.c`,
		`
kasan: CONFIG_KASAN_INLINE enabled
kasan: GPF could be caused by NULL-ptr deref or user memory access
general protection fault: 0000 [#1] SMP KASAN
Dumping ftrace buffer:
   (ftrace buffer empty)
Modules linked in:
CPU: 3 PID: 5124 Comm: kworker/3:3 Not tainted 4.12.0-rc3+ #370
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS Bochs 01/01/2011
Workqueue: events bpf_map_free_deferred
task: ffff880065321700 task.stack: ffff880065380000
RIP: 0010:css_put include/linux/cgroup.h:354 [inline]
RIP: 0010:cgroup_put include/linux/cgroup.h:373 [inline]
RIP: 0010:cgroup_fd_array_put_ptr+0x88/0x370 kernel/bpf/arraymap.c:535
RSP: 0018:ffff880065387378 EFLAGS: 00010202
RAX: 000000002000000d RBX: 1ffff1000ca70e71 RCX: 1ffffffff0a1912c
RDX: 0000000000000000 RSI: 1ffff1000ca643e6 RDI: 0000000100000069
RBP: ffff880065387450 R08: ffffffff85b0b9e0 R09: 0000000000000000
R10: 0000000000000000 R11: 0000000000000000 R12: 00000000fffffffd
R13: ffff880065387428 R14: dffffc0000000000 R15: ffffffff850c8920
FS:  0000000000000000(0000) GS:ffff88006df00000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 0000000020014000 CR3: 00000000231ae000 CR4: 00000000000006e0
Call Trace:
 fd_array_map_delete_elem kernel/bpf/arraymap.c:374 [inline]
 bpf_fd_array_map_clear+0x144/0x260 kernel/bpf/arraymap.c:410
 cgroup_fd_array_free+0x15/0x20 kernel/bpf/arraymap.c:540
 bpf_map_free_deferred+0xac/0xd0 kernel/bpf/syscall.c:124
 process_one_work+0xc03/0x1bd0 kernel/workqueue.c:2097
 worker_thread+0x223/0x1860 kernel/workqueue.c:2231
 kthread+0x35e/0x430 kernel/kthread.c:231
 ret_from_fork+0x2a/0x40 arch/x86/entry/entry_64.S:424
Code: 04 00 f2 f2 f2 c7 40 08 f2 f2 f2 f2 c7 40 0c 00 f2 f2 f2 c7 40 10 f3 f3 f3 f3 e8 a4 dc f0 ff 49 8d 7c 24 6c 48 89 f8 48 c1 e8 03 <42> 0f b6 14 30 48 89 f8 83 e0 07 83 c0 03 38 d0 7c 08 84 d2 0f 
RIP: css_put include/linux/cgroup.h:354 [inline] RSP: ffff880065387378
RIP: cgroup_put include/linux/cgroup.h:373 [inline] RSP: ffff880065387378
RIP: cgroup_fd_array_put_ptr+0x88/0x370 kernel/bpf/arraymap.c:535 RSP: ffff880065387378
---[ end trace 6192ca3b51b170a8 ]---
Kernel panic - not syncing: Fatal exception
Dumping ftrace buffer:
   (ftrace buffer empty)
Kernel Offset: disabled
Rebooting in 86400 seconds..
`: `kernel/bpf/arraymap.c`,
		`
------------[ cut here ]------------
WARNING: CPU: 1 PID: 4961 at lib/refcount.c:150 refcount_inc+0x47/0x50 lib/refcount.c:150
Kernel panic - not syncing: panic_on_warn set ...

CPU: 1 PID: 4961 Comm: syz-executor1 Not tainted 4.12.0-rc2+ #77
Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011
Call Trace:
 __dump_stack lib/dump_stack.c:16 [inline]
 dump_stack+0x2ee/0x3ea lib/dump_stack.c:52
 panic+0x1fb/0x412 kernel/panic.c:180
 __warn+0x1c4/0x1e0 kernel/panic.c:541
 report_bug+0x211/0x2d0 lib/bug.c:183
 fixup_bug arch/x86/kernel/traps.c:190 [inline]
 do_trap_no_signal arch/x86/kernel/traps.c:224 [inline]
 do_trap+0x32c/0x410 arch/x86/kernel/traps.c:273
 do_error_trap+0x15a/0x3b0 arch/x86/kernel/traps.c:310
 do_invalid_op+0x1b/0x20 arch/x86/kernel/traps.c:323
 invalid_op+0x1e/0x30 arch/x86/entry/entry_64.S:847
RIP: 0010:refcount_inc+0x47/0x50 lib/refcount.c:150
RSP: 0018:ffff8801d3d4fcc0 EFLAGS: 00010282
RAX: 000000000000002b RBX: ffff8801c2514240 RCX: 0000000000000000
RDX: 000000000000002b RSI: ffffc90002fb8000 RDI: ffffed003a7a9f8a
RBP: ffff8801d3d4fcc8 R08: 1ffff1003a7a9e71 R09: 0000000000000000
R10: dffffc0000000000 R11: 0000000000000000 R12: 1ffff1003a7a9fa0
R13: 000000001fd29e67 R14: 000000001fd29e67 R15: ffff8801c2514240
 __key_get include/linux/key.h:254 [inline]
 key_lookup+0x1ec/0x230 security/keys/key.c:670
 lookup_user_key+0x8ba/0x11e0 security/keys/process_keys.c:680
 keyctl_keyring_link+0x24/0xc0 security/keys/keyctl.c:507
 SYSC_keyctl security/keys/keyctl.c:1661 [inline]
 SyS_keyctl+0x1af/0x290 security/keys/keyctl.c:1633
 entry_SYSCALL_64_fastpath+0x1f/0xbe
RIP: 0033:0x44fe99
RSP: 002b:00007f93b93c9b58 EFLAGS: 00000212 ORIG_RAX: 00000000000000fa
RAX: ffffffffffffffda RBX: ffffffffffffffff RCX: 000000000044fe99
RDX: 000000001fd29e67 RSI: ffffffffffffffff RDI: 0000000000000008
RBP: 0000000000000008 R08: 0000000000000000 R09: 0000000000000000
R10: 0000000000000000 R11: 0000000000000212 R12: 00000000007180a8
R13: 0000000000001000 R14: 0000000000000003 R15: 0000000000000000
Dumping ftrace buffer:
   (ftrace buffer empty)
Kernel Offset: 0x6000000 from 0xffffffff81000000 (relocation range: 0xffffffff80000000-0xffffffffbfffffff)
Rebooting in 86400 seconds..
`: `security/keys/key.c`,
		`
kasan: GPF could be caused by NULL-ptr deref or user memory access
general protection fault: 0000 [#1] SMP KASAN
Dumping ftrace buffer:
   (ftrace buffer empty)
Modules linked in:
CPU: 1 PID: 14551 Comm: syz-executor0 Not tainted 4.12.0-rc1+ #366
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS Bochs 01/01/2011
task: ffff880028ceadc0 task.stack: ffff880038460000
RIP: 0010:__read_once_size include/linux/compiler.h:254 [inline]
RIP: 0010:raw_seqcount_begin include/linux/seqlock.h:183 [inline]
RIP: 0010:__d_lookup_rcu+0x27b/0xa10 fs/dcache.c:2144
RSP: 0018:ffff880038466d18 EFLAGS: 00010a03
RAX: 1fff6a12b169980b RBX: 1ffff1000708cdc2 RCX: ffffc90000abd000
RDX: 00000000000001b4 RSI: ffffffff819034c6 RDI: 0000000000000a06
RBP: ffff880038466ef8 R08: ffffffff8590ba60 R09: ffff880038466b20
R10: 0000000000000000 R11: 0000000000000000 R12: 000000004cfffffb
R13: fffb50958b4cc05d R14: dffffc0000000000 R15: fffb50958b4cc085
FS:  00007f63f0717700(0000) GS:ffff88003ed00000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 000000002000fff8 CR3: 0000000027bd5000 CR4: 00000000000006e0
Call Trace:
 lookup_fast+0x12c/0xf80 fs/namei.c:1554
 walk_component+0x129/0x13e0 fs/namei.c:1780
 lookup_last fs/namei.c:2252 [inline]
 path_lookupat+0x1d7/0xbc0 fs/namei.c:2302
 filename_lookup+0x29e/0x5b0 fs/namei.c:2336
 kern_path+0x33/0x40 fs/namei.c:2425
 bpf_obj_do_get kernel/bpf/inode.c:305 [inline]
 bpf_obj_get_user+0x11f/0xdd0 kernel/bpf/inode.c:340
 bpf_obj_get kernel/bpf/syscall.c:888 [inline]
 SYSC_bpf kernel/bpf/syscall.c:1061 [inline]
 SyS_bpf+0xdc2/0x3a80 kernel/bpf/syscall.c:997
 entry_SYSCALL_64_fastpath+0x1f/0xbe
RIP: 0033:0x445e89
RSP: 002b:00007f63f0716b58 EFLAGS: 00000296 ORIG_RAX: 0000000000000141
RAX: ffffffffffffffda RBX: 0000000000000007 RCX: 0000000000445e89
RDX: 0000000000000010 RSI: 0000000020005ff0 RDI: 0000000000000007
RBP: 00000000006e0370 R08: 0000000000000000 R09: 0000000000000000
R10: 0000000000000000 R11: 0000000000000296 R12: 0000000000708000
R13: 4000000000080000 R14: 0000000000000000 R15: 0000000000000000
Code: 89 bd 18 ff ff ff 42 c6 04 33 f8 0f 84 33 04 00 00 e8 da fc ca ff 48 8b 85 b0 fe ff ff 4d 8d 6f d8 c6 00 04 4c 89 e8 48 c1 e8 03 <42> 0f b6 0c 30 4c 89 e8 83 e0 07 83 c0 03 38 c8 7c 08 84 c9 0f 
RIP: __read_once_size include/linux/compiler.h:254 [inline] RSP: ffff880038466d18
RIP: raw_seqcount_begin include/linux/seqlock.h:183 [inline] RSP: ffff880038466d18
RIP: __d_lookup_rcu+0x27b/0xa10 fs/dcache.c:2144 RSP: ffff880038466d18
---[ end trace cc5c09f1eb5b005a ]---
Kernel panic - not syncing: Fatal exception
Dumping ftrace buffer:
   (ftrace buffer empty)
Kernel Offset: disabled
Rebooting in 86400 seconds..
`: `fs/dcache.c`,
		`
==================================================================
BUG: KASAN: use-after-free in ip6_dst_store include/net/ip6_fib.h:176 [inline]
BUG: KASAN: use-after-free in tcp_v6_connect+0x1dfd/0x20f0 net/ipv6/tcp_ipv6.c:271
Read of size 4 at addr ffff880066df126c by task syz-executor6/22754

CPU: 0 PID: 22754 Comm: syz-executor6 Not tainted 4.12.0-rc1+ #366
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS Bochs 01/01/2011
Call Trace:
 __dump_stack lib/dump_stack.c:16 [inline]
 dump_stack+0x292/0x395 lib/dump_stack.c:52
 print_address_description+0x73/0x280 mm/kasan/report.c:252
 kasan_report_error mm/kasan/report.c:351 [inline]
 kasan_report+0x22b/0x340 mm/kasan/report.c:408
 __asan_report_load4_noabort+0x14/0x20 mm/kasan/report.c:428
 ip6_dst_store include/net/ip6_fib.h:176 [inline]
 tcp_v6_connect+0x1dfd/0x20f0 net/ipv6/tcp_ipv6.c:271
 __inet_stream_connect+0x2ee/0xf90 net/ipv4/af_inet.c:618
 inet_stream_connect+0x58/0xa0 net/ipv4/af_inet.c:682
 SYSC_connect+0x251/0x590 net/socket.c:1588
 SyS_connect+0x24/0x30 net/socket.c:1569
 entry_SYSCALL_64_fastpath+0x1f/0xbe
RIP: 0033:0x445e89
RSP: 002b:00007fc98a723b58 EFLAGS: 00000286 ORIG_RAX: 000000000000002a
RAX: ffffffffffffffda RBX: 0000000000000016 RCX: 0000000000445e89
RDX: 000000000000001c RSI: 0000000020066000 RDI: 0000000000000016
RBP: 00000000006e04c0 R08: 0000000000000000 R09: 0000000000000000
R10: 0000000000000000 R11: 0000000000000286 R12: 00000000007081f8
R13: 0000000000000000 R14: 00007fc98a7249c0 R15: 00007fc98a724700
`: `net/ipv6/tcp_ipv6.c`,
		`
------------[ cut here ]------------
WARNING: CPU: 1 PID: 23686 at net/core/dev.c:2444 skb_warn_bad_offload+0x2c0/0x3a0 net/core/dev.c:2439()
lo: caps=(0x00000014401b7c69, 0x0000000000000000) len=246 data_len=0 gso_size=35328 gso_type=4 ip_summed=0
Kernel panic - not syncing: panic_on_warn set ...

CPU: 1 PID: 23686 Comm: syz-executor0 Not tainted 4.4.64+ #26
Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011
 0000000000000001 ffff8801d8a674b8 ffffffff81bfd89c ffffffff82a382a0
 ffff8801d8a67590 ffffffff82c2f040 0000000000000009 ffff8801d8a67580
 ffffffff813a0073 0000000041b58ab3 ffffffff82d52827 ffffffff8139fed1
Call Trace:
 [<ffffffff81bfd89c>] __dump_stack lib/dump_stack.c:15 [inline]
 [<ffffffff81bfd89c>] dump_stack+0x80/0xb4 lib/dump_stack.c:51
 [<ffffffff813a0073>] panic+0x1a2/0x347 kernel/panic.c:115
 [<ffffffff810e209a>] warn_slowpath_common+0x12a/0x140 kernel/panic.c:463
 [<ffffffff810e2160>] warn_slowpath_fmt+0xb0/0xe0 kernel/panic.c:479
 [<ffffffff8217e980>] skb_warn_bad_offload+0x2c0/0x3a0 net/core/dev.c:2439
 [<ffffffff8218cc64>] __skb_gso_segment+0x3c4/0x4b0 net/core/dev.c:2596
 [<ffffffff8218d883>] skb_gso_segment include/linux/netdevice.h:3702 [inline]
 [<ffffffff8218d883>] validate_xmit_skb.isra.102.part.103+0x453/0x980 net/core/dev.c:2804
 [<ffffffff821902eb>] validate_xmit_skb include/linux/spinlock.h:347 [inline]
 [<ffffffff821902eb>] __dev_queue_xmit+0x133b/0x1550 net/core/dev.c:3173
 [<ffffffff8219051c>] dev_queue_xmit+0x1c/0x20 net/core/dev.c:3215
 [<ffffffff8278c519>] packet_snd net/packet/af_packet.c:2825 [inline]
 [<ffffffff8278c519>] packet_sendmsg+0x2959/0x4950 net/packet/af_packet.c:2850
 [<ffffffff821260af>] sock_sendmsg_nosec net/socket.c:611 [inline]
 [<ffffffff821260af>] sock_sendmsg+0xcf/0x110 net/socket.c:621
 [<ffffffff82127c49>] ___sys_sendmsg+0x6f9/0x810 net/socket.c:1947
 [<ffffffff82129590>] __sys_sendmsg+0xd0/0x180 net/socket.c:1981
 [<ffffffff82129672>] SYSC_sendmsg net/socket.c:1992 [inline]
 [<ffffffff82129672>] SyS_sendmsg+0x32/0x50 net/socket.c:1988
 [<ffffffff828ab96e>] entry_SYSCALL_64_fastpath+0x12/0x6d
Dumping ftrace buffer:
   (ftrace buffer empty)
Kernel Offset: disabled
`: `net/packet/af_packet.c`,
		`
==================================================================
BUG: KASAN: use-after-free in dst_check include/net/dst.h:498 [inline]
BUG: KASAN: use-after-free in tcp_v4_early_demux+0x967/0xa60 net/ipv4/tcp_ipv4.c:1480
Read of size 8 at addr ffff8800397d2fe0 by task syz-executor0/4289

CPU: 0 PID: 4289 Comm: syz-executor0 Not tainted 4.12.0-rc1+ #366
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS Bochs 01/01/2011
Call Trace:
 <IRQ>
 __dump_stack lib/dump_stack.c:16 [inline]
 dump_stack+0x292/0x395 lib/dump_stack.c:52
 print_address_description+0x73/0x280 mm/kasan/report.c:252
 kasan_report_error mm/kasan/report.c:351 [inline]
 kasan_report+0x22b/0x340 mm/kasan/report.c:408
 __asan_report_load8_noabort+0x14/0x20 mm/kasan/report.c:429
 dst_check include/net/dst.h:498 [inline]
 tcp_v4_early_demux+0x967/0xa60 net/ipv4/tcp_ipv4.c:1480
 ip_rcv_finish+0x1941/0x2110 net/ipv4/ip_input.c:334
sctp: [Deprecated]: syz-executor7 (pid 4299) Use of struct sctp_assoc_value in delayed_ack socket option.
Use struct sctp_sack_info instead
 NF_HOOK include/linux/netfilter.h:257 [inline]
 ip_rcv+0xd8c/0x19c0 net/ipv4/ip_input.c:488
 __netif_receive_skb_core+0x1ad1/0x3400 net/core/dev.c:4216
 __netif_receive_skb+0x2c/0x1b0 net/core/dev.c:4254
 netif_receive_skb_internal+0x240/0x1b20 net/core/dev.c:4416
 napi_skb_finish net/core/dev.c:4773 [inline]
 napi_gro_receive+0x4e6/0x680 net/core/dev.c:4807
 e1000_receive_skb drivers/net/ethernet/intel/e1000/e1000_main.c:4018 [inline]
 e1000_clean_rx_irq+0x5e0/0x1490 drivers/net/ethernet/intel/e1000/e1000_main.c:4474
 e1000_clean+0xb9a/0x28f0 drivers/net/ethernet/intel/e1000/e1000_main.c:3819
 napi_poll net/core/dev.c:5407 [inline]
 net_rx_action+0xe7a/0x18f0 net/core/dev.c:5473
 __do_softirq+0x2fb/0xb99 kernel/softirq.c:284
 invoke_softirq kernel/softirq.c:364 [inline]
 irq_exit+0x19e/0x1d0 kernel/softirq.c:405
 exiting_irq arch/x86/include/asm/apic.h:652 [inline]
 smp_apic_timer_interrupt+0x76/0xa0 arch/x86/kernel/apic/apic.c:966
 apic_timer_interrupt+0x93/0xa0 arch/x86/entry/entry_64.S:484
RIP: 0033:0x449783
RSP: 002b:00007ffde3d48590 EFLAGS: 00000202 ORIG_RAX: ffffffffffffff10
RAX: 00000000006e6bc0 RBX: 0000000000000001 RCX: 0000000000000040
RDX: 0000000000000001 RSI: 0000000000a640a0 RDI: 00007ffb7ef3a700
RBP: 0000000000000000 R08: 000000000139cda0 R09: 0000000000000012
R10: 0000000000020022 R11: 0000000000000201 R12: 00007ffde3d486c0
R13: 0000000000000000 R14: 0000000000000444 R15: 0000000000a640c8
 </IRQ>
`: `net/ipv4/tcp_ipv4.c`,
		`
==================================================================
BUG: KMSAN: use of unitialized memory in rtnl_fdb_dump+0x5dc/0x1000
CPU: 0 PID: 1039 Comm: probe Not tainted 4.11.0-rc5+ #2727
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS Bochs 01/01/2011
Call Trace:
 __dump_stack lib/dump_stack.c:16
 dump_stack+0x143/0x1b0 lib/dump_stack.c:52
 kmsan_report+0x12a/0x180 mm/kmsan/kmsan.c:1007
 __kmsan_warning_32+0x66/0xb0 mm/kmsan/kmsan_instr.c:491
 rtnl_fdb_dump+0x5dc/0x1000 net/core/rtnetlink.c:3230
 netlink_dump+0x84f/0x1190 net/netlink/af_netlink.c:2168
 __netlink_dump_start+0xc97/0xe50 net/netlink/af_netlink.c:2258
 netlink_dump_start ./include/linux/netlink.h:165
 rtnetlink_rcv_msg+0xae9/0xb40 net/core/rtnetlink.c:4094
 netlink_rcv_skb+0x339/0x5a0 net/netlink/af_netlink.c:2339
 rtnetlink_rcv+0x83/0xa0 net/core/rtnetlink.c:4110
 netlink_unicast_kernel net/netlink/af_netlink.c:1272
 netlink_unicast+0x13b7/0x1480 net/netlink/af_netlink.c:1298
 netlink_sendmsg+0x10b8/0x10f0 net/netlink/af_netlink.c:1844
 sock_sendmsg_nosec net/socket.c:633
 sock_sendmsg net/socket.c:643
 ___sys_sendmsg+0xd4b/0x10f0 net/socket.c:1997
 __sys_sendmsg net/socket.c:2031
 SYSC_sendmsg+0x2c6/0x3f0 net/socket.c:2042
 SyS_sendmsg+0x87/0xb0 net/socket.c:2038
 do_syscall_64+0x102/0x150 arch/x86/entry/common.c:285
 entry_SYSCALL64_slow_path+0x25/0x25 arch/x86/entry/entry_64.S:246
`: `net/core/rtnetlink.c`,
		`
==================================================================
BUG: KASAN: use-after-free in __read_once_size include/linux/compiler.h:254 [inline] at addr ffff88004f0f1938
BUG: KASAN: use-after-free in atomic_read arch/x86/include/asm/atomic.h:26 [inline] at addr ffff88004f0f1938
BUG: KASAN: use-after-free in virt_spin_lock arch/x86/include/asm/qspinlock.h:62 [inline] at addr ffff88004f0f1938
BUG: KASAN: use-after-free in queued_spin_lock_slowpath+0xb0a/0xfd0 kernel/locking/qspinlock.c:421 at addr ffff88004f0f1938
Read of size 4 by task syz-executor0/28813
CPU: 1 PID: 28813 Comm: syz-executor0 Not tainted 4.11.0-rc7+ #251
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS Bochs 01/01/2011
Call Trace:
 __dump_stack lib/dump_stack.c:16 [inline]
 dump_stack+0x292/0x398 lib/dump_stack.c:52
 kasan_object_err+0x1c/0x70 mm/kasan/report.c:164
 print_address_description mm/kasan/report.c:202 [inline]
 kasan_report_error mm/kasan/report.c:291 [inline]
 kasan_report+0x252/0x510 mm/kasan/report.c:347
 __asan_report_load4_noabort+0x14/0x20 mm/kasan/report.c:367
 __read_once_size include/linux/compiler.h:254 [inline]
 atomic_read arch/x86/include/asm/atomic.h:26 [inline]
 virt_spin_lock arch/x86/include/asm/qspinlock.h:62 [inline]
 queued_spin_lock_slowpath+0xb0a/0xfd0 kernel/locking/qspinlock.c:421
 queued_spin_lock include/asm-generic/qspinlock.h:103 [inline]
 do_raw_spin_lock+0x151/0x1e0 kernel/locking/spinlock_debug.c:113
 __raw_spin_lock include/linux/spinlock_api_smp.h:143 [inline]
 _raw_spin_lock+0x32/0x40 kernel/locking/spinlock.c:151
 spin_lock include/linux/spinlock.h:299 [inline]
 lockref_get_not_dead+0x19/0x80 lib/lockref.c:179
 __ns_get_path+0x197/0x860 fs/nsfs.c:66
 open_related_ns+0xda/0x200 fs/nsfs.c:143
 sock_ioctl+0x39d/0x440 net/socket.c:1001
 vfs_ioctl fs/ioctl.c:45 [inline]
 do_vfs_ioctl+0x1bf/0x1780 fs/ioctl.c:685
 SYSC_ioctl fs/ioctl.c:700 [inline]
 SyS_ioctl+0x8f/0xc0 fs/ioctl.c:691
 entry_SYSCALL_64_fastpath+0x1f/0xc2
`: `fs/nsfs.c`,
		`
irq bypass consumer (token ffff8801bff15e80) registration fails: -16
kasan: CONFIG_KASAN_INLINE enabled
kasan: GPF could be caused by NULL-ptr deref or user memory access
general protection fault: 0000 [#1] SMP KASAN
Dumping ftrace buffer:
   (ftrace buffer empty)
Modules linked in:
CPU: 0 PID: 1427 Comm: kworker/0:3 Not tainted 4.9.0+ #9
Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011
Workqueue: kvm-irqfd-cleanup irqfd_shutdown
task: ffff8801d60cc700 task.stack: ffff8801d62f8000
RIP: 0010:[<ffffffff84352ab6>]  [<ffffffff84352ab6>] __list_del include/linux/list.h:89 [inline]
RIP: 0010:[<ffffffff84352ab6>]  [<ffffffff84352ab6>] list_del include/linux/list.h:107 [inline]
RIP: 0010:[<ffffffff84352ab6>]  [<ffffffff84352ab6>] irq_bypass_unregister_consumer+0x296/0x470 virt/lib/irqbypass.c:258
RSP: 0018:ffff8801d62ff318  EFLAGS: 00010202
RAX: 0000000000000000 RBX: 1ffff1003ac5fe65 RCX: dffffc0000000000
RDX: ffff8801d3075170 RSI: 0000000000000001 RDI: 0000000000000008
RBP: ffff8801d62ff3b0 R08: 0000000000000000 R09: 0000000000000000
R10: 0000000000000006 R11: 0000000000000000 R12: ffff8801d3075168
R13: ffff8801d7d071a8 R14: 0000000000000000 R15: ffffffff8541bbe0
FS:  0000000000000000(0000) GS:ffff8801dc000000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 00007f960f8f3db8 CR3: 00000001da19b000 CR4: 00000000001426f0
DR0: 0000000020000000 DR1: 0000000020000000 DR2: 0000000000000000
DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000600
Stack:
 ffffffff814cc212 ffff8801d60cc700 0000000041b58ab3 ffffffff84ad688d
 ffffffff84352820 ffffffff815720c0 ffff8801da11b640 0000000041b58ab3
 ffffffff84aea0a0 ffffffff81262e90 1ffff1003ac5fe74 0000000041b58ab3
Call Trace:
 [<ffffffff8108aaf3>] irqfd_shutdown+0x123/0x1c0 arch/x86/kvm/../../../virt/kvm/eventfd.c:145
 [<ffffffff81492c00>] process_one_work+0xbd0/0x1c10 kernel/workqueue.c:2096
 [<ffffffff81493e63>] worker_thread+0x223/0x1990 kernel/workqueue.c:2230
 [<ffffffff814abd53>] kthread+0x323/0x3e0 kernel/kthread.c:209
 [<ffffffff84377c6a>] ret_from_fork+0x2a/0x40 arch/x86/entry/entry_64.S:433
Code: 48 89 d1 48 c1 e9 03 80 3c 01 00 0f 85 76 01 00 00 49 8d 7e 08 48 b9 00 00 00 00 00 fc ff df 49 8b 44 24 08 48 89 fe 48 c1 ee 03 <80> 3c 0e 00 0f 85 2c 01 00 00 4c 8d 6d 98 48 b9 00 00 00 00 00 
RIP  [<ffffffff84352ab6>] __list_del include/linux/list.h:89 [inline]
RIP  [<ffffffff84352ab6>] list_del include/linux/list.h:107 [inline]
RIP  [<ffffffff84352ab6>] irq_bypass_unregister_consumer+0x296/0x470 virt/lib/irqbypass.c:258
 RSP <ffff8801d62ff318>
---[ end trace c88bb3be8e63e0af ]---
Kernel panic - not syncing: Fatal exception
Dumping ftrace buffer:
   (ftrace buffer empty)
Kernel Offset: disabled
Rebooting in 86400 seconds..
`: `arch/x86/kvm/../../../virt/kvm/eventfd.c`,
		`
------------[ cut here ]------------
kernel BUG at ./include/linux/skbuff.h:2389!
invalid opcode: 0000 [#1] SMP KASAN
Dumping ftrace buffer:
   (ftrace buffer empty)
Modules linked in:
CPU: 2 PID: 10793 Comm: syz-executor0 Not tainted 4.10.0-rc8+ #201
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS Bochs 01/01/2011
task: ffff88006aeb1700 task.stack: ffff880069b08000
RIP: 0010:skb_set_owner_r include/linux/skbuff.h:2389 [inline]
RIP: 0010:__sock_queue_rcv_skb+0x8c0/0xda0 net/core/sock.c:425
RSP: 0018:ffff88006de06b58 EFLAGS: 00010206
RAX: ffff88006aeb1700 RBX: ffff8800581dc170 RCX: 0000000000000000
RDX: 0000000000000100 RSI: 1ffff1000d5fcb7b RDI: ffff88006afe5be0
RBP: ffff88006de06dc0 R08: 0000000000000002 R09: 0000000000000001
R10: 0000000000000000 R11: dffffc0000000000 R12: ffff88006afe5bc0
R13: ffff88006de06d98 R14: ffff8800581dc198 R15: ffff88006afe5c20
FS:  00007f06a3bd9700(0000) GS:ffff88006de00000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 0000000020007000 CR3: 000000006a280000 CR4: 00000000000006e0
Call Trace:
 <IRQ>
 sock_queue_rcv_skb+0x3a/0x50 net/core/sock.c:451
PF_BRIDGE: RTM_DELNEIGH with invalid address
 llc_sap_state_process+0x3e3/0x4e0 net/llc/llc_sap.c:220
 llc_sap_rcv net/llc/llc_sap.c:294 [inline]
 llc_sap_handler+0x695/0x1320 net/llc/llc_sap.c:434
 llc_rcv+0x6da/0xed0 net/llc/llc_input.c:208
 __netif_receive_skb_core+0x1ae5/0x3400 net/core/dev.c:4190
 __netif_receive_skb+0x2a/0x170 net/core/dev.c:4228
 process_backlog+0xe5/0x6c0 net/core/dev.c:4839
 napi_poll net/core/dev.c:5202 [inline]
 net_rx_action+0xe70/0x1900 net/core/dev.c:5267
 __do_softirq+0x2fb/0xb7d kernel/softirq.c:284
 do_softirq_own_stack+0x1c/0x30 arch/x86/entry/entry_64.S:902
 </IRQ>
 do_softirq.part.17+0x1e8/0x230 kernel/softirq.c:328
 do_softirq kernel/softirq.c:176 [inline]
 __local_bh_enable_ip+0x1f2/0x200 kernel/softirq.c:181
 local_bh_enable include/linux/bottom_half.h:31 [inline]
 rcu_read_unlock_bh include/linux/rcupdate.h:971 [inline]
 __dev_queue_xmit+0xd87/0x2860 net/core/dev.c:3399
 dev_queue_xmit+0x17/0x20 net/core/dev.c:3405
 llc_build_and_send_ui_pkt+0x240/0x330 net/llc/llc_output.c:74
 llc_ui_sendmsg+0x98d/0x1430 net/llc/af_llc.c:928
 sock_sendmsg_nosec net/socket.c:635 [inline]
 sock_sendmsg+0xca/0x110 net/socket.c:645
 ___sys_sendmsg+0x9d2/0xae0 net/socket.c:1985
 __sys_sendmsg+0x138/0x320 net/socket.c:2019
 SYSC_sendmsg net/socket.c:2030 [inline]
 SyS_sendmsg+0x2d/0x50 net/socket.c:2026
 entry_SYSCALL_64_fastpath+0x1f/0xc2
`: `net/llc/llc_sap.c`,
		`
==================================================================
BUG: KASAN: use-after-free in skb_pfmemalloc include/linux/skbuff.h:829 [inline] at addr ffff88003b910d8c
BUG: KASAN: use-after-free in skb_clone+0x3a2/0x420 net/core/skbuff.c:1029 at addr ffff88003b910d8c
Read of size 4 by task syz-executor0/5591
CPU: 1 PID: 5591 Comm: syz-executor0 Not tainted 4.10.0-rc8+ #201
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS Bochs 01/01/2011
Call Trace:
 <IRQ>
 __dump_stack lib/dump_stack.c:15 [inline]
 dump_stack+0x292/0x398 lib/dump_stack.c:51
 kasan_object_err+0x1c/0x70 mm/kasan/report.c:162
 print_address_description mm/kasan/report.c:200 [inline]
 kasan_report_error mm/kasan/report.c:289 [inline]
 kasan_report.part.1+0x20e/0x4e0 mm/kasan/report.c:311
 kasan_report mm/kasan/report.c:331 [inline]
 __asan_report_load4_noabort+0x29/0x30 mm/kasan/report.c:331
 skb_pfmemalloc include/linux/skbuff.h:829 [inline]
 skb_clone+0x3a2/0x420 net/core/skbuff.c:1029
 dccp_v6_request_recv_sock+0xb5e/0x1960 net/dccp/ipv6.c:527
 dccp_check_req+0x335/0x5a0 net/dccp/minisocks.c:186
 dccp_v6_rcv+0x69e/0x1d00 net/dccp/ipv6.c:711
 ip6_input_finish+0x46d/0x17a0 net/ipv6/ip6_input.c:279
 NF_HOOK include/linux/netfilter.h:257 [inline]
 ip6_input+0xdb/0x590 net/ipv6/ip6_input.c:322
 dst_input include/net/dst.h:507 [inline]
 ip6_rcv_finish+0x289/0x890 net/ipv6/ip6_input.c:69
 NF_HOOK include/linux/netfilter.h:257 [inline]
 ipv6_rcv+0x12ec/0x23d0 net/ipv6/ip6_input.c:203
 __netif_receive_skb_core+0x1ae5/0x3400 net/core/dev.c:4190
 __netif_receive_skb+0x2a/0x170 net/core/dev.c:4228
 process_backlog+0xe5/0x6c0 net/core/dev.c:4839
 napi_poll net/core/dev.c:5202 [inline]
 net_rx_action+0xe70/0x1900 net/core/dev.c:5267
 __do_softirq+0x2fb/0xb7d kernel/softirq.c:284
 do_softirq_own_stack+0x1c/0x30 arch/x86/entry/entry_64.S:902
 </IRQ>
 do_softirq.part.17+0x1e8/0x230 kernel/softirq.c:328
 do_softirq kernel/softirq.c:176 [inline]
 __local_bh_enable_ip+0x1f2/0x200 kernel/softirq.c:181
 local_bh_enable include/linux/bottom_half.h:31 [inline]
 rcu_read_unlock_bh include/linux/rcupdate.h:971 [inline]
 ip6_finish_output2+0xbb0/0x23d0 net/ipv6/ip6_output.c:123
 ip6_finish_output+0x302/0x960 net/ipv6/ip6_output.c:148
 NF_HOOK_COND include/linux/netfilter.h:246 [inline]
 ip6_output+0x1cb/0x8d0 net/ipv6/ip6_output.c:162
 ip6_xmit+0xce6/0x20d0 include/net/dst.h:501
 inet6_csk_xmit+0x320/0x5f0 net/ipv6/inet6_connection_sock.c:179
 dccp_transmit_skb+0xb09/0x1120 net/dccp/output.c:141
 dccp_send_ack+0x1bf/0x350 net/dccp/output.c:594
 dccp_rcv_request_sent_state_process net/dccp/input.c:501 [inline]
 dccp_rcv_state_process+0x102f/0x1650 net/dccp/input.c:670
 dccp_v6_do_rcv+0x213/0x350 net/dccp/ipv6.c:632
 sk_backlog_rcv include/net/sock.h:893 [inline]
 __release_sock+0x127/0x3a0 net/core/sock.c:2053
 release_sock+0xa5/0x2b0 net/core/sock.c:2540
 inet_wait_for_connect net/ipv4/af_inet.c:557 [inline]
 __inet_stream_connect+0x5f7/0xeb0 net/ipv4/af_inet.c:626
 inet_stream_connect+0x55/0xa0 net/ipv4/af_inet.c:665
 SYSC_connect+0x251/0x590 net/socket.c:1579
 SyS_connect+0x24/0x30 net/socket.c:1560
 entry_SYSCALL_64_fastpath+0x1f/0xc2
`: `net/dccp/ipv6.c`,
		`
==================================================================
BUG: KASAN: use-after-free in __list_add_rcu include/linux/rculist.h:57 [inline] at addr ffff8801c5b6c110
BUG: KASAN: use-after-free in list_add_rcu include/linux/rculist.h:78 [inline] at addr ffff8801c5b6c110
BUG: KASAN: use-after-free in timerfd_setup_cancel fs/timerfd.c:141 [inline] at addr ffff8801c5b6c110
BUG: KASAN: use-after-free in do_timerfd_settime+0xd32/0xf50 fs/timerfd.c:446 at addr ffff8801c5b6c110
Write of size 8 by task syz-executor5/10885
CPU: 1 PID: 10885 Comm: syz-executor5 Not tainted 4.10.0+ #7
Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011
Call Trace:
 __dump_stack lib/dump_stack.c:15 [inline]
 dump_stack+0x2ee/0x3ef lib/dump_stack.c:51
 kasan_object_err+0x1c/0x70 mm/kasan/report.c:162
 print_address_description mm/kasan/report.c:200 [inline]
 kasan_report_error mm/kasan/report.c:289 [inline]
 kasan_report.part.2+0x1e5/0x4b0 mm/kasan/report.c:311
 kasan_report mm/kasan/report.c:337 [inline]
 __asan_report_store8_noabort+0x2c/0x30 mm/kasan/report.c:337
 __list_add_rcu include/linux/rculist.h:57 [inline]
 list_add_rcu include/linux/rculist.h:78 [inline]
 timerfd_setup_cancel fs/timerfd.c:141 [inline]
 do_timerfd_settime+0xd32/0xf50 fs/timerfd.c:446
 SYSC_timerfd_settime fs/timerfd.c:533 [inline]
 SyS_timerfd_settime+0xef/0x1c0 fs/timerfd.c:524
 entry_SYSCALL_64_fastpath+0x1f/0xc
`: `fs/timerfd.c`,
		`
driver/foo/lib/foo.c:10
`: `driver/foo/lib/foo.c`,
		`
BUG: soft lockup - CPU#1 stuck for 22s! [syz-executor2:7067]
hardirqs last  enabled at (210421): [<ffffffff82c51728>] restore_regs_and_iret+0x0/0x1d
hardirqs last disabled at (210422): [<ffffffff8100fb22>] apic_timer_interrupt+0x82/0x90 arch/x86/entry/entry_64.S:710
softirqs last  enabled at (210420): [<ffffffff810114a3>] __do_softirq+0x613/0x8c4 kernel/softirq.c:344
softirqs last disabled at (210415): [<ffffffff812c1650>] invoke_softirq kernel/softirq.c:395 [inline]
softirqs last disabled at (210415): [<ffffffff812c1650>] irq_exit+0x170/0x1a0 kernel/softirq.c:436
RIP: 0010:[<ffffffff8181134a>]  [<ffffffff8181134a>] next_group+0x5a/0x2e0 fs/pnode.c:172
`: `fs/pnode.c`,
		`
------------[ cut here ]------------
WARNING: CPU: 1 PID: 7733 at mm/vmalloc.c:1473 __vunmap+0x1ca/0x300 mm/vmalloc.c:1472()
Trying to vfree() bad address (ffff8800b3254fc0)
Kernel panic - not syncing: panic_on_warn set ...

Call Trace:
 [<ffffffff81c8f6cd>] __dump_stack lib/dump_stack.c:15 [inline]
 [<ffffffff81c8f6cd>] dump_stack+0xc1/0x124 lib/dump_stack.c:51
 [<ffffffff815f5f34>] __panic+0x11f/0x30b kernel/panic.c:179
 [<ffffffff815f61da>] panic_saved_regs+0xba/0xba kernel/panic.c:280
 [<ffffffff812b148f>] warn_slowpath_common+0x12f/0x150 kernel/panic.c:642
 [<ffffffff812b1560>] warn_slowpath_fmt+0xb0/0xe0 kernel/panic.c:658
 [<ffffffff816d015a>] __vunmap+0x1ca/0x300 mm/vmalloc.c:1472
 [<ffffffff816d0355>] vfree+0x55/0xe0 mm/vmalloc.c:1533
 [<ffffffff81b26404>] ipc_free+0x44/0x50 ipc/util.c:420
 [<ffffffff81b3203d>] semctl_main+0x20d/0x1ba0 ipc/sem.c:1496
`: `ipc/util.c`,
		`
===============================
[ INFO: suspicious RCU usage. ]
Call Trace:
 [<ffffffff81c8f6cd>] __dump_stack lib/dump_stack.c:15 [inline]
 [<ffffffff81c8f6cd>] dump_stack+0xc1/0x124 lib/dump_stack.c:51
 [<ffffffff81614578>] warn_alloc+0x208/0x230 mm/page_alloc.c:2850
 [<ffffffff816d0915>] __vmalloc_area_node_memcg mm/vmalloc.c:1647 [inline]
 [<ffffffff816d0915>] __vmalloc_node_range_memcg+0x375/0x670 mm/vmalloc.c:1690
 [<ffffffff816d0c79>] __vmalloc_node_memcg mm/vmalloc.c:1751 [inline]
 [<ffffffff816d0c79>] __vmalloc_node_memcg_flags mm/vmalloc.c:1788 [inline]
 [<ffffffff816d0c79>] vmalloc+0x69/0x70 mm/vmalloc.c:1803
 [<ffffffff8279a0b0>] xt_alloc_table_info+0xd0/0x100 net/netfilter/x_tables.c:952
 [<ffffffff829a50bc>] do_replace net/ipv4/netfilter/ip_tables.c:1140 [inline]
 [<ffffffff829a50bc>] do_ipt_set_ctl+0x21c/0x430 net/ipv4/netfilter/ip_tables.c:1687
 [<ffffffff827436ac>] nf_sockopt net/netfilter/nf_sockopt.c:105 [inline]
`: `net/netfilter/x_tables.c`,
		`
BUG: unable to handle kernel NULL pointer dereference at 0000000000000074
IP: virt_to_cache mm/slab.c:400 [inline]
IP: kfree+0xb2/0x250 mm/slab.c:3802
PGD 1c18ff067 P4D 1c18ff067 PUD 1c3556067 PMD 0
Oops: 0000 [#1] SMP KASAN
Dumping ftrace buffer:
    (ftrace buffer empty)
Modules linked in:
CPU: 1 PID: 24672 Comm: syz-executor7 Not tainted 4.14.0+ #129
Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS  
Google 01/01/2011
task: ffff8801c904c540 task.stack: ffff8801a4320000
RIP: 0010:virt_to_cache mm/slab.c:400 [inline]
RIP: 0010:kfree+0xb2/0x250 mm/slab.c:3802
RSP: 0018:ffff8801a4327750 EFLAGS: 00010046
RAX: 0000000000000000 RBX: ffff8801a4327918 RCX: ffffffffffffffff
RDX: ffffea000690c9c0 RSI: 0000000000000000 RDI: ffff8801a4327918
RBP: ffff8801a4327770 R08: ffffed003a6e6874 R09: 0000000000000000
R10: 0000000000000001 R11: ffffed003a6e6873 R12: 0000000000000286
R13: 0000000000000000 R14: ffff8801a4327918 R15: ffff8801a4327880
FS:  00007f63f74de700(0000) GS:ffff8801db500000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 0000000000000074 CR3: 00000001c6f12000 CR4: 00000000001406e0
DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
Call Trace:
  blkcipher_walk_done+0x72b/0xde0 crypto/blkcipher.c:139
`: `crypto/blkcipher.c`,
	}
	reporter, err := NewReporter("linux", "", "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	linux := reporter.(*linux)
	for report, guilty0 := range tests {
		if guilty := linux.extractGuiltyFile([]byte(report)); guilty != guilty0 {
			t.Logf("log:\n%s", report)
			t.Logf("want guilty:\n%s", guilty0)
			t.Logf("got guilty:\n%s", guilty)
			t.Fatalf("couldn't extract guilty file")
		}
	}
}
