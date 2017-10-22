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
	tests := map[string]string{
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
`: `BUG: unable to handle kernel paging request in __memset`,

		`
[ 1019.110825] BUG: unable to handle kernel paging request at 000000010000001a
[ 1019.112065] IP: skb_release_data+0x258/0x470
`: `BUG: unable to handle kernel paging request in skb_release_data`,

		`
BUG: unable to handle kernel paging request at 00000000ffffff8a
IP: [<ffffffff810a376f>] __call_rcu.constprop.76+0x1f/0x280 kernel/rcu/tree.c:3046
`: `BUG: unable to handle kernel paging request in __call_rcu`,

		`
[ 1581.999813] BUG: unable to handle kernel paging request at ffffea0000f0e440
[ 1581.999824] IP: [<ffffea0000f0e440>] 0xffffea0000f0e440
`: `BUG: unable to handle kernel paging request`,

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
`: `general protection fault in drm_legacy_newctx`,

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
`: `general protection fault in logfs_init_inode`,

		`
general protection fault: 0000 [#1] SMP KASAN
Dumping ftrace buffer:
   (ftrace buffer empty)
Modules linked in:
CPU: 0 PID: 27388 Comm: syz-executor5 Not tainted 4.10.0-rc6+ #117
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS Bochs 01/01/2011
task: ffff88006252db40 task.stack: ffff880062090000
RIP: 0010:__ip_options_echo+0x120a/0x1770
RSP: 0018:ffff880062097530 EFLAGS: 00010206
RAX: dffffc0000000000 RBX: ffff880062097910 RCX: 0000000000000000
RDX: 0000000000000003 RSI: ffffffff83988dca RDI: 0000000000000018
RBP: ffff8800620976a0 R08: ffff88006209791c R09: ffffed000c412f26
R10: 0000000000000004 R11: ffffed000c412f25 R12: ffff880062097900
R13: ffff88003a8c0a6c R14: 1ffff1000c412eb3 R15: 000000000000000d
FS:  00007fd61b443700(0000) GS:ffff88003ec00000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 000000002095f000 CR3: 0000000062876000 CR4: 00000000000006f0
`: `general protection fault in __ip_options_echo`,

		`
==================================================================
BUG: KASAN: slab-out-of-bounds in memcpy+0x1d/0x40 at addr ffff88003a6bd110
Read of size 8 by task a.out/6260
BUG: KASAN: slab-out-of-bounds in memcpy+0x1d/0x40 at addr ffff88003a6bd110
Write of size 4 by task a.out/6260
`: `KASAN: slab-out-of-bounds Read in memcpy`,

		`
[   50.583499] BUG: KASAN: use-after-free in remove_wait_queue+0xfb/0x120 at addr ffff88002db3cf50
[   50.583499] Write of size 8 by task syzkaller_execu/10568 
`: `KASAN: use-after-free Write in remove_wait_queue`,

		`
[  380.688570] BUG: KASAN: use-after-free in copy_from_iter+0xf30/0x15e0 at addr ffff880033f4b02a
[  380.688570] Read of size 4059 by task syz-executor/29957
`: `KASAN: use-after-free Read in copy_from_iter`,

		`
[23818.431954] BUG: KASAN: null-ptr-deref on address           (null)

[23818.438140] Read of size 4 by task syz-executor/22534

[23818.443211] CPU: 3 PID: 22534 Comm: syz-executor Tainted: G     U         3.18.0 #78
`: `KASAN: null-ptr-deref Read`,

		`
==================================================================
BUG: KASAN: wild-memory-access on address ffe7087450a17000
Read of size 205 by task syz-executor1/9018
`: `KASAN: wild-memory-access Read`,

		`
[  149.188010] BUG: unable to handle kernel NULL pointer dereference at 000000000000058c
unrelateed line
[  149.188010] IP: [<ffffffff8148e81d>] __lock_acquire+0x2bd/0x3410
`: `BUG: unable to handle kernel NULL pointer dereference in __lock_acquire`,

		`
[   55.112844] BUG: unable to handle kernel NULL pointer dereference at 000000000000001a
[   55.113569] IP: skb_release_data+0x258/0x470
`: `BUG: unable to handle kernel NULL pointer dereference in skb_release_data`,

		`
[   50.583499] WARNING: CPU: 2 PID: 2636 at ipc/shm.c:162 shm_open.isra.5.part.6+0x74/0x80
[   50.583499] Modules linked in: 
`: `WARNING in shm_open`,

		`
[  753.120788] WARNING: CPU: 0 PID: 0 at net/sched/sch_generic.c:316 dev_watchdog+0x648/0x770
[  753.122260] NETDEV WATCHDOG: eth0 (e1000): transmit queue 0 timed out
`: `WARNING in dev_watchdog`,

		`
------------[ cut here ]------------
WARNING: CPU: 3 PID: 1975 at fs/locks.c:241 locks_free_lock_context+0x118/0x180()
`: `WARNING in locks_free_lock_context`,

		`
WARNING: CPU: 3 PID: 23810 at /linux-src-3.18/net/netlink/genetlink.c:1037 genl_unbind+0x110/0x130()
`: `WARNING in genl_unbind`,

		`
=======================================================
[ INFO: possible circular locking dependency detected ]
2.6.32-rc6-00035-g8b17a4f #1
-------------------------------------------------------
kacpi_hotplug/246 is trying to acquire lock:
 (kacpid){+.+.+.}, at: [<ffffffff8105bbd0>] flush_workqueue+0x0/0xb0
`: `possible deadlock in flush_workqueue`,

		`WARNING: possible circular locking dependency detected
4.12.0-rc2-next-20170525+ #1 Not tainted
------------------------------------------------------
kworker/u4:2/54 is trying to acquire lock:
 (&buf->lock){+.+...}, at: [<ffffffff9edb41bb>] tty_buffer_flush+0xbb/0x3a0 drivers/tty/tty_buffer.c:221

but task is already holding lock:
 (&o_tty->termios_rwsem/1){++++..}, at: [<ffffffff9eda4961>] isig+0xa1/0x4d0 drivers/tty/n_tty.c:1100

which lock already depends on the new lock.
`: `possible deadlock in tty_buffer_flush`,

		`
[   44.025025] =========================================================
[   44.025025] [ INFO: possible irq lock inversion dependency detected ]
[   44.025025] 4.10.0-rc8+ #228 Not tainted
[   44.025025] ---------------------------------------------------------
[   44.025025] syz-executor6/1577 just changed the state of lock:
[   44.025025]  (&(&r->consumer_lock)->rlock){+.+...}, at: [<ffffffff82de6c86>] tun_queue_purge+0xe6/0x210
`: `possible deadlock in tun_queue_purge`,

		`
[  121.451623] ======================================================
[  121.452013] [ INFO: SOFTIRQ-safe -> SOFTIRQ-unsafe lock order detected ]
[  121.452013] 4.10.0-rc8+ #228 Not tainted
[  121.453507] ------------------------------------------------------
[  121.453507] syz-executor1/19557 [HC0[0]:SC0[0]:HE0:SE1] is trying to acquire:
[  121.453507]  (&(&r->consumer_lock)->rlock){+.+...}, at: [<ffffffff82df4347>] tun_device_event+0x897/0xc70
`: `possible deadlock in tun_device_event`,

		`
[   48.981019] =============================================
[   48.981019] [ INFO: possible recursive locking detected ]
[   48.981019] 4.11.0-rc4+ #198 Not tainted
[   48.981019] ---------------------------------------------
[   48.981019] kauditd/901 is trying to acquire lock:
[   48.981019]  (audit_cmd_mutex){+.+.+.}, at: [<ffffffff81585f59>] audit_receive+0x79/0x360
`: `possible deadlock in audit_receive`,

		`
[  131.449768] ======================================================
[  131.449777] [ INFO: possible circular locking dependency detected ]
[  131.449789] 3.10.37+ #1 Not tainted
[  131.449797] -------------------------------------------------------
[  131.449807] swapper/2/0 is trying to acquire lock:
[  131.449859]  (&port_lock_key){-.-...}, at: [<c036a6dc>]     serial8250_console_write+0x108/0x134
[  131.449866] 
`: `possible deadlock in serial8250_console_write`,

		`
[   52.261501] =================================
[   52.261501] [ INFO: inconsistent lock state ]
[   52.261501] 4.10.0+ #60 Not tainted
[   52.261501] ---------------------------------
[   52.261501] inconsistent {IN-SOFTIRQ-W} -> {SOFTIRQ-ON-W} usage.
[   52.261501] syz-executor3/5076 [HC0[0]:SC0[0]:HE1:SE1] takes:
[   52.261501]  (&(&hashinfo->ehash_locks[i])->rlock){+.?...}, at: [<ffffffff83a6a370>] inet_ehash_insert+0x240/0xad0
`: `inconsistent lock state in inet_ehash_insert`,

		`
[ INFO: suspicious RCU usage. ]
4.3.5-smp-DEV #101 Not tainted
-------------------------------
net/core/filter.c:1917 suspicious rcu_dereference_protected() usage!
other info that might help us debug this:
`: `suspicious RCU usage at net/core/filter.c:LINE`,

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
[   37.540614] 
[   37.540614] stack backtrace:
`: `suspicious RCU usage at ./include/linux/kvm_host.h:LINE`,

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
`: `BUG: still has locks held in pipe_lock`,

		`
=====================================
[ BUG: bad unlock balance detected! ]
4.10.0+ #179 Not tainted
-------------------------------------
syz-executor1/21439 is trying to release lock (sk_lock-AF_INET) at:
[<ffffffff83f7ac8b>] sctp_sendmsg+0x2a3b/0x38a0 net/sctp/socket.c:2007
`: `BUG: bad unlock balance in sctp_sendmsg`,

		`
[  633.049984] =========================
[  633.049987] [ BUG: held lock freed! ]
[  633.049993] 4.10.0+ #260 Not tainted
[  633.049996] -------------------------
[  633.050005] syz-executor7/27251 is freeing memory ffff8800178f8180-ffff8800178f8a77, with a lock still held there!
[  633.050009]  (slock-AF_INET6){+.-...}, at: [<ffffffff835f22c9>] sk_clone_lock+0x3d9/0x12c0
`: `BUG: held lock freed in sk_clone_lock`,

		`
[ 2569.618120] BUG: Bad rss-counter state mm:ffff88005fac4300 idx:0 val:15
`: `BUG: Bad rss-counter state`,

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
`: `UBSAN: Undefined behaviour in drivers/usb/core/devio.c:LINE`,

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
`: `UBSAN: Undefined behaviour in ./arch/x86/include/asm/atomic.h:LINE`,

		`
[   50.583499] UBSAN: Undefined behaviour in kernel/time/hrtimer.c:310:16
[   50.583499] signed integer overflow:
`: `UBSAN: Undefined behaviour in kernel/time/hrtimer.c:LINE`,

		`
------------[ cut here ]------------
kernel BUG at fs/buffer.c:1917!
invalid opcode: 0000 [#1] SMP
`: `kernel BUG at fs/buffer.c:LINE!`,

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
`: `unable to handle kernel paging request in _snd_timer_stop`,

		`
Unable to handle kernel paging request at virtual address 0c0c9ca0
pgd = c0004000
[0c0c9ca0] *pgd=00000000
Internal error: Oops: 5 [#1] PREEMPT
last sysfs file: /sys/devices/virtual/irqk/irqk/dev
Modules linked in: cmemk dm365mmap edmak irqk
CPU: 0    Not tainted  (2.6.32-17-ridgerun #22)
PC is at blk_rq_map_sg+0x70/0x2c0
LR is at mmc_queue_map_sg+0x2c/0xa4
pc : [<c01751ac>]    lr : [<c025a42c>]    psr: 80000013
sp : c23e1db0  ip : c3cf8848  fp : c23e1df4
`: `unable to handle kernel paging request in blk_rq_map_sg`,

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
`: `kernel panic: Attempted to kill init!`,

		`
[  616.344091] Kernel panic - not syncing: Fatal exception in interrupt
`: `kernel panic: Fatal exception in interrupt`,

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
`: `divide error in snd_hrtimer_callback`,

		`
divide error: 0000 [#1] SMP KASAN
Dumping ftrace buffer:
   (ftrace buffer empty)
Modules linked in:
CPU: 2 PID: 5664 Comm: syz-executor5 Not tainted 4.10.0-rc6+ #122
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS Bochs 01/01/2011
task: ffff88003a46adc0 task.stack: ffff880036a00000
RIP: 0010:__tcp_select_window+0x6db/0x920
RSP: 0018:ffff880036a07638 EFLAGS: 00010212
RAX: 0000000000000480 RBX: ffff880036a077d0 RCX: ffffc900030db000
RDX: 0000000000000000 RSI: 0000000000000000 RDI: ffff88003809c3b5
RBP: ffff880036a077f8 R08: ffff880039de5dc0 R09: 0000000000000000
R10: 0000000000000000 R11: 0000000000000000 R12: 0000000000000480
R13: 0000000000000000 R14: ffff88003809bb00 R15: 0000000000000000
FS:  00007f35ecf32700(0000) GS:ffff88006de00000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 00000000205fb000 CR3: 0000000032467000 CR4: 00000000000006e0
`: `divide error in __tcp_select_window`,

		`
unreferenced object 0xffff880039a55260 (size 64): 
  comm "executor", pid 11746, jiffies 4298984475 (age 16.078s) 
  hex dump (first 32 bytes): 
    2f 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  /............... 
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................ 
  backtrace: 
    [<ffffffff848a2f5f>] sock_kmalloc+0x7f/0xc0 net/core/sock.c:1774 
    [<ffffffff84e5bea0>] do_ipv6_setsockopt.isra.7+0x15d0/0x2830 net/ipv6/ipv6_sockglue.c:483 
    [<ffffffff84e5d19b>] ipv6_setsockopt+0x9b/0x140 net/ipv6/ipv6_sockglue.c:885 
    [<ffffffff8544616c>] sctp_setsockopt+0x15c/0x36c0 net/sctp/socket.c:3702 
    [<ffffffff848a2035>] sock_common_setsockopt+0x95/0xd0 net/core/sock.c:2645 
    [<ffffffff8489f1d8>] SyS_setsockopt+0x158/0x240 net/socket.c:1736 
`: `memory leak in ipv6_setsockopt (size 64)`,

		`
unreferenced object 0xffff8800342540c0 (size 1864): 
  comm "a.out", pid 24109, jiffies 4299060398 (age 27.984s) 
  hex dump (first 32 bytes): 
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................ 
    0a 00 07 40 00 00 00 00 00 00 00 00 00 00 00 00  ...@............ 
  backtrace: 
    [<ffffffff85c73a22>] kmemleak_alloc+0x72/0xc0 mm/kmemleak.c:915 
    [<ffffffff816cc14d>] kmem_cache_alloc+0x12d/0x2c0 mm/slub.c:2607 
    [<ffffffff84b642c9>] sk_prot_alloc+0x69/0x340 net/core/sock.c:1344 
    [<ffffffff84b6d36a>] sk_alloc+0x3a/0x6b0 net/core/sock.c:1419 
    [<ffffffff850c6d57>] inet6_create+0x2d7/0x1000 net/ipv6/af_inet6.c:173 
    [<ffffffff84b5f47c>] __sock_create+0x37c/0x640 net/socket.c:1162 
`: `memory leak in sk_prot_alloc (size 1864)`,

		`
unreferenced object 0xffff880133c63800 (size 1024):
  comm "exe", pid 1521, jiffies 4294894652
  backtrace:
    [<ffffffff810f8f36>] create_object+0x126/0x2b0
    [<ffffffff810f91d5>] kmemleak_alloc+0x25/0x60
    [<ffffffff810f32a3>] __kmalloc+0x113/0x200
    [<ffffffff811aa061>] ext4_mb_init+0x1b1/0x570
    [<ffffffff8119b3d2>] ext4_fill_super+0x1de2/0x26d0
`: `memory leak in __kmalloc (size 1024)`,

		`
unreferenced object 0xc625e000 (size 2048):
  comm "swapper", pid 1, jiffies 4294937521
  backtrace:
    [<c00c89f0>] create_object+0x11c/0x200
    [<c00c6764>] __kmalloc_track_caller+0x138/0x178
    [<c01d78c0>] __alloc_skb+0x4c/0x100
    [<c01d8490>] dev_alloc_skb+0x18/0x3c
    [<c0198b48>] eth_rx_fill+0xd8/0x3fc
    [<c019ac74>] mv_eth_start_internals+0x30/0xf8
`: `memory leak in __alloc_skb (size 2048)`,

		`
unreferenced object 0xdb8040c0 (size 20):
  comm "swapper", pid 0, jiffies 4294667296
  backtrace:
    [<c04fd8b3>] kmemleak_alloc+0x193/0x2b8
    [<c04f5e73>] kmem_cache_alloc+0x11e/0x174
    [<c0aae5a7>] debug_objects_mem_init+0x63/0x1d9
    [<c0a86a62>] start_kernel+0x2da/0x38d
    [<c0a86090>] i386_start_kernel+0x7f/0x98
    [<ffffffff>] 0xffffffff
`: `memory leak in debug_objects_mem_init (size 20)`,

		`
BUG: sleeping function called from invalid context at include/linux/wait.h:1095 
in_atomic(): 1, irqs_disabled(): 0, pid: 3658, name: syz-fuzzer 
`: `BUG: sleeping function called from invalid context at include/linux/wait.h:LINE `,

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
`: `INFO: rcu detected stall in __sctp_write_space`,

		`
INFO: rcu_preempt detected stalls on CPUs/tasks: { 2} (detected by 0, t=65008 jiffies, g=48068, c=48067, q=7339)
`: `INFO: rcu detected stall`,

		`
[  317.168127] INFO: rcu_sched detected stalls on CPUs/tasks: { 0} (detected by 1, t=2179 jiffies, g=740, c=739, q=1)
`: `INFO: rcu detected stall`,

		`
[   50.583499] something
[   50.583499] INFO: rcu_preempt self-detected stall on CPU
[   50.583499]         0: (20822 ticks this GP) idle=94b/140000000000001/0
`: `INFO: rcu detected stall`,

		`
[   50.583499] INFO: rcu_sched self-detected stall on CPU
`: `INFO: rcu detected stall`,

		`
[  152.002376] INFO: rcu_bh detected stalls on CPUs/tasks:
`: `INFO: rcu detected stall`,

		`
[   72.159680] INFO: rcu_sched detected expedited stalls on CPUs/tasks: {
`: `INFO: rcu detected stall`,

		`
BUG: spinlock lockup suspected on CPU#2, syz-executor/12636
`: `BUG: spinlock lockup suspected`,

		`
BUG: soft lockup - CPU#3 stuck for 11s! [syz-executor:643]
`: `BUG: soft lockup`,

		`
BUG: spinlock lockup suspected on CPU#2, syz-executor/12636
BUG: soft lockup - CPU#3 stuck for 11s! [syz-executor:643]
`: `BUG: spinlock lockup suspected`,

		`
BUG: soft lockup - CPU#3 stuck for 11s! [syz-executor:643]
BUG: spinlock lockup suspected on CPU#2, syz-executor/12636
`: `BUG: soft lockup`,

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
`: `BUG: spinlock recursion`,

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
`: `INFO: task hung`,

		`
BUG UNIX (Not tainted): kasan: bad access detected
`: ``,

		`
[901320.960000] INFO: lockdep is turned off.
`: ``,

		`
INFO: Stall ended before state dump start
`: ``,

		`
WARNING: /etc/ssh/moduli does not exist, using fixed modulus
`: ``,

		`
[ 1579.244514] BUG: KASAN: slab-out-of-bounds in ip6_fragment+0x1052/0x2d80 at addr ffff88004ec29b58
`: `KASAN: slab-out-of-bounds in ip6_fragment at addr ADDR`,

		`
[  982.271203] BUG: spinlock bad magic on CPU#0, syz-executor12/24932
`: `BUG: spinlock bad magic`,

		`
[  374.860710] BUG: KASAN: use-after-free in do_con_write.part.23+0x1c50/0x1cb0 at addr ffff88000012c43a
`: `KASAN: use-after-free in do_con_write.part.23 at addr ADDR`,

		`
[  163.314570] WARNING: kernel stack regs at ffff8801d100fea8 in syz-executor1:16059 has bad 'bp' value ffff8801d100ff28
`: `WARNING: kernel stack regs has bad 'bp' value`,

		`
[   76.825838] BUG: using __this_cpu_add() in preemptible [00000000] code: syz-executor0/10076
`: `BUG: using __this_cpu_add() in preemptible [ADDR] code: syz-executor`,

		`
[  367.131148] BUG kmalloc-8 (Tainted: G    B         ): Object already free
`: `BUG: Object already free`,

		`
[   92.396607] APIC base relocation is unsupported by KVM
[   95.445015] INFO: NMI handler (perf_event_nmi_handler) took too long to run: 1.356 msecs
[   95.445015] perf: interrupt took too long (3985 > 3976), lowering kernel.perf_event_max_sample_rate to 50000
`: ``,

		`
[   92.396607] general protection fault: 0000 [#1] [ 387.811073] audit: type=1326 audit(1486238739.637:135): auid=4294967295 uid=0 gid=0 ses=4294967295 pid=10020 comm="syz-executor1" exe="/root/syz-executor1" sig=31 arch=c000003e syscall=202 compat=0 ip=0x44fad9 code=0x0
`: `general protection fault: 0000 [#1] [ 387.NUM] audit: type=1326 audit(ADDR.637:LINE): auid=ADDR uid=0 gid=0 ses=ADDR pid=NUM comm="syz-executor" exe="/root/s`,

		`
[   40.438790] BUG: Bad page map in process syz-executor6  pte:ffff8801a700ff00 pmd:1a700f067
[   40.447217] addr:00000000009ca000 vm_flags:00100073 anon_vma:ffff8801d16f20e0 mapping:          (null) index:9ca
[   40.457560] file:          (null) fault:          (null) mmap:          (null) readpage:          (null)
`: `BUG: Bad page map in process syz-executor  pte:ADDR pmd:ADDR`,

		`
======================================================
WARNING: possible circular locking dependency detected
4.12.0-rc2-next-20170529+ #1 Not tainted
------------------------------------------------------
kworker/u4:2/58 is trying to acquire lock:
 (&buf->lock){+.+...}, at: [<ffffffffa41b4e5b>] tty_buffer_flush+0xbb/0x3a0 drivers/tty/tty_buffer.c:221

but task is already holding lock:
 (&o_tty->termios_rwsem/1){++++..}, at: [<ffffffffa41a5601>] isig+0xa1/0x4d0 drivers/tty/n_tty.c:1100

which lock already depends on the new lock.
`: `possible deadlock in tty_buffer_flush`,

		`
Buffer I/O error on dev loop0, logical block 6, async page read
BUG: Dentry ffff880175978600{i=8bb9,n=lo}  still in use (1) [unmount of proc proc]
------------[ cut here ]------------
WARNING: CPU: 1 PID: 8922 at fs/dcache.c:1445 umount_check+0x246/0x2c0 fs/dcache.c:1436
Kernel panic - not syncing: panic_on_warn set ...
`: `BUG: Dentry still in use [unmount of proc proc]`,

		`
WARNING: kernel stack frame pointer at ffff88003e1f7f40 in migration/1:14 has bad value ffffffff85632fb0
unwind stack type:0 next_sp:          (null) mask:0x6 graph_idx:0
ffff88003ed06ef0: ffff88003ed06f78 (0xffff88003ed06f78)
`: `WARNING: kernel stack frame pointer has bad value`,

		`
BUG: Bad page state in process syz-executor9  pfn:199e00
page:ffffea00059a9000 count:0 mapcount:0 mapping:          (null) index:0x20a00
TCP: request_sock_TCPv6: Possible SYN flooding on port 20032. Sending cookies.  Check SNMP counters.
flags: 0x200000000040019(locked|uptodate|dirty|swapbacked)
raw: 0200000000040019 0000000000000000 0000000000020a00 00000000ffffffff
raw: dead000000000100 dead000000000200 0000000000000000
page dumped because: PAGE_FLAGS_CHECK_AT_FREE flag(s)
`: `BUG: Bad page state`,

		`
Kernel panic - not syncing: Couldn't open N_TTY ldisc for ptm1 --- error -12.
CPU: 1 PID: 14836 Comm: syz-executor5 Not tainted 4.12.0-rc4+ #15
Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS Bochs 01/01/2011
Call Trace:
`: `kernel panic: Couldn't open N_TTY ldisc`,

		`
===============================
[ INFO: suspicious RCU usage. ]
4.3.5+ #8 Not tainted
-------------------------------
net/ipv6/ip6_flowlabel.c:544 suspicious rcu_dereference_check() usage!

other info that might help us debug this:
`: `suspicious RCU usage at net/ipv6/ip6_flowlabel.c:LINE`,

		`[   37.991733]  [4:SdpManagerServi: 3874] KEK_PACK[3874] __add_kek :: item ffffffc822340400
[   38.018742]  [4:  system_server: 3344] logger: !@Boot_DEBUG: start networkManagement
[   38.039013]  [2:    kworker/2:1: 1608] Trustonic TEE: c01|TL_TZ_KEYSTORE: Starting
`: ``,

		`[   16.761978] [syscamera][msm_companion_pll_init::526][BIN_INFO::0x0008]
[   16.762666] [syscamera][msm_companion_pll_init::544][WAFER_INFO::0xcf80]
[   16.763144] [syscamera][msm_companion_pll_init::594][BIN_INFO::0x0008][WAFER_INFO::0xcf80][voltage 0.775]
`: ``,

		`
BUG: workqueue lockup - pool cpus=0 node=0 flags=0x0 nice=0 stuck for 32s!
`: `BUG: workqueue lockup`,

		`
BUG: spinlock already unlocked on CPU#1, migration/1/12
 lock: rcu_sched_state+0xb40/0xc20, .magic: dead4ead, .owner: <none>/-1, .owner_cpu: -1
CPU: 1 PID: 12 Comm: migration/1 Not tainted 4.3.5+ #6
Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011
 0000000000000001 ffff8801d8f6fb30 ffffffff81d0010d ffffffff837b69c0
 ffff8801d8f68340 0000000000000003 0000000000000001 0000000000000000
 ffff8801d8f6fb70 ffffffff813fba22 0000000000000046 ffff8801d8f68b80
Call Trace:
 [<ffffffff81d0010d>] __dump_stack lib/dump_stack.c:15 [inline]
 [<ffffffff81d0010d>] dump_stack+0xc1/0x124 lib/dump_stack.c:51
 [<ffffffff813fba22>] spin_dump+0x152/0x280 kernel/locking/spinlock_debug.c:67
 [<ffffffff813fc152>] spin_bug kernel/locking/spinlock_debug.c:75 [inline]
 [<ffffffff813fc152>] debug_spin_unlock kernel/locking/spinlock_debug.c:98 [inline]
 [<ffffffff813fc152>] do_raw_spin_unlock+0x1e2/0x240 kernel/locking/spinlock_debug.c:158
 [<ffffffff810108ec>] __raw_spin_unlock_irqrestore include/linux/spinlock_api_smp.h:161 [inline]
 [<ffffffff810108ec>] _raw_spin_unlock_irqrestore+0x2c/0x60 kernel/locking/spinlock.c:191
 [<ffffffff813cd204>] spin_unlock_irqrestore include/linux/spinlock.h:362 [inline]
 [<ffffffff813cd204>] __wake_up+0x44/0x50 kernel/sched/wait.c:96
 [<ffffffff8142958a>] synchronize_sched_expedited_cpu_stop+0x8a/0xa0 kernel/rcu/tree.c:3498
 [<ffffffff814dbfe8>] cpu_stopper_thread+0x1f8/0x400 kernel/stop_machine.c:442
 [<ffffffff8134237c>] smpboot_thread_fn+0x47c/0x880 kernel/smpboot.c:163
 [<ffffffff81338531>] kthread+0x231/0x2c0 kernel/kthread.c:217
 [<ffffffff82d2fbac>] ret_from_fork+0x5c/0x90 arch/x86/entry/entry_64.S:538
 `: `BUG: spinlock already unlocked`,
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
		BUG: bug1
		BUG: bug2
	`
	if !reporter.ContainsCrash([]byte(log)) {
		t.Fatalf("no crash")
	}
	if desc, _, _, _ := reporter.Parse([]byte(log)); desc != "BUG: bug1" {
		t.Fatalf("want `BUG: bug1`, found `%v`", desc)
	}

	if !reporter1.ContainsCrash([]byte(log)) {
		t.Fatalf("no crash")
	}
	if desc, _, _, _ := reporter1.Parse([]byte(log)); desc != "BUG: bug1" {
		t.Fatalf("want `BUG: bug1`, found `%v`", desc)
	}

	if !reporter2.ContainsCrash([]byte(log)) {
		t.Fatalf("no crash")
	}
	if desc, _, _, _ := reporter2.Parse([]byte(log)); desc != "BUG: bug2" {
		t.Fatalf("want `BUG: bug2`, found `%v`", desc)
	}

	if reporter3.ContainsCrash([]byte(log)) {
		t.Fatalf("found crash, should be ignored")
	}
	if desc, _, _, _ := reporter3.Parse([]byte(log)); desc != "" {
		t.Fatalf("found `%v`, should be ignored", desc)
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
		if desc, text, _, _ := reporter.Parse([]byte(log)); string(text) != text0 {
			t.Logf("log:\n%s", log)
			t.Logf("want text:\n%s", text0)
			t.Logf("got text:\n%s", text)
			t.Fatalf("bad text, desc: '%v'", desc)
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
			_, text, _, _ := reporter.Parse([]byte(test.in))
			if test.out != string(text) {
				t.Logf("expect:\n%v", test.out)
				t.Logf("got:\n%v", string(text))
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
	}
	reporter, err := NewReporter("linux", "", "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for report, guilty0 := range tests {
		if guilty := reporter.ExtractGuiltyFile([]byte(report)); guilty != guilty0 {
			t.Logf("log:\n%s", report)
			t.Logf("want guilty:\n%s", guilty0)
			t.Logf("got guilty:\n%s", guilty)
			t.Fatalf("couldn't extract guilty file")
		}
	}
}
