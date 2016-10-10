// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/syzkaller/symbolizer"
)

func TestParse(t *testing.T) {
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
BUG: unable to handle kernel paging request at 00000000ffffff8a
IP: [<ffffffff810a376f>] __call_rcu.constprop.76+0x1f/0x280 kernel/rcu/tree.c:3046
`: `BUG: unable to handle kernel paging request in __call_rcu`,

		`
[ 1581.999813] BUG: unable to handle kernel paging request at ffffea0000f0e440
[ 1581.999824] IP: [<ffffea0000f0e440>] 0xffffea0000f0e440
`: `BUG: unable to handle kernel paging request`,

		`
[   50.583499] something
[   50.583499] INFO: rcu_sched self-detected stall on CPU
[   50.583499]         0: (20822 ticks this GP) idle=94b/140000000000001/0
`: `INFO: rcu_sched self-detected stall on CPU`,

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
==================================================================
BUG: KASAN: slab-out-of-bounds in memcpy+0x1d/0x40 at addr ffff88003a6bd110
Read of size 8 by task a.out/6260
`: `KASAN: slab-out-of-bounds Read of size 8 in memcpy`,

		`
[   50.583499] BUG: KASAN: use-after-free in remove_wait_queue+0xfb/0x120 at addr ffff88002db3cf50
[   50.583499] Write of size 8 by task syzkaller_execu/10568 
`: `KASAN: use-after-free Write of size 8 in remove_wait_queue`,

		`
[23818.431954] BUG: KASAN: null-ptr-deref on address           (null)

[23818.438140] Read of size 4 by task syz-executor/22534

[23818.443211] CPU: 3 PID: 22534 Comm: syz-executor Tainted: G     U         3.18.0 #78
`: `KASAN: null-ptr-deref Read of size 4`,

		`
[  149.188010] BUG: unable to handle kernel NULL pointer dereference at 000000000000058c
unrelateed line
[  149.188010] IP: [<ffffffff8148e81d>] __lock_acquire+0x2bd/0x3410
`: `BUG: unable to handle kernel NULL pointer dereference in __lock_acquire`,

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
[ INFO: suspicious RCU usage. ]
4.3.5-smp-DEV #101 Not tainted
-------------------------------
net/core/filter.c:1917 suspicious rcu_dereference_protected() usage!
other info that might help us debug this:
`: `suspicious RCU usage at net/core/filter.c:1917`,

		`
[   80.586804] =====================================
[   80.587241] [ BUG: syz-executor/13525 still has locks held! ]
[   80.587792] 4.8.0+ #29 Not tainted
[   80.588114] -------------------------------------
[   80.588585] 1 lock held by syz-executor/13525:
[   80.588975]  #0:  (&pipe->mutex/1){+.+.+.}, at: [<ffffffff81844c8b>] pipe_lock+0x5b/0x70
[   80.589809] 
[   80.589809] stack backtrace:
[   80.590236] CPU: 2 PID: 13525 Comm: syz-executor Not tainted 4.8.0+ #29
`: `BUG: still has locks held in pipe_lock`,

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
`: `UBSAN: Undefined behaviour in drivers/usb/core/devio.c:1517:25`,

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
`: `UBSAN: Undefined behaviour in ./arch/x86/include/asm/atomic.h:156:2`,

		`
[   50.583499] UBSAN: Undefined behaviour in kernel/time/hrtimer.c:310:16
[   50.583499] signed integer overflow:
`: `UBSAN: Undefined behaviour in kernel/time/hrtimer.c:310:16`,

		`
------------[ cut here ]------------
kernel BUG at fs/buffer.c:1917!
invalid opcode: 0000 [#1] SMP
`: `kernel BUG at fs/buffer.c:1917!`,

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
`: `BUG: sleeping function called from invalid context at include/linux/wait.h:1095 `,

		`
INFO: rcu_preempt detected stalls on CPUs/tasks: { 2} (detected by 0, t=65008 jiffies, g=48068, c=48067, q=7339)
`: `INFO: rcu_preempt detected stalls`,

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
BUG UNIX (Not tainted): kasan: bad access detected
`: "",
	}
	for log, crash := range tests {
		if strings.Index(log, "\r\n") != -1 {
			continue
		}
		tests[strings.Replace(log, "\n", "\r\n", -1)] = crash
	}
	for log, crash := range tests {
		if ContainsCrash([]byte(log)) != (crash != "") {
			t.Fatalf("ContainsCrash did not find crash")
		}
		desc, _, _, _ := Parse([]byte(log))
		if desc == "" && crash != "" {
			t.Fatalf("did not find crash message '%v' in:\n%v", crash, log)
		}
		if desc != "" && crash == "" {
			t.Fatalf("found bogus crash message '%v' in:\n%v", desc, log)
		}
		if desc != crash {
			t.Fatalf("extracted bad crash message:\n%+q\nwant:\n%+q", desc, crash)
		}
	}
}

func TestReplace(t *testing.T) {
	tests := []struct {
		where  string
		start  int
		end    int
		what   string
		result string
	}{
		{"0123456789", 3, 5, "abcdef", "012abcdef56789"},
		{"0123456789", 3, 5, "ab", "012ab56789"},
		{"0123456789", 3, 3, "abcd", "012abcd3456789"},
		{"0123456789", 0, 2, "abcd", "abcd23456789"},
		{"0123456789", 0, 0, "ab", "ab0123456789"},
		{"0123456789", 10, 10, "ab", "0123456789ab"},
		{"0123456789", 8, 10, "ab", "01234567ab"},
		{"0123456789", 5, 5, "", "0123456789"},
		{"0123456789", 3, 8, "", "01289"},
		{"0123456789", 3, 8, "ab", "012ab89"},
		{"0123456789", 0, 5, "a", "a56789"},
		{"0123456789", 5, 10, "ab", "01234ab"},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("%+v", test), func(t *testing.T) {
			result := replace([]byte(test.where), test.start, test.end, []byte(test.what))
			if test.result != string(result) {
				t.Errorf("want '%v', got '%v'", test.result, string(result))
			}
		})
	}
}

func TestSymbolizeLine(t *testing.T) {
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
			"WARNING: CPU: 2 PID: 2636 at ipc/shm.c:162 foo+0x101/0x185\n",
		},
		// Tricky function name.
		{
			"    [<ffffffff84e5bea0>] do_ipv6_setsockopt.isra.7.part.3+0x101/0x2830 \n",
			"    [<ffffffff84e5bea0>] do_ipv6_setsockopt.isra.7.part.3+0x101/0x2830 net.c:111 \n",
		},
		// Inlined frames.
		{
			"    [<ffffffff84e5bea0>] foo+0x141/0x185\n",
			"    [<     inline     >] inlined1 net.c:111\n" +
				"    [<     inline     >] inlined2 mm.c:222\n" +
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
