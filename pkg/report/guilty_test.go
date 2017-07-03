// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"testing"
)

func TestGuilty(t *testing.T) {
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
	for report, guilty0 := range tests {
		if guilty := ExtractGuiltyFile([]byte(report)); guilty != guilty0 {
			t.Logf("log:\n%s", report)
			t.Logf("extracted files:\n%s", extractFiles([]byte(report)))
			t.Logf("want guilty:\n%s", guilty0)
			t.Logf("got guilty:\n%s", guilty)
			t.Fatalf("couldn't extract guilty file")
		}
	}
}
