// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"testing"
)

func TestFreebsdParse(t *testing.T) {
	testParse(t, "freebsd", freebsdTests)
}

var freebsdTests = map[string]string{
	`
Fatal trap 12: page fault while in kernel mode
cpuid = 0; apic id = 00
fault virtual address	= 0xffffffff12852143
fault code		= supervisor read data, page not present
instruction pointer	= 0x20:0xffffffff8102fe62
stack pointer	        = 0x28:0xfffffe009524a960
frame pointer	        = 0x28:0xfffffe009524a990
code segment		= base 0x0, limit 0xfffff, type 0x1b
			= DPL 0, pres 1, long 1, def32 0, gran 1
processor eflags	= interrupt enabled, resume, IOPL = 0
current process		= 3094 (syz-executor0)
trap number		= 12
panic: page fault
cpuid = 0
KDB: stack backtrace:
#0 0xffffffff80aada97 at kdb_backtrace+0x67
#1 0xffffffff80a6bb76 at vpanic+0x186
#2 0xffffffff80a6b9e3 at panic+0x43
#3 0xffffffff80edf832 at trap_fatal+0x322
#4 0xffffffff80edf889 at trap_pfault+0x49
#5 0xffffffff80edf0c6 at trap+0x286
#6 0xffffffff80ec3641 at calltrap+0x8
#7 0xffffffff810302fc at atrtc_settime+0xc
#8 0xffffffff80ab7361 at resettodr+0xf1
#9 0xffffffff80a7fcc6 at settime+0x156
#10 0xffffffff80a7fae5 at sys_clock_settime+0x85
#11 0xffffffff80ee0394 at amd64_syscall+0x6c4
#12 0xffffffff80ec392b at Xfast_syscall+0xfb
`: `Fatal trap 12: page fault while in kernel mode in atrtc_settime`,

	`
Fatal trap 12: page fault while in kernel mode
cpuid = 3; apic id = 03
fault virtual address	= 0xfffff7ffb48e19a8
fault code		= supervisor read data, page not present
instruction pointer	= 0x20:0xffffffff80edd52a
stack pointer	        = 0x28:0xfffffe009524a7a0
frame pointer	        = 0x28:0xfffffe009524a7a0
code segment		= base 0x0, limit 0xfffff, type 0x1b
			= DPL 0, pres 1, long 1, def32 0, gran 1
processor eflags	= interrupt enabled, resume, IOPL = 0
current process		= 40394 (syz-executor1)
trap number		= 12
panic: page fault
cpuid = 3
KDB: stack backtrace:
#0 0xffffffff80aada97 at kdb_backtrace+0x67
#1 0xffffffff80a6bb76 at vpanic+0x186
#2 0xffffffff80a6b9e3 at panic+0x43
#3 0xffffffff80edf832 at trap_fatal+0x322
#4 0xffffffff80edf889 at trap_pfault+0x49
#5 0xffffffff80edf0c6 at trap+0x286
#6 0xffffffff80ec3641 at calltrap+0x8
#7 0xffffffff80ae96e1 at m_copydata+0x61
#8 0xffffffff80c05ba7 at sctp_sosend+0x157
#9 0xffffffff80afa411 at kern_sendit+0x291
#10 0xffffffff80afa773 at sendit+0x1a3
#11 0xffffffff80afa831 at sys_sendmsg+0x61
#12 0xffffffff80ee0394 at amd64_syscall+0x6c4
#13 0xffffffff80ec392b at Xfast_syscall+0xfb
`: `Fatal trap 12: page fault while in kernel mode in sctp_sosend`,

	`
Fatal trap 9: general protection fault while in kernel mode
cpuid = 0; apic id = 00
instruction pointer	= 0x20:0xffffffff80ac2563
stack pointer	        = 0x28:0xfffffe00003bd6e0
frame pointer	        = 0x28:0xfffffe00003bd720
code segment		= base 0x0, limit 0xfffff, type 0x1b
			= DPL 0, pres 1, long 1, def32 0, gran 1
processor eflags	= resume, IOPL = 0
current process		= 51304 (syz-executor5)
trap number		= 9
panic: general protection fault
cpuid = 0
KDB: stack backtrace:
#0 0xffffffff80aada97 at kdb_backtrace+0x67
#1 0xffffffff80a6bb76 at vpanic+0x186
#2 0xffffffff80a6b9e3 at panic+0x43
#3 0xffffffff80edf832 at trap_fatal+0x322
#4 0xffffffff80edee9e at trap+0x5e
#5 0xffffffff80ec3641 at calltrap+0x8
#6 0xffffffff80a6780b at __rw_wlock_hard+0x32b
#7 0xffffffff80c65e72 at udp_close+0x142
#8 0xffffffff80af2b41 at soclose+0xe1
#9 0xffffffff80a1ace9 at closef+0x269
#10 0xffffffff80a1a7bd at fdescfree_fds+0x7d
#11 0xffffffff80a1a397 at fdescfree+0x517
#12 0xffffffff80a29348 at exit1+0x508
#13 0xffffffff80a28e3d at sys_sys_exit+0xd
#14 0xffffffff80ee0394 at amd64_syscall+0x6c4
#15 0xffffffff80ec392b at Xfast_syscall+0xfb
`: `Fatal trap 9: general protection fault while in kernel mode in udp_close`,

	`
panic: ffs_write: type 0xfffff80036275ce8 8 (0,230)
cpuid = 0
KDB: stack backtrace:
#0 0xffffffff80aada97 at kdb_backtrace+0x67
#1 0xffffffff80a6bb76 at vpanic+0x186
#2 0xffffffff80a6b9e3 at panic+0x43
#3 0xffffffff80d3611c at ffs_write+0x57c
#4 0xffffffff8104c6b1 at VOP_WRITE_APV+0x111
#5 0xffffffff80b3ade0 at vn_write+0x240
#6 0xffffffff80b36902 at vn_io_fault+0x112
#7 0xffffffff80ac8d08 at dofilewrite+0xc8
#8 0xffffffff80ac87fb at sys_write+0xdb
#9 0xffffffff80ee0394 at amd64_syscall+0x6c4
#10 0xffffffff80ec392b at Xfast_syscall+0xfb
`: `panic: ffs_write: type ADDR X (Y,Z)`,
}
