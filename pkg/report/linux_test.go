// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"bytes"
	"fmt"
	"regexp"
	"testing"

	"github.com/google/syzkaller/pkg/symbolizer"
)

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

func TestLinuxParseLog(t *testing.T) {
	type ParseLogTest struct {
		Log  string
		Oops string
	}
	tests := []ParseLogTest{
		{
			`
2017/11/27 07:13:57 executing program 2:
mmap(&(0x7f0000000000/0xfff000)=nil, 0xfff000, 0x3, 0x32, 0xffffffffffffffff, 0x0)
pipe(&(0x7f0000860000-0x8)={<r0=>0xffffffffffffffff, <r1=>0xffffffffffffffff})
vmsplice(r1, &(0x7f0000ee7000-0x70)=[{&(0x7f00006b9000-0xcc)="2069fde890af3c8d3b6f7cc9b10207e66d9b649333016bb8e60d1898a65497520f52d08ef979093a9d7ff6c8f15c7d33bd887ceed473c03ddf53f1abfb394f56ba9a58663c4625b2fd20e42c3634dea7cbaa13af1c486edca29b0f20cd0f6f9e58863da6a4813592a092994e34f99c8bb8a57ec4c9cbb12dff54ea53142ba42b6e72", 0x82}, {&(0x7f00004ff000)="8c15a76ee72d8b37743d0a520e40aa435bd35800be1bcb2193947ea2cd5131644958b1c874", 0x25}], 0x2, 0x0)
r2 = socket$inet(0x2, 0xfffffffffffffffd, 0x4007)
setsockopt$inet_mtu(r2, 0x0, 0xa, &(0x7f0000892000)=0x3, 0x4)
mmap(&(0x7f0000000000/0xfff000)=nil, 0xfff000, 0x3, 0x32, 0xffffffffffffffff, 0x0)
ioctl$sock_SIOCGIFCONF(0xffffffffffffffff, 0x8910, &(0x7f0000000000)=@req={0x28, &(0x7f000033c000-0x28)={@generic="7e2ce949379d7b45abd44fd13199f4c7", @ifru_settings={0x0, 0x0, @fr=&(0x7f0000631000)={0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}}})
r3 = socket(0x14, 0x802, 0xffff)
ioctl$sock_ifreq(0xffffffffffffffff, 0x0, &(0x7f0000edd000)={@common="6c6f0000000000000000000000000000", @ifru_ivalue=0x0})
getsockopt$inet_int(r3, 0x0, 0x37, &(0x7f00005e9000-0x4)=0x0, &(0x7f00009d9000-0x4)=0x4)
write(r3, &(0x7f0000c07000-0x20)="1f0000005400056d0002020000000003073f00000000000000000000110000d5", 0x20)
syslog(0x1, 0x0, 0x0)
ioctl$DRM_IOCTL_CONTROL(r1, 0x40086414, &(0x7f0000f20000-0x8)={0x2, 0x5e2})
setsockopt$inet_opts(r2, 0x0, 0x4, &(0x7f00006ec000)="8907040000", 0x5)
sendto$inet(r2, &(0x7f00002e6000)="51918cf29f669c7deb5294775dad77984cac8d8ec96b07bf44f6e534a50979dff39532ce5629eb5a8ce530f4a2aa939b2d024f3afcf558cb118297f99eeebb999643463acfca3ac63911e0d9502b916c4585c5d8d0a155f0b497d1a1aa2fe94c7b7897ff72ee", 0x66, 0x8800, &(0x7f0000654000-0x10)={0x2, 0x2, @rand_addr=0x4, [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]}, 0x10)
splice(r0, 0x0, r2, 0x0, 0x8dc6, 0x2)
socketpair(0xb, 0x5, 0x0, &(0x7f000065f000)={0x0, 0x0})
[   53.722692] ==================================================================
[   53.730124] BUG: KASAN: use-after-free in aead_recvmsg+0x1758/0x1bc0
[   53.736605] Read of size 4 at addr ffff8801c1afdb5c by task syz-executor5/3568
[   53.743949] 
[   53.745574] CPU: 1 PID: 3568 Comm: syz-executor5 Not tainted 4.14.0-next-20171127+ #52
[   53.753624] Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011
[   53.762966] Call Trace:
[   53.765717]  dump_stack+0x194/0x257
[   53.765733]  ? arch_local_irq_restore+0x53/0x53
[   53.765747]  ? show_regs_print_info+0x65/0x65
[   53.765765]  ? af_alg_make_sg+0x510/0x510
[   53.765775]  ? aead_recvmsg+0x1758/0x1bc0
[   53.765791]  print_address_description+0x73/0x250
[   53.765801]  ? aead_recvmsg+0x1758/0x1bc0
[   53.765813]  kasan_report+0x25b/0x340
[   53.765831]  __asan_report_load4_noabort+0x14/0x20
[   53.765839]  aead_recvmsg+0x1758/0x1bc0
[   53.765886]  ? aead_release+0x50/0x50
[   53.765906]  ? selinux_socket_recvmsg+0x36/0x40
[   53.765917]  ? security_socket_recvmsg+0x91/0xc0
[   53.765931]  ? aead_release+0x50/0x50
[   53.765942]  sock_recvmsg+0xc9/0x110
[   53.765950]  ? __sock_recv_wifi_status+0x210/0x210
[   53.765965]  ___sys_recvmsg+0x29b/0x630
[   53.765990]  ? ___sys_sendmsg+0x8a0/0x8a0
[   53.765999]  ? lock_downgrade+0x980/0x980
[   53.766055]  ? _raw_spin_unlock_irq+0x27/0x70
[   53.766069]  ? trace_hardirqs_on_caller+0x421/0x5c0
[   53.766080]  ? trace_hardirqs_on+0xd/0x10
[   53.766089]  ? _raw_spin_unlock_irq+0x27/0x70
[   53.766100]  ? task_work_run+0x1f4/0x270
[   53.766126]  ? __fdget+0x18/0x20
[   53.766146]  __sys_recvmsg+0xe2/0x210
[   53.766153]  ? __sys_recvmsg+0xe2/0x210
[   53.766166]  ? SyS_sendmmsg+0x60/0x60
[   53.766191]  ? SyS_futex+0x269/0x390
[   53.766225]  ? trace_hardirqs_on_caller+0x421/0x5c0
[   53.766246]  SyS_recvmsg+0x2d/0x50
[   53.766260]  entry_SYSCALL_64_fastpath+0x1f/0x96
[   53.766267] RIP: 0033:0x452879
[   53.766272] RSP: 002b:00007fab1b978be8 EFLAGS: 00000212 ORIG_RAX: 000000000000002f
[   53.766280] RAX: ffffffffffffffda RBX: 0000000000758020 RCX: 0000000000452879
[   53.766285] RDX: 0000000000002021 RSI: 0000000020b2dfc8 RDI: 0000000000000014
[   53.766290] RBP: 0000000000000086 R08: 0000000000000000 R09: 0000000000000000
[   53.766294] R10: 0000000000000000 R11: 0000000000000212 R12: 00000000006ed250
[   53.766299] R13: 00000000ffffffff R14: 00007fab1b9796d4 R15: 0000000000000000
[   53.766335] 
[   53.766339] Allocated by task 3568:
[   53.766347]  save_stack+0x43/0xd0
[   53.766352]  kasan_kmalloc+0xad/0xe0
[   53.766360]  __kmalloc+0x162/0x760
[   53.766367]  crypto_create_tfm+0x82/0x2e0
[   53.766373]  crypto_alloc_tfm+0x10e/0x2f0
[   53.766379]  crypto_alloc_skcipher+0x2c/0x40
[   53.766388]  crypto_get_default_null_skcipher+0x5f/0x80
[   53.766394]  aead_bind+0x89/0x140
[   53.766400]  alg_bind+0x1ab/0x440
[   53.766406]  SYSC_bind+0x1b4/0x3f0
[   53.766412]  SyS_bind+0x24/0x30
[   53.766418]  entry_SYSCALL_64_fastpath+0x1f/0x96
[   53.766421] 
[   53.766424] Freed by task 3568:
[   53.766430]  save_stack+0x43/0xd0
[   53.766436]  kasan_slab_free+0x71/0xc0
[   53.766442]  kfree+0xca/0x250
[   53.766450]  kzfree+0x28/0x30
[   53.766456]  crypto_destroy_tfm+0x140/0x2e0
[   53.766464]  crypto_put_default_null_skcipher+0x35/0x60
[   53.766470]  aead_sock_destruct+0x13c/0x220
[   53.766477]  __sk_destruct+0xfd/0x910
[   53.766483]  sk_destruct+0x47/0x80
[   53.766489]  __sk_free+0x57/0x230
[   53.766495]  sk_free+0x2a/0x40
[   53.766501]  af_alg_release+0x5d/0x70
[   53.766506]  sock_release+0x8d/0x1e0
[   53.766512]  sock_close+0x16/0x20
[   53.766520]  __fput+0x333/0x7f0
[   53.766526]  ____fput+0x15/0x20
[   53.766532]  task_work_run+0x199/0x270
[   53.766543]  exit_to_usermode_loop+0x296/0x310
[   53.766550]  syscall_return_slowpath+0x490/0x550
[   53.766557]  entry_SYSCALL_64_fastpath+0x94/0x96
[   53.766559] 
[   53.766564] The buggy address belongs to the object at ffff8801c1afdb40
[   53.766564]  which belongs to the cache kmalloc-128 of size 128
[   53.766570] The buggy address is located 28 bytes inside of
[   53.766570]  128-byte region [ffff8801c1afdb40, ffff8801c1afdbc0)
[   53.766573] The buggy address belongs to the page:
[   53.766579] page:ffffea000706bf40 count:1 mapcount:0 mapping:ffff8801c1afd000 index:0x0
[   53.766587] flags: 0x2fffc0000000100(slab)
[   53.766602] raw: 02fffc0000000100 ffff8801c1afd000 0000000000000000 0000000100000015
[   53.766611] raw: ffffea000707f1e0 ffffea00070fef20 ffff8801db000640 0000000000000000
[   53.766614] page dumped because: kasan: bad access detected
[   53.766616] 
[   53.766619] Memory state around the buggy address:
[   53.766625]  ffff8801c1afda00: fb fb fb fb fb fb fb fb fc fc fc fc fc fc fc fc
[   53.766631]  ffff8801c1afda80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
[   53.766637] >ffff8801c1afdb00: fc fc fc fc fc fc fc fc fb fb fb fb fb fb fb fb
[   53.766640]                                                     ^
[   53.766646]  ffff8801c1afdb80: fb fb fb fb fb fb fb fb fc fc fc fc fc fc fc fc
[   53.766652]  ffff8801c1afdc00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
[   53.766655] ==================================================================
`, `[   53.730124] BUG: KASAN: use-after-free in aead_recvmsg+0x1758/0x1bc0`,
		},
	}
	reporter, err := NewReporter("linux", "", "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range tests {
		log := []byte(test.Log)
		oops := []byte(test.Oops)
		rep := reporter.Parse(log)
		if !bytes.Equal(rep.Output, log) {
			t.Fatal("reporter.Parse returned bad Output")
		}
		startPos := bytes.Index(log, oops)
		endPos := startPos + len(oops)
		if rep.StartPos != startPos {
			t.Fatal(fmt.Sprintf("reporter.Parse returned bad StartPos: want: %v, got: %v", startPos, rep.StartPos))
		}
		if rep.EndPos != endPos {
			t.Fatal(fmt.Sprintf("reporter.Parse returned bad EndPos: want: %v, got: %v", endPos, rep.EndPos))
		}
	}
}
