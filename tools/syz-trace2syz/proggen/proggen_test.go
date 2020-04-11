// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build !codeanalysis

package proggen

import (
	"bytes"
	"strings"
	"testing"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/tools/syz-trace2syz/parser"
)

func TestParse(t *testing.T) {
	type Test struct {
		input  string
		output string
	}
	tests := []Test{
		{`
open("file", 66) = 3
write(3, "somedata", 8) = 8
`, `
r0 = open(&(0x7f0000000000)='file\x00', 0x42, 0x0)
write(r0, &(0x7f0000000040)='somedata', 0x8)
`,
		}, {`
pipe([5,6]) = 0
write(6, "\xff\xff\xfe\xff", 4) = 4
`, `
pipe(&(0x7f0000000000)={0xffffffffffffffff, <r0=>0xffffffffffffffff})
write(r0, &(0x7f0000000040)="fffffeff", 0x4)
`,
		}, {`
pipe({0x0, 0x1}) = 0
shmget(0x0, 0x1, 0x2, 0x3) = 0
`, `
pipe(&(0x7f0000000000))
shmget(0x0, 0x1, 0x2, &(0x7f0000001000/0x1)=nil)
`,
		}, {`
socket(29, 3, 1) = 3
getsockopt(-1, 132, 119, 0x200005c0, [14]) = -1 EBADF (Bad file descriptor)
`, `
socket$can_raw(0x1d, 0x3, 0x1)
getsockopt$inet_sctp6_SCTP_RESET_STREAMS(0xffffffffffffffff, 0x84, 0x77, &(0x7f0000000000), &(0x7f0000000040)=0x8)
`,
		}, {`
inotify_init() = 2
open("tmp", 66) = 3
inotify_add_watch(3, "\x2e", 0xfff) = 3
write(3, "temp", 4) = 4
inotify_rm_watch(2, 3) = 0
`, `
r0 = inotify_init()
r1 = open(&(0x7f0000000000)='tmp\x00', 0x42, 0x0)
r2 = inotify_add_watch(r1, &(0x7f0000000040)='.\x00', 0xfff)
write(r1, &(0x7f0000000080)='temp', 0x4)
inotify_rm_watch(r0, r2)
`,
		}, {`
socket(1, 1, 0) = 3
socket(1, 1 | 2048, 0) = 3
socket(1, 1 | 524288, 0) = 3
socket(1, 1 | 524288, 0) = 3
`, `
socket$unix(0x1, 0x1, 0x0)
socket$unix(0x1, 0x801, 0x0)
socket$unix(0x1, 0x80001, 0x0)
socket$unix(0x1, 0x80001, 0x0)
`,
		}, {`
open("temp", 1) = 3
connect(3, {sa_family=2, sin_port=37957, sin_addr=0x0}, 16) = -1
`, `
r0 = open(&(0x7f0000000000)='temp\x00', 0x1, 0x0)
connect(r0, &(0x7f0000000040)=@in={0x2, 0x9445}, 0x80)
`,
		}, {`
open("temp", 1) = 3
connect(3, {sa_family=1, sun_path="temp"}, 110) = -1
`, `
r0 = open(&(0x7f0000000000)='temp\x00', 0x1, 0x0)
connect(r0, &(0x7f0000000040)=@un=@file={0x1, 'temp\x00'}, 0x80)
`,
		}, {`
open("temp", 1) = 3
bind(5, {sa_family=16, nl_pid=0x2, nl_groups=00000003}, 12)  = -1
`, `
open(&(0x7f0000000000)='temp\x00', 0x1, 0x0)
bind(0x5, &(0x7f0000000040)=@nl=@proc={0x10, 0x2, 0x3}, 0x80)
`,
		}, {`
socket(17, 3, 768)  = 3
ioctl(3, 35111, {ifr_name="\x6c\x6f", ifr_hwaddr=00:00:00:00:00:00}) = 0
`, `
r0 = socket$packet(0x11, 0x3, 0x300)
ioctl$sock_ifreq(r0, 0x8927, &(0x7f0000000000)={'lo\x00'})
`,
		}, {`
socket(1, 1, 0) = 3
connect(3, {sa_family=1, sun_path="temp"}, 110) = -1 ENOENT (Bad file descriptor)
`, `
r0 = socket$unix(0x1, 0x1, 0x0)
connect$unix(r0, &(0x7f0000000000)=@file={0x1, 'temp\x00'}, 0x6e)
`,
		}, {`
socket(1, 1, 0) = 3
`, `
socket$unix(0x1, 0x1, 0x0)
`,
		}, {`
socket(2, 1, 0) = 5
ioctl(5, 21537, [1]) = 0
`, `
r0 = socket$inet_tcp(0x2, 0x1, 0x0)
ioctl$int_in(r0, 0x5421, &(0x7f0000000000)=0x1)
`,
		}, {`
socket(2, 1, 0) = 3
setsockopt(3, 1, 2, [1], 4) = 0
`, `
r0 = socket$inet_tcp(0x2, 0x1, 0x0)
setsockopt$sock_int(r0, 0x1, 0x2, &(0x7f0000000000)=0x1, 0x4)
`,
		}, {`
9795  socket(17, 3, 768)  = 3
9795  ioctl(3, 35123, {ifr_name="\x6c\x6f", }) = 0
`, `
r0 = socket$packet(0x11, 0x3, 0x300)
ioctl$ifreq_SIOCGIFINDEX_batadv_hard(r0, 0x8933, &(0x7f0000000000)={'lo\x00'})
`,
		}, {`
open("temp", 1) = 3
connect(3, {sa_family=2, sin_port=17812, sin_addr=0x0}, 16) = -1
`, `
r0 = open(&(0x7f0000000000)='temp\x00', 0x1, 0x0)
connect(r0, &(0x7f0000000040)=@in={0x2, 0x4594}, 0x80)
`,
		}, {`
ioprio_get(1, 0) = 4
`, `
ioprio_get$pid(0x1, 0x0)
`,
		}, {`
socket(17, 2, 768) = 3
`, `
socket$packet(0x11, 0x2, 0x300)
`,
		}, {`
socket(2, 1, 0) = 3
connect(3, {sa_family=2, sin_port=17812, sin_addr=0x0}, 16) = 0
`, `
r0 = socket$inet_tcp(0x2, 0x1, 0x0)
connect$inet(r0, &(0x7f0000000000)={0x2, 0x4594}, 0x10)
`,
		}, {`
open("\x2f\x64\x65\x76\x2f\x73\x6e\x64\x2f\x73\x65\x71", 0) = 3
fsetxattr(3, "\x73\x65\x63\x75\x72\x69\x74\x79\x2e\x73\x65\x6c\x69\x6e\x75\x78","\x73\x79\x73", 4, 0) = 0
`, `
r0 = openat$sndseq(0xffffffffffffff9c, &(0x7f0000000000)='/dev/snd/seq\x00', 0x0)
fsetxattr(r0, &(0x7f0000000040)=@known='security.selinux\x00', &(0x7f0000000080)='sys\x00', 0x4, 0x0)
`,
		}, {`
socket(0x2, 0x1, 0) = 3
connect(3, {sa_family=0x2, sin_port="\x1f\x90", sin_addr="\x7f\x00\x00\x01"}, 16) = -1
`, `
r0 = socket$inet_tcp(0x2, 0x1, 0x0)
connect$inet(r0, &(0x7f0000000000)={0x2, 0x1f90, @rand_addr=0x7f000001}, 0x10)
`,
		}, {`
socket(0x2, 0x1, 0) = 3
connect(3, {sa_family=0x2, sin_port="\x1f\x90", sin_addr="\x00\x00\x00\x00\x7f\x00\x00\x01"}, 16) = -1
`, `
r0 = socket$inet_tcp(0x2, 0x1, 0x0)
connect$inet(r0, &(0x7f0000000000)={0x2, 0x1f90, @rand_addr=0x7f000001}, 0x10)
`,
		}, {`
socket(0x2, 0x1, 0) = 3
connect(3, {sa_family=0x2, sin_port="\x1f\x90", sin_addr="\x00"}, 16) = -1
`, `
r0 = socket$inet_tcp(0x2, 0x1, 0x0)
connect$inet(r0, &(0x7f0000000000)={0x2, 0x1f90}, 0x10)
`,
		}, {`
socket(0x2, 0x1, 0) = 3
connect(3, {sa_family=0x2, sin_port="\x1f\x90", sin_addr="\x00"}, 16) = -1
`, `
r0 = socket$inet_tcp(0x2, 0x1, 0x0)
connect$inet(r0, &(0x7f0000000000)={0x2, 0x1f90}, 0x10)
`,
		}, {`
connect(-1, {sa_family=0xa, sin6_port="\x30\x39",` +
			`sin6_flowinfo="\x07\x5b\xcd\x7a",` +
			`sin6_addr="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",` +
			`sin6_scope_id=4207869677}, 28) = -1
`, `
connect(0xffffffffffffffff, &(0x7f0000000000)=` +
			`@in6={0xa, 0x3039, 0x75bcd7a, @rand_addr='\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01',` +
			` 0xfacefeed}, 0x80)
`,
		}, {`
connect(-1, {sa_family=0xa, sin6_port="\x30\x39",` +
			` sin6_flowinfo="\x07\x5b\xcd\x7a",` +
			` sin6_addr="\x00\x12\x00\x34\x00\x56\x00\x78\x00\x90\x00\xab\x00\xcd\x00\xef",` +
			` sin6_scope_id=4207869677}, 28) = -1
`, `
connect(0xffffffffffffffff, &(0x7f0000000000)=` +
			`@in6={0xa, 0x3039, 0x75bcd7a, @rand_addr='\x00\x12\x004\x00V\x00x\x00\x90\x00\xab\x00\xcd\x00\xef',` +
			` 0xfacefeed}, 0x80)
`,
		}, {`
socket(0xa, 0x2, 0) = 3
sendto(3, "", 0, 0, {sa_family=0xa, sin6_port="\x4e\x24", sin6_flowinfo="\x00\x00\x00\x00",` +
			` sin6_addr="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",` +
			` sin6_scope_id=0}, 28) = -1
`, `
r0 = socket$inet6_udp(0xa, 0x2, 0x0)
sendto$inet6(r0, &(0x7f0000000000), 0x0, 0x0, &(0x7f0000000040)={0xa, 0x4e24}, 0x1c)
`,
		}, {`
open("\x2f\x64\x65\x76\x2f\x7a\x65\x72\x6f", "1") = 3
`, `
openat$zero(0xffffffffffffff9c, &(0x7f0000000000)='/dev/zero\x00', 0x31, 0x0)
`,
		}, {`
open("\x2f\x64\x65\x76\x2f\x6c\x6f\x6f\x70\x30", 0) = 3
`, `
syz_open_dev$loop(&(0x7f0000000000)='/dev/loop0\x00', 0x0, 0x0)
`,
		}, {`
open("\x2f\x64\x65\x76\x2f\x6c\x6f\x6f\x70\x31", 0) = 3
`, `
syz_open_dev$loop(&(0x7f0000000000)='/dev/loop1\x00', 0x1, 0x0)
`,
		}, {`
open("\x2f\x64\x65\x76\x2f\x62\x75\x73\x2f\x75\x73\x62\x2f\x30\x30\x31\x2f\x30\x30\x31", 0) = 3
`, `
syz_open_dev$usbfs(&(0x7f0000000000)='/dev/bus/usb/001/001\x00', 0xb, 0x0)
`,
		}, {`
openat(0xffffffffffffff9c, "\x2f\x64\x65\x76\x2f\x7a\x65\x72\x6f", 0x31, 0) = 3
`, `
openat$zero(0xffffffffffffff9c, &(0x7f0000000000)='/dev/zero\x00', 0x31, 0x0)
`}, {`
socket(0xa, 0x1, 0) = 3
setsockopt(3, 0x29, 0x2a, {gr_interface=0, gr_group={sa_family=0xa, sin6_port="\x00\x00", sin6_flowinfo=` +
			`"\x00\x00\x00\x00", sin6_addr="\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",` +
			` sin6_scope_id=0}}, 136) = 0
`, `
r0 = socket$inet6_tcp(0xa, 0x1, 0x0)
setsockopt$inet6_MCAST_JOIN_GROUP(r0, 0x29, 0x2a, ` +
			`&(0x7f0000000000)={0x0, {{0xa, 0x0, 0x0, @rand_addr='\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'}}}, 0x88)`,
		}, {
			`
openat(-100, "\x2f\x64\x65\x76\x2f\x72\x74\x63\x30", 0) = 3
ioctl(3, 0x4028700f, {enabled=0, pending=0, time={tm_sec=0, tm_min=0, tm_hour=0, tm_mday=0, tm_mon=65536,` +
				`tm_year=20865, tm_wday=0, tm_yday=0, tm_isdst=0}}) = -1 EINVAL (Invalid argument)`,
			`
r0 = openat$rtc(0xffffffffffffff9c, &(0x7f0000000000)='/dev/rtc0\x00', 0x0, 0x0)
ioctl$RTC_WKALM_SET(r0, 0x4028700f, &(0x7f0000000040)={0x0, 0x0, {0x0, 0x0, 0x0, 0x0, 0x10000, 0x5181}})`,
		},
	}
	target, err := prog.GetTarget("linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	target.ConstMap = make(map[string]uint64)
	for _, c := range target.Consts {
		target.ConstMap[c.Name] = c.Value
	}
	for _, test := range tests {
		input := strings.TrimSpace(test.input)
		tree, err := parser.ParseData([]byte(input))
		if err != nil {
			t.Fatal(err)
		}
		p := genProg(tree.TraceMap[tree.RootPid], target)
		if p == nil {
			t.Fatalf("failed to parse trace")
		}
		got := string(bytes.TrimSpace(p.Serialize()))
		want := strings.TrimSpace(test.output)
		if want != got {
			t.Errorf("input:\n%v\n\nwant:\n%v\n\ngot:\n%v", input, want, got)
		}
	}
}
