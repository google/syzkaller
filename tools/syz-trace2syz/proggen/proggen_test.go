// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package proggen

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/tools/syz-trace2syz/parser"
)

var (
	OS   = "linux"
	Arch = "amd64"
)

func initializeTarget(os, arch string) *prog.Target {
	target, err := prog.GetTarget(os, arch)
	if err != nil {
		log.Fatalf("%s", err)
	}
	target.ConstMap = make(map[string]uint64)
	for _, c := range target.Consts {
		target.ConstMap[c.Name] = c.Value
	}
	return target
}

func parseSingleTrace(t *testing.T, data string) *Context {
	var traceTree *parser.TraceTree
	var ctx *Context

	target := initializeTarget(OS, Arch)
	selector := NewCallSelector()
	traceTree = parser.ParseLoop(data)
	ctx = GenSyzProg(traceTree.TraceMap[traceTree.RootPid], target, selector)
	ctx.FillOutMemory()
	if err := ctx.Prog.Validate(); err != nil {
		t.Fatalf("failed to parse trace: %s", err.Error())
	}
	return ctx
}

func TestParseTraceBasic(t *testing.T) {
	test := `open("file", 66) = 3
			 write(3, "somedata", 8) = 8`
	ctx := parseSingleTrace(t, test)
	p := ctx.Prog
	expectedSeq := "open-write"
	if p.String() != expectedSeq {
		t.Fatalf("expected: %s != %s", expectedSeq, p.String())
	}
	switch a := p.Calls[1].Args[0].(type) {
	case *prog.ResultArg:
		if a.Res != p.Calls[0].Ret {
			t.Fatalf("first argument of write should equal result of open.")
		}
	default:
		t.Fatalf("expected result arg, got: %s\n", a.Type().Name())
	}
}

func TestParseTraceInnerResource(t *testing.T) {
	test := `pipe([5,6]) = 0
			 write(6, "\xff\xff\xfe\xff", 4) = 4`
	p := parseSingleTrace(t, test).Prog
	expectedSeq := "pipe-write"
	if p.String() != expectedSeq {
		t.Fatalf("Expected: %s != %s", expectedSeq, p.String())
	}
	switch a := p.Calls[1].Args[0].(type) {
	case *prog.ResultArg:
		pipeSecondFd := p.Calls[0].Args[0].(*prog.PointerArg).Res.(*prog.GroupArg).Inner[1]
		if a.Res != pipeSecondFd {
			t.Fatalf("first argument of write must match second fd from pipe")
		}
	default:
		t.Fatalf("expected result arg, got: %s\n", a.Type().Name())
	}
}

func TestNegativeResource(t *testing.T) {
	test := `socket(29, 3, 1) = 3
 			  getsockopt(-1, 132, 119, 0x200005c0, [14]) = -1 EBADF (Bad file descriptor)`

	p := parseSingleTrace(t, test).Prog
	expectedSeq := "socket$can_raw-getsockopt$inet_sctp6_SCTP_RESET_STREAMS"
	if p.String() != expectedSeq {
		t.Fatalf("expected: %s != %s", expectedSeq, p.String())
	}
	switch a := p.Calls[1].Args[0].(type) {
	case *prog.ResultArg:
		if a.Val != ^uint64(0) {
			t.Fatalf("expected resource type to be negative, got: %d", a.Val)
		}
	default:
		t.Fatalf("expected result arg, got: %s\n", a.Type().Name())
	}
}

func TestDistinguishResourceTypes(t *testing.T) {
	test := `inotify_init() = 2
			 open("tmp", 66) = 3
			 inotify_add_watch(3, "\x2e", 0xfff) = 3
	 		 write(3, "temp", 5) = 5
			 inotify_rm_watch(2, 3) = 0`
	expectedSeq := "inotify_init-open-inotify_add_watch-write-inotify_rm_watch"
	p := parseSingleTrace(t, test).Prog
	if p.String() != expectedSeq {
		t.Fatalf("Expected: %s != %s", expectedSeq, p.String())
	}
	write := p.Calls[len(p.Calls)-2]
	inotifyRmWatch := p.Calls[len(p.Calls)-1]
	switch a := write.Args[0].Type().(type) {
	case *prog.ResourceType:
		if a.TypeName != "fd" {
			t.Fatalf("expected first argument of write to have type fd, got: %s", a.TypeName)
		}
	default:
		t.Fatalf("first argument of write is not resource type: %s", a.Name())
	}
	switch a := inotifyRmWatch.Args[1].(type) {
	case *prog.ResultArg:
		b := a.Type().(*prog.ResourceType)
		if b.TypeName != "inotifydesc" {
			t.Fatalf("expected second argument of inotify_rm_watch to have type inoitfydesc, got: %s", b.TypeName)
		}
		if a.Res != p.Calls[2].Ret {
			t.Fatalf("inotify_rm_watch's second argument should match the result of inotify_add_watch.")
		}
	}
}

func TestSocketLevel(t *testing.T) {
	test := `socket(1, 1, 0) = 3
			 socket(1, 1 | 2048, 0) = 3
			 socket(1, 1 | 524288, 0) = 3
			 socket(1, 1 | 524288, 0) = 3`
	expectedSeq := "socket$unix-socket$unix-socket$unix-socket$unix"
	p := parseSingleTrace(t, test).Prog
	if p.String() != expectedSeq {
		t.Fatalf("Expected: %s != %s", expectedSeq, p.String())
	}
}

func TestIdentifySockaddrStorage(t *testing.T) {
	type identifyStorageTest struct {
		test        string
		expectedSeq string
		callIdx     int
		argIdx      int
		fieldName   string
	}
	tests := []identifyStorageTest{
		{
			`open("temp", 1) = 3
			  connect(3, {sa_family=2, sin_port=37957, sin_addr=0x0}, 16) = -1`,
			"open-connect",
			1,
			1,
			"sockaddr_in",
		},
		{
			`open("temp", 1) = 3
			  connect(3, {sa_family=1, sun_path="temp"}, 110) = -1`,
			"open-connect",
			1,
			1,
			"sockaddr_un",
		},
		{
			`open("temp", 1) = 3
			  bind(5, {sa_family=16, nl_pid=0, nl_groups=00000000}, 12)  = -1`,
			"open-bind",
			1,
			1,
			"sockaddr_nl",
		},
	}

	validator := func(arg prog.Arg, field string) error {
		var (
			storageArg *prog.UnionArg
			storagePtr *prog.PointerArg
			ok         bool
		)
		storagePtr = arg.(*prog.PointerArg)
		if storageArg, ok = storagePtr.Res.(*prog.UnionArg); !ok {
			t.Fatalf("second argument not union: %s", storagePtr.Res.Type().Name())
		}
		fieldName := storageArg.Option.Type().Name()
		if fieldName != field {
			return fmt.Errorf("incorrect storage type, expected %s != %s", field, fieldName)
		}
		return nil
	}

	for i, test := range tests {
		p := parseSingleTrace(t, test.test).Prog
		if p.String() != test.expectedSeq {
			t.Fatalf("failed btest: %d, expected: %s != %s", i, test.expectedSeq, p.String())
		}
		err := validator(p.Calls[test.callIdx].Args[test.argIdx], test.fieldName)
		if err != nil {
			t.Fatalf("failed subtest: %d with err: %s", i, err)
		}
	}
}

func TestIdentifyIfru(t *testing.T) {
	type testIfru struct {
		test        string
		expectedSeq string
	}
	tests := []testIfru{
		{
			`socket(17, 3, 768)  = 3
			 ioctl(3, 35111, {ifr_name="\x6c\x6f", ifr_hwaddr=00:00:00:00:00:00}) = 0`,
			"socket$packet-ioctl$sock_ifreq",
		},
	}

	for i, test := range tests {
		p := parseSingleTrace(t, test.test).Prog
		if p.String() != test.expectedSeq {
			t.Fatalf("failed subtest: %d, expected %s != %s", i, test.expectedSeq, p.String())
		}
	}
}

func TestParseVariants(t *testing.T) {
	type variantTest struct {
		test        string
		expectedSeq string
	}
	tests := []variantTest{
		{
			`socket(1, 1, 0) = 3
			  connect(3, {sa_family=1, sun_path="temp"}, 110) = -1 ENOENT (Bad file descriptor)`,
			"socket$unix-connect$unix",
		},
		{
			`socket(1, 1, 0) = 3`,
			"socket$unix",
		},
		{
			`socket(2, 1, 0) = 5
			  ioctl(5, 21537, [1]) = 0`,
			"socket$inet_tcp-ioctl$int_in",
		},
		{
			`socket(2, 1, 0) = 3
			  setsockopt(3, 1, 2, [1], 4) = 0`,
			"socket$inet_tcp-setsockopt$sock_int",
		},
		{
			`9795  socket(17, 3, 768)  = 3
			  9795  ioctl(3, 35123, {ifr_name="\x6c\x6f", }) = 0`,
			"socket$packet-ioctl$ifreq_SIOCGIFINDEX_team",
		},
		{
			`open("temp", 1) = 3
			  connect(3, {sa_family=2, sin_port=17812, sin_addr=0x0}, 16) = -1`,
			"open-connect",
		},
		{
			`ioprio_get(1, 0) = 4`,
			"ioprio_get$pid",
		},
		{
			`socket(17, 2, 768) = 3`,
			"socket$packet",
		},
	}

	for i, test := range tests {
		p := parseSingleTrace(t, test.test).Prog
		if p.String() != test.expectedSeq {
			t.Fatalf("failed subtest: %d, expected %s != %s", i, test.expectedSeq, p.String())
		}
	}
}

func TestParseIPv4(t *testing.T) {
	type ip4test struct {
		test        string
		expectedSeq string
		ip4         uint64
	}
	tests := []ip4test{
		{
			`socket(2, 1, 0) = 3
			  connect(3, {sa_family=2, sin_port=17812, sin_addr=0x0}, 16) = 0`,
			"socket$inet_tcp-connect$inet",
			0,
		},
		{
			`socket(2, 1, 0) = 3
			  connect(3, {sa_family=2, sin_port=17812, sin_addr=0x7f000001}, 16) = 0`,
			"socket$inet_tcp-connect$inet",
			0x7f000001,
		},
	}
	testIpv4 := func(expectedIp uint64, a prog.Arg, t *testing.T) {
		sockaddr, ok := a.(*prog.PointerArg).Res.(*prog.GroupArg)
		if !ok {
			t.Fatalf("%s", a.Type().Name())
		}
		ipv4Addr, ok := sockaddr.Inner[2].(*prog.UnionArg)
		if !ok {
			t.Fatalf("expected 3rd argument to be unionArg, got %s", sockaddr.Inner[2].Type().Name())
		}
		optName := ipv4Addr.Option.Type().FieldName()
		if !strings.Contains(optName, "rand") {
			t.Fatalf("expected ip option to be random opt, got: %s", optName)
		}
		ip, ok := ipv4Addr.Option.(*prog.ConstArg)
		if !ok {
			t.Fatalf("ipv4Addr option is not IntType")
		}
		if ip.Val != expectedIp {
			t.Fatalf("parsed != expected, %d != %d", ip.Val, expectedIp)
		}
	}
	for i, test := range tests {
		p := parseSingleTrace(t, test.test).Prog
		if p.String() != test.expectedSeq {
			t.Fatalf("failed subtest: %d, expected %s != %s", i, test.expectedSeq, p.String())
		}
		testIpv4(test.ip4, p.Calls[1].Args[1], t)
	}
}
