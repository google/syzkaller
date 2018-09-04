package trace2syz

import (
	"bufio"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys"
	"testing"
)

var (
	OS   = "linux"
	Arch = "amd64"
	rev  = sys.GitRevision
)

func parseSingleTrace(t *testing.T, data string) *Context {
	var err error
	var target *prog.Target
	var scanner *bufio.Scanner
	var traceTree *TraceTree
	var ctx *Context

	target, err = prog.GetTarget(OS, Arch)
	if err != nil {
		t.Fatalf("Failed to load target. Revision %s\n", rev)
	}
	scanner = initialize(data)
	traceTree = parseLoop(scanner, Strace)
	ctx, err = ParseTrace(traceTree.TraceMap[traceTree.RootPid], target)
	if err != nil {
		goto errexit
	}
	if err = ctx.FillOutMemory(); err != nil {
		goto errexit
	}
	if err = ctx.Prog.Validate(); err != nil {
		goto errexit
	}
	return ctx

errexit:
	t.Fatalf("Failed to parse trace: %s", err.Error())
	return nil
}

func TestParseTraceBasic(t *testing.T) {
	test := `open("file", O_CREAT|O_RDWR) = 3` + "\n" +
		`write(3, "somedata", 8) = 8`
	ctx := parseSingleTrace(t, test)
	p := ctx.Prog
	if len(p.Calls) < 3 {
		t.Fatalf("Expected three calls. Got: %d\n", len(p.Calls))
	}
	if p.Calls[0].Meta.CallName != "mmap" {
		t.Fatalf("Expected first call to be mmap. Got: %s\n", p.Calls[0].Meta.CallName)
	}
	if p.Calls[1].Meta.CallName != "open" {
		t.Fatalf("Expected second call to be open. Got: %s\n", p.Calls[1].Meta.CallName)
	}
	if p.Calls[2].Meta.CallName != "write" {
		t.Fatalf("Expected third call to be fstat. Got: %s\n", p.Calls[2].Meta.CallName)
	}
	switch a := p.Calls[2].Args[0].(type) {
	case *prog.ResultArg:
	default:
		t.Fatalf("Expected result arg. Got: %s\n", a.Type().Name())
	}
}

func TestParseTraceInnerResource(t *testing.T) {
	test := `pipe([5,6]) = 0` + "\n" +
		`write(6, "\xff\xff\xfe\xff", 4) = 4`

	p := parseSingleTrace(t, test).Prog
	if len(p.Calls) < 3 {
		t.Fatalf("Expected three calls. Got: %d\n", len(p.Calls))
	}
	switch a := p.Calls[2].Args[0].(type) {
	case *prog.ResultArg:
	default:
		t.Fatalf("Expected result arg. Got: %s\n", a.Type().Name())
	}
}

func TestParseIpv4(t *testing.T) {
	test := `socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK, 0) = 3` + "\n" +
		`connect(3, {sa_family=AF_UNIX,` +
		`sun_path="\x2f\x76\x61\x72\x2f\x72\x75\x6e\x2f\x6e\x73\x63\x64\x2f\x73\x6f\x63\x6b\x65\x74"}, 110)` +
		`= -1 ENOENT (Bad file descriptor)`
	p := parseSingleTrace(t, test).Prog
	if len(p.Calls) < 3 {
		t.Fatalf("Expected three calls. Got: %d\n", len(p.Calls))
	}
}
