// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package parser

import (
	"testing"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

var (
	OS   = "linux"
	Arch = "amd64"
)

func initializeTarget(os, arch string) *prog.Target {
	target, err := prog.GetTarget(os, arch)
	if err != nil {
		log.Fatalf("Failed to load target: %s", err)
	}
	target.ConstMap = make(map[string]uint64)
	for _, c := range target.Consts {
		target.ConstMap[c.Name] = c.Value
	}
	return target
}

func TestParseLoopBasic(t *testing.T) {

	tests := []string{
		`open() = 3
		fstat() = 0`,
		`open() = 0x73ffddabc
		fstat() = 0`,
		`open() = -1 ENOSPEC (something)
		fstat() = 0`,
		`open( ,  <unfinished ...>
		<... open resumed>) = 3
		fstat() = 0`,
		`open( ,  <unfinished ...>
		<... open resumed> , 2) = 3
		fstat() = 0`,
		`open( <unfinished ...>
		<... open resumed>) = 3
		fstat() = 0`,
		`open( <unfinished ...>
		<... open resumed>) = 0x44277ffff
		fstat() = 0`,
		`open( <unfinished ...>
		<... open resumed>) = ?
		fstat() = 0`,
		`open( <unfinished ...>
		<... open resumed>) = -1 FLAG (sdfjfjfjf)
		fstat() = 0`,
		`open(1,  <unfinished ...>
		<... open resumed> , FLAG|FLAG) = -1 FLAG (sdfjfjfjf)
		fstat() = 0`,
		`open([USR1 IO], NULL, {tv_sec=5, tv_nsec=0}, 8 <unfinished ...>
		<... rt_sigtimedwait resumed> )   = 10 (SIGUSR1)
		fstat() = 0`,
		`open(0, SNDCTL_TMR_START, {c_cc[VMIN]=1, c_cc[VTIME]=0} <unfinished ...>
		<... open resumed> , FLAG|FLAG) = -1 FLAG (sdfjfjfjf)
		fstat() = 0`,
		`open(-ENODEV) = 0
		 fstat() = 0`,
		`open(1 + 2) = 0
		 fstat() = 0`,
		`open(3 - 1) = 0
		 fstat() = 0`,
		`open(FS_IOC_FSSETXATTR, 0x20000000) = -1 EBADF (Bad file descriptor)
		 fstat() = 0`,
		`open() = 0 (IOPRIO_PRIO_VALUE(IOPRIO_CLASS_NONE, 4))
		 fstat() = 0`,
		`open() = -1 EIO (Input/output error)
		 fstat() = 0`,
		`open(113->114) = -1 EIO (Input/output error)
		 fstat() = 0`,
	}

	for _, test := range tests {
		tree := ParseLoop(test)
		if tree.RootPid != -1 {
			t.Fatalf("Incorrect Root Pid: %d\n", tree.RootPid)
		}

		calls := tree.TraceMap[tree.RootPid].Calls
		if len(calls) != 2 {
			t.Fatalf("Expect 2 calls. Got %d instead", len(calls))
		}
		if calls[0].CallName != "open" || calls[1].CallName != "fstat" {
			t.Fatalf("call list should be open->fstat. Got %s->%s\n", calls[0].CallName, calls[1].CallName)
		}
	}
}

func TestParseLoopPid(t *testing.T) {
	data := `1  open() = 3
			 1  fstat() = 0`

	tree := ParseLoop(data)
	if tree.RootPid != 1 {
		t.Fatalf("Incorrect Root Pid: %d\n", tree.RootPid)
	}

	calls := tree.TraceMap[tree.RootPid].Calls
	if len(calls) != 2 {
		t.Fatalf("Expect 2 calls. Got %d instead", len(calls))
	}
	if calls[0].CallName != "open" || calls[1].CallName != "fstat" {
		t.Fatalf("call list should be open->fstat. Got %s->%s\n", calls[0].CallName, calls[1].CallName)
	}
}

func TestParseLoop1Child(t *testing.T) {
	data1Child := `1 open() = 3
				   1 clone() = 2
                   2 read() = 16`

	tree := ParseLoop(data1Child)
	if len(tree.Ptree) != 2 {
		t.Fatalf("Incorrect Root Pid. Expected: 2, Got %d\n", tree.RootPid)
	}
	if tree.Ptree[tree.RootPid][0] != 2 {
		t.Fatalf("Expected child to have pid: 2. Got %d\n", tree.Ptree[tree.RootPid][0])
	} else {
		if len(tree.TraceMap[2].Calls) != 1 {
			t.Fatalf("Child trace should have only 1 call. Got %d\n", len(tree.TraceMap[2].Calls))
		}
	}
}

func TestParseLoop2Childs(t *testing.T) {
	data2Childs := `1 open() = 3
                    1 clone() = 2
                    2 read() = 16
                    1 clone() = 3
                    3 open() = 3`
	tree := ParseLoop(data2Childs)
	if len(tree.Ptree) != 3 {
		t.Fatalf("Incorrect Root Pid. Expected: 3, Got %d\n", tree.RootPid)
	}
	if len(tree.Ptree[tree.RootPid]) != 2 {
		t.Fatalf("Expected Pid 1 to have 2 children: Got %d\n", len(tree.Ptree[tree.RootPid]))
	}
}

func TestParseLoop1Grandchild(t *testing.T) {
	data1Grandchild := `1 open() = 3
						1 clone() = 2
						2 clone() = 3
						3 open() = 4`
	tree := ParseLoop(data1Grandchild)
	if len(tree.Ptree[tree.RootPid]) != 1 {
		t.Fatalf("Expect RootPid to have 1 child. Got %d\n", tree.RootPid)
	}
	if len(tree.Ptree[2]) != 1 {
		t.Fatalf("Incorrect Root Pid. Expected: 3, Got %d\n", tree.RootPid)

	}
}

func TestParseExprType(t *testing.T) {
	type irTest struct {
		test string
	}
	tests := []irTest{
		{`open(MAKEDEV(1)) = 0`},
	}
	for _, test := range tests {
		tree := ParseLoop(test.test)
		call := tree.TraceMap[tree.RootPid].Calls[0]
		_, ok := call.Args[0].(Expression)
		if !ok {
			t.Fatalf("Expected Expression type. Got: %#v", call.Args[0])
		}
	}
}

func TestParseGroupType(t *testing.T) {
	type irTest struct {
		test string
	}
	tests := []irTest{
		{`open({1, 2, 3}) = 0`},
		{`open([1, 2, 3]) = 0`},
		{`open([1 2]) = 0`},
	}
	for _, test := range tests {
		tree := ParseLoop(test.test)
		call := tree.TraceMap[tree.RootPid].Calls[0]
		_, ok := call.Args[0].(*GroupType)
		if !ok {
			t.Fatalf("Expected Group type. Got: %#v", call.Args[0])
		}
	}
}

func TestEvalFlags(t *testing.T) {
	target := initializeTarget(OS, Arch)
	type desc struct {
		test         string
		expectedEval uint64
	}
	tests := []desc{
		{test: `open(AT_FDCWD) = 0`, expectedEval: target.ConstMap["AT_FDCWD"]},
		{test: `open([BUS ALRM]) = 0`, expectedEval: target.ConstMap["SIGBUS"] | target.ConstMap["SIGALRM"]},
		{test: `open([BUS]) = 0`, expectedEval: target.ConstMap["SIGBUS"]},
		{test: `open(SNDCTL_TMR_START) = 0`, expectedEval: target.ConstMap["SNDCTL_TMR_START"]},
	}
	for i, test := range tests {
		tree := ParseLoop(test.test)
		call := tree.TraceMap[tree.RootPid].Calls[0]
		var expr Expression
		switch a := call.Args[0].(type) {
		case *GroupType:
			expr = a.Elems[0].(Expression)
		case Expression:
			expr = a
		}
		flagEval := expr.Eval(target)
		if test.expectedEval != flagEval {
			t.Fatalf("Incorrect Flag Evaluation for Test %d. Expected %v != %v", i, test.expectedEval, flagEval)
		}
	}
}
