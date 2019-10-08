// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build !codeanalysis

package parser

import (
	"testing"

	_ "github.com/google/syzkaller/sys"
)

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
		<... open resumed> , 0x1|0x2) = -1 FLAG (sdfjfjfjf)
		fstat() = 0`,
		`open([0x1, 0x2], NULL, {tv_sec=5, tv_nsec=0}, 8 <unfinished ...>
		<... rt_sigtimedwait resumed> )   = 10 (SIGUSR1)
		fstat() = 0`,
		`open(0, 536892418, {c_cc[VMIN]=1, c_cc[VTIME]=0} <unfinished ...>
		<... open resumed> , 0x1|0x2) = -1 FLAG (sdfjfjfjf)
		fstat() = 0`,
		`open(-19) = 0
		 fstat() = 0`,
		`open(1 + 2) = 0
		 fstat() = 0`,
		`open(3 - 1) = 0
		 fstat() = 0`,
		`open(1075599392, 0x20000000) = -1 EBADF (Bad file descriptor)
		 fstat() = 0`,
		`open() = -1 EIO (Input/output error)
		 fstat() = 0`,
		`open(113->114) = -1 EIO (Input/output error)
		 fstat() = 0`,
	}

	for _, test := range tests {
		tree, err := ParseData([]byte(test))
		if err != nil {
			t.Fatal(err)
		}
		if tree.RootPid != -1 {
			t.Fatalf("Incorrect Root Pid: %d", tree.RootPid)
		}

		calls := tree.TraceMap[tree.RootPid].Calls
		if len(calls) != 2 {
			t.Fatalf("expected 2 calls. Got %d instead", len(calls))
		}
		if calls[0].CallName != "open" || calls[1].CallName != "fstat" {
			t.Fatalf("call list should be open->fstat. Got %s->%s", calls[0].CallName, calls[1].CallName)
		}
	}
}

func TestEvaluateExpressions(t *testing.T) {
	type ExprTest struct {
		line         string
		expectedEval uint64
	}
	tests := []ExprTest{
		{"open(0x1) = 0", 1},
		{"open(1) = 0", 1},
		{"open(0x1|0x2) = 0", 3},
		{"open(0x1|2) = 0", 3},
		{"open(1 << 5) = 0", 32},
		{"open(1 << 5|1) = 0", 33},
		{"open(1 & 0) = 0", 0},
		{"open(1 + 2) = 0", 3},
		{"open(1-2) = 0", ^uint64(0)},
		{"open(4 >> 1) = 0", 2},
		{"open(0700) = 0", 448},
		{"open(0) = 0", 0},
	}
	for i, test := range tests {
		tree, err := ParseData([]byte(test.line))
		if err != nil {
			t.Fatal(err)
		}
		if tree.RootPid != -1 {
			t.Fatalf("failed test: %d. Incorrect Root Pid: %d", i, tree.RootPid)
		}
		calls := tree.TraceMap[tree.RootPid].Calls
		if len(calls) != 1 {
			t.Fatalf("failed test: %d. Expected 1 call. Got %d instead", i, len(calls))
		}
		arg, ok := calls[0].Args[0].(Constant)
		if !ok {
			t.Fatalf("first argument expected to be constant. Got: %s", arg.String())
		}
		if arg.Val() != test.expectedEval {
			t.Fatalf("expected %v != %v", test.expectedEval, arg.Val())
		}
	}
}

func TestParseLoopPid(t *testing.T) {
	data := `1  open() = 3
			 1  fstat() = 0`

	tree, err := ParseData([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if tree.RootPid != 1 {
		t.Fatalf("Incorrect Root Pid: %d", tree.RootPid)
	}

	calls := tree.TraceMap[tree.RootPid].Calls
	if len(calls) != 2 {
		t.Fatalf("Expect 2 calls. Got %d instead", len(calls))
	}
	if calls[0].CallName != "open" || calls[1].CallName != "fstat" {
		t.Fatalf("call list should be open->fstat. Got %s->%s", calls[0].CallName, calls[1].CallName)
	}
}

func TestParseLoop1Child(t *testing.T) {
	data1Child := `1 open() = 3
				   1 clone() = 2
                   2 read() = 16`

	tree, err := ParseData([]byte(data1Child))
	if err != nil {
		t.Fatal(err)
	}
	if len(tree.TraceMap) != 2 {
		t.Fatalf("Incorrect Root Pid. Expected: 2, Got %d", tree.RootPid)
	}
	if tree.RootPid != 1 {
		t.Fatalf("Incorrect Root Pid. Expected: 1, Got %d", tree.RootPid)
	}
	if tree.Ptree[tree.RootPid][0] != 2 {
		t.Fatalf("Expected child to have pid: 2. Got %d", tree.Ptree[tree.RootPid][0])
	} else {
		if len(tree.TraceMap[2].Calls) != 1 {
			t.Fatalf("Child trace should have only 1 call. Got %d", len(tree.TraceMap[2].Calls))
		}
	}
}

func TestParseLoop2Childs(t *testing.T) {
	data2Childs := `1 open() = 3
                    1 clone() = 2
                    2 read() = 16
                    1 clone() = 3
                    3 open() = 3`
	tree, err := ParseData([]byte(data2Childs))
	if err != nil {
		t.Fatal(err)
	}
	if len(tree.TraceMap) != 3 {
		t.Fatalf("Incorrect Root Pid. Expected: 3, Got %d", tree.RootPid)
	}
	if len(tree.Ptree[tree.RootPid]) != 2 {
		t.Fatalf("Expected Pid 1 to have 2 children: Got %d", len(tree.Ptree[tree.RootPid]))
	}
}

func TestParseLoop1Grandchild(t *testing.T) {
	data1Grandchild := `1 open() = 3
						1 clone() = 2
						2 clone() = 3
						3 open() = 4`
	tree, err := ParseData([]byte(data1Grandchild))
	if err != nil {
		t.Fatal(err)
	}
	if len(tree.Ptree[tree.RootPid]) != 1 {
		t.Fatalf("Expect RootPid to have 1 child. Got %d", tree.RootPid)
	}
	if len(tree.Ptree[2]) != 1 {
		t.Fatalf("Incorrect Root Pid. Expected: 3, Got %d", tree.RootPid)

	}
}

func TestParseGroupType(t *testing.T) {
	type irTest struct {
		test string
	}
	tests := []irTest{
		{`open({1, 2, 3}) = 0`},
		{`open([1, 2, 3]) = 0`},
		{`open([1 2 3]) = 0`},
	}
	for _, test := range tests {
		tree, err := ParseData([]byte(test.test))
		if err != nil {
			t.Fatal(err)
		}
		call := tree.TraceMap[tree.RootPid].Calls[0]
		_, ok := call.Args[0].(*GroupType)
		if !ok {
			t.Fatalf("Expected Group type. Got: %#v", call.Args[0])
		}
	}
}
