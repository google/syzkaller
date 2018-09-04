package trace2syz

import (
	"bufio"
	"strings"
	"testing"
)

func initialize(data string) *bufio.Scanner {
	buf := make([]byte, maxBufferSize)
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(buf, maxBufferSize)
	return scanner
}

func TestParseLoopBasic(t *testing.T) {
	tests := []string{
		`open() = 3` + "\n" +
			`fstat() = 0`,
		`open() = 0x73ffddabc` + "\n" +
			`fstat() = 0`,
		`open() = -1 ENOSPEC (something)` + "\n" +
			`fstat() = 0`,
		`open( ,  <unfinished ...>` + "\n" +
			`<... open resumed>) = 3` + "\n" +
			`fstat() = 0`,
		`open( ,  <unfinished ...>` + "\n" +
			`<... open resumed> , 2) = 3` + "\n" +
			`fstat() = 0`,
		`open( <unfinished ...>` + "\n" +
			`<... open resumed>) = 3` + "\n" +
			`fstat() = 0`,
		`open( <unfinished ...>` + "\n" +
			`<... open resumed>) = 0x44277ffff` + "\n" +
			`fstat() = 0`,
		`open( <unfinished ...>` + "\n" +
			`<... open resumed>) = ?` + "\n" +
			`fstat() = 0`,
		`open( <unfinished ...>` + "\n" +
			`<... open resumed>) = -1 FLAG (sdfjfjfjf)` + "\n" +
			`fstat() = 0`,
		`open(1,  <unfinished ...>` + "\n" +
			`<... open resumed> , FLAG|FLAG) = -1 FLAG (sdfjfjfjf)` + "\n" +
			`fstat() = 0`,
	}

	for _, test := range tests {
		scanner := initialize(test)
		tree := parseLoop(scanner, Strace)
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
	/*
		Parses two basic calls. Make sure the trace tree just has one entry with two calls
	*/

	data := `1  open() = 3` + "\n" +
		`1  fstat() = 0`

	scanner := initialize(data)
	tree := parseLoop(scanner, Strace)
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
	data1Child := `1 open() = 3` + "\n" +
		`1 clone() = 2` + "\n" +
		`2 read() = 16`

	scanner := initialize(data1Child)
	tree := parseLoop(scanner, Strace)
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
	data2Childs := `1 open() = 3` + "\n" +
		`1 clone() = 2` + "\n" +
		`2 read() = 16` + "\n" +
		`1 clone() = 3` + "\n" +
		`3 open() = 3`
	scanner := initialize(data2Childs)
	tree := parseLoop(scanner, Strace)
	if len(tree.Ptree) != 3 {
		t.Fatalf("Incorrect Root Pid. Expected: 3, Got %d\n", tree.RootPid)
	}
	if len(tree.Ptree[tree.RootPid]) != 2 {
		t.Fatalf("Expected Pid 1 to have 2 children: Got %d\n", len(tree.Ptree[tree.RootPid]))
	}
}

func TestParseLoop1Grandchild(t *testing.T) {
	data1Grandchild := `1 open() = 3` + "\n" +
		`1 clone() = 2` + "\n" +
		`2 clone() = 3` + "\n" +
		`3 open() = 4`
	scanner := initialize(data1Grandchild)
	tree := parseLoop(scanner, Strace)
	if len(tree.Ptree[tree.RootPid]) != 1 {
		t.Fatalf("Expect RootPid to have 1 child. Got %d\n", tree.RootPid)
	}
	if len(tree.Ptree[2]) != 1 {
		t.Fatalf("Incorrect Root Pid. Expected: 3, Got %d\n", tree.RootPid)

	}
}

func TestParseLoopIrTypes(t *testing.T) {
	//This test makes sure that we can parse various strace arguments into their proper ir type
	data := `open(MAKEDEV(1), {1, field1="\xff\xff", {1, 2, 3}` +
		`, [1, 2, 3], [1 2], field2=inet_pton("\xff\xff"), NULL, c_cc[VMIN]=1}, TCSETS or TCGETS) = 3`
	scanner := initialize(data)
	tree := parseLoop(scanner, Strace)
	syscall := tree.TraceMap[tree.RootPid].Calls[0]
	switch a := syscall.Args[0].(type) {
	case *expression:
	default:
		t.Fatalf("Expected macro type. Got: %s\n", a.Name())
	}
	switch a := syscall.Args[1].(type) {
	case *structType:
		switch b := a.Fields[1].(type) {
		case *field:
			if b.Key != "field1" {
				t.Fatalf("Expected field to be 'field'. Got %s\n", b.Key)
			}
			switch c := b.Val.(type) {
			case *bufferType:
			default:
				t.Fatalf("Expected field value to have struct type. Got %s\n", c.Name())
			}
		}

		switch b := a.Fields[2].(type) {
		case *structType:
		default:
			t.Fatalf("Expected argument to be array type. Got: %s\n", b.Name())
		}

		switch b := a.Fields[3].(type) {
		case *arrayType:
		default:
			t.Fatalf("Expected argument to be array type. Got: %s\n", b.Name())
		}

		switch b := a.Fields[4].(type) {
		case *arrayType:
			if b.Len != 1 {
				t.Fatalf("array should have only 1 element. Got %d\n", b.Len)
			}
		default:
			t.Fatalf("Expected argument to be ints type. Got: %s\n", a.Name())
		}

		switch b := a.Fields[5].(type) {
		case *field:
			switch c := b.Val.(type) {
			case *call:
			default:
				t.Fatalf("Expected field value to be innerCallType. Got: %s\n", c.Name())
			}
		default:
			t.Fatalf("Expected argument to be fields type. Got: %s\n", a.Name())
		}

		switch b := a.Fields[6].(type) {
		case *pointerType:
		default:
			t.Fatalf("Expected argument to be pointer type. Got: %s\n", b.Name())
		}

		switch b := a.Fields[7].(type) {
		case *field:
		default:
			t.Fatalf("Expected argument to be field type. Got: %s\n", b.Name())
		}

	default:
		t.Fatalf("First argument should be int, got: %s\n", a.Name())
	}
	switch a := syscall.Args[2].(type) {
	case *expression:
	default:
		t.Fatalf("Expected argument to be expression type. Got: %s\n", a.Name())
	}
}
