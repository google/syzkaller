// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"bytes"
	"fmt"
	"testing"
)

func TestClone(t *testing.T) {
	rs, iters := initTest(t)
	for i := 0; i < iters; i++ {
		p := Generate(rs, 10, nil)
		p1 := p.Clone()
		data := p.Serialize()
		data1 := p1.Serialize()
		if !bytes.Equal(data, data1) {
			t.Fatalf("program changed after clone\noriginal:\n%s\n\nnew:\n%s\n", data, data1)
		}
	}
}

func TestMutate(t *testing.T) {
	rs, iters := initTest(t)
next:
	for i := 0; i < iters; i++ {
		p := Generate(rs, 10, nil)
		data0 := p.Serialize()
		p1 := p.Clone()
		// There is a chance that mutation will produce the same program.
		// So we check that at least 1 out of 10 mutations actually change the program.
		for try := 0; try < 10; try++ {
			p1.Mutate(rs, 10, nil, nil)
			data := p.Serialize()
			if !bytes.Equal(data0, data) {
				t.Fatalf("program changed after clone/mutate\noriginal:\n%s\n\nnew:\n%s\n", data0, data)
			}
			data1 := p1.Serialize()
			if !bytes.Equal(data, data1) {
				continue next
			}
		}
		t.Fatalf("mutation does not change program:\n%s", data0)
	}
}

func TestMutateTable(t *testing.T) {
	tests := [][2]string{
		// Insert calls.
		{
			"mmap(&(0x7f0000000000/0x1000)=nil, (0x1000), 0x3, 0x32, 0xffffffffffffffff, 0x0)\n" +
				"pipe2(&(0x7f0000000000)={0x0, 0x0}, 0x0)\n",

			"mmap(&(0x7f0000000000/0x1000)=nil, (0x1000), 0x3, 0x32, 0xffffffffffffffff, 0x0)\n" +
				"sched_yield()\n" +
				"pipe2(&(0x7f0000000000)={0x0, 0x0}, 0x0)\n",
		},
		// Remove calls and update args.
		{
			"r0 = open(&(0x7f0000001000)=\"2e2f66696c653000\", 0x22c0, 0x1)\n" +
				"sched_yield()\n" +
				"read(r0, &(0x7f0000000000)=0x0, 0x1)\n" +
				"sched_yield()\n",

			"sched_yield()\n" +
				"read(0xffffffffffffffff, &(0x7f0000000000)=0x0, 0x1)\n" +
				"sched_yield()\n",
		},
		// Mutate flags.
		{
			"r0 = open(&(0x7f0000001000)=\"2e2f66696c653000\", 0x22c0, 0x1)\n" +
				"sched_yield()\n" +
				"read(r0, &(0x7f0000000000)=0x0, 0x1)\n" +
				"sched_yield()\n",

			"r0 = open(&(0x7f0000001000)=\"2e2f66696c653000\", 0x22c0, 0x2)\n" +
				"sched_yield()\n" +
				"read(r0, &(0x7f0000000000)=0x0, 0x1)\n" +
				"sched_yield()\n",
		},
		// Mutate data (delete byte and update size).
		{
			"r0 = open(&(0x7f0000001000)=\"2e2f66696c653000\", 0x22c0, 0x1)\n" +
				"write(r0, &(0x7f0000000000)=\"11223344\", 0x4)\n",

			"r0 = open(&(0x7f0000001000)=\"2e2f66696c653000\", 0x22c0, 0x1)\n" +
				"write(r0, &(0x7f0000000000)=\"112244\", 0x3)\n",
		},
		// Mutate data (insert byte and update size).
		{
			"r0 = open(&(0x7f0000001000)=\"2e2f66696c653000\", 0x22c0, 0x1)\n" +
				"write(r0, &(0x7f0000000000)=\"1122\", 0x2)\n",

			"r0 = open(&(0x7f0000001000)=\"2e2f66696c653000\", 0x22c0, 0x1)\n" +
				"write(r0, &(0x7f0000000000)=\"112255\", 0x3)\n",
		},
		// Mutate data (change byte).
		{
			"r0 = open(&(0x7f0000001000)=\"2e2f66696c653000\", 0x22c0, 0x1)\n" +
				"write(r0, &(0x7f0000000000)=\"1122\", 0x2)\n",

			"r0 = open(&(0x7f0000001000)=\"2e2f66696c653000\", 0x22c0, 0x1)\n" +
				"write(r0, &(0x7f0000000000)=\"1155\", 0x2)\n",
		},
		// Change filename.
		{
			"open(&(0x7f0000001000)=\"2e2f66696c653000\", 0x22c0, 0x1)\n" +
				"r0 = open(&(0x7f0000001000)=\"2e2f66696c653000\", 0x22c0, 0x1)\n" +
				"write(r0, &(0x7f0000000000)=\"\", 0x0)\n",

			"open(&(0x7f0000001000)=\"2e2f66696c653000\", 0x22c0, 0x1)\n" +
				"r0 = open(&(0x7f0000001000)=\"2e2f66696c653100\", 0x22c0, 0x1)\n" +
				"write(r0, &(0x7f0000000000)=\"\", 0x0)\n",
		},
		// Extend an array.
		{
			"r0 = open(&(0x7f0000001000)=\"2e2f66696c653000\", 0x22c0, 0x1)\n" +
				"readv(r0, &(0x7f0000000000)=[{&(0x7f0000001000)=\"00\", 0x1}, {&(0x7f0000002000)=\"00\", 0x2}], 0x2)\n",

			"mmap(&(0x7f0000000000/0x1000)=nil, (0x1000), 0x3, 0x32, 0xffffffffffffffff, 0x0)\n" +
				"r0 = open(&(0x7f0000001000)=\"2e2f66696c653000\", 0x22c0, 0x1)\n" +
				"readv(r0, &(0x7f0000000000)=[{&(0x7f0000001000)=\"00\", 0x1}, {&(0x7f0000002000)=\"00\", 0x2}, {&(0x7f0000000000)=\"00\", 0x3}], 0x3)\n",
		},
	}
	rs, _ := initTest(t)
nextTest:
	for ti, test := range tests {
		p, err := Deserialize([]byte(test[0]))
		if err != nil {
			t.Fatalf("failed to deserialize original program: %v", err)
		}
		if testing.Short() {
			continue
		}
		for i := 0; i < 1e6; i++ {
			p1 := p.Clone()
			p1.Mutate(rs, 30, nil, nil)
			data1 := p1.Serialize()
			if string(data1) == test[1] {
				t.Logf("test #%v: success on iter %v", ti, i)
				continue nextTest
			}
			_ = fmt.Printf
		}
		t.Fatalf("failed to achieve mutation goal\noriginal:\n%s\n\ngoal:\n%s\n", test[0], test[1])
	}
}

func TestMinimize(t *testing.T) {
	tests := []struct {
		orig            string
		callIndex       int
		pred            func(*Prog, int) bool
		result          string
		resultCallIndex int
	}{
		// Predicate always returns false, so must get the same program.
		{
			"mmap(&(0x7f0000000000/0x1000)=nil, (0x1000), 0x3, 0x32, 0xffffffffffffffff, 0x0)\n" +
				"sched_yield()\n" +
				"pipe2(&(0x7f0000000000)={0x0, 0x0}, 0x0)\n",
			2,
			func(p *Prog, callIndex int) bool {
				if len(p.Calls) == 0 {
					t.Fatalf("got an empty program")
				}
				if p.Calls[len(p.Calls)-1].Meta.Name != "pipe2" {
					t.Fatalf("last call is removed")
				}
				return false
			},
			"mmap(&(0x7f0000000000/0x1000)=nil, (0x1000), 0x3, 0x32, 0xffffffffffffffff, 0x0)\n" +
				"sched_yield()\n" +
				"pipe2(&(0x7f0000000000)={0x0, 0x0}, 0x0)\n",
			2,
		},
		// Remove a call.
		{
			"mmap(&(0x7f0000000000/0x1000)=nil, (0x1000), 0x3, 0x32, 0xffffffffffffffff, 0x0)\n" +
				"sched_yield()\n" +
				"pipe2(&(0x7f0000000000)={0xffffffffffffffff, 0xffffffffffffffff}, 0x0)\n",
			2,
			func(p *Prog, callIndex int) bool {
				// Aim at removal of sched_yield.
				return len(p.Calls) == 2 && p.Calls[0].Meta.Name == "mmap" && p.Calls[1].Meta.Name == "pipe2"
			},
			"mmap(&(0x7f0000000000/0x1000)=nil, (0x1000), 0x0, 0x0, 0xffffffffffffffff, 0x0)\n" +
				"pipe2(&(0x7f0000000000)={0xffffffffffffffff, 0xffffffffffffffff}, 0x0)\n",
			1,
		},
		// Remove two dependent calls.
		{
			"mmap(&(0x7f0000000000/0x1000)=nil, (0x1000), 0x3, 0x32, 0xffffffffffffffff, 0x0)\n" +
				"pipe2(&(0x7f0000000000)={0x0, 0x0}, 0x0)\n" +
				"sched_yield()\n",
			2,
			func(p *Prog, callIndex int) bool {
				// Aim at removal of pipe2 and then mmap.
				if len(p.Calls) == 2 && p.Calls[0].Meta.Name == "mmap" && p.Calls[1].Meta.Name == "sched_yield" {
					return true
				}
				if len(p.Calls) == 1 && p.Calls[0].Meta.Name == "sched_yield" {
					return true
				}
				return false
			},
			"sched_yield()\n",
			0,
		},
		// Remove a call and replace results.
		{
			"mmap(&(0x7f0000000000/0x1000)=nil, (0x1000), 0x3, 0x32, 0xffffffffffffffff, 0x0)\n" +
				"pipe2(&(0x7f0000000000)={<r0=>0x0, 0x0}, 0x0)\n" +
				"write(r0, &(0x7f0000000000)=\"1155\", 0x2)\n" +
				"sched_yield()\n",
			3,
			func(p *Prog, callIndex int) bool {
				return p.String() == "mmap-write-sched_yield"
			},
			"mmap(&(0x7f0000000000/0x1000)=nil, (0x1000), 0x0, 0x0, 0xffffffffffffffff, 0x0)\n" +
				"write(0xffffffffffffffff, &(0x7f0000000000)=\"\", 0x0)\n" +
				"sched_yield()\n",
			2,
		},
		// Remove a call and replace results.
		{
			"mmap(&(0x7f0000000000/0x1000)=nil, (0x1000), 0x3, 0x32, 0xffffffffffffffff, 0x0)\n" +
				"r0=open(&(0x7f0000000000)=\"1155\", 0x0, 0x0)\n" +
				"write(r0, &(0x7f0000000000)=\"1155\", 0x2)\n" +
				"sched_yield()\n",
			-1,
			func(p *Prog, callIndex int) bool {
				return p.String() == "mmap-write-sched_yield"
			},
			"mmap(&(0x7f0000000000/0x1000)=nil, (0x1000), 0x0, 0x0, 0xffffffffffffffff, 0x0)\n" +
				"write(0xffffffffffffffff, &(0x7f0000000000)=\"\", 0x0)\n" +
				"sched_yield()\n",
			-1,
		},
		// Glue several mmaps together.
		{
			"sched_yield()\n" +
				"mmap(&(0x7f0000000000/0x1000)=nil, (0x1000), 0x3, 0x32, 0xffffffffffffffff, 0x0)\n" +
				"mmap(&(0x7f0000001000/0x1000)=nil, (0x1000), 0x3, 0x32, 0xffffffffffffffff, 0x0)\n" +
				"getpid()\n" +
				"mmap(&(0x7f0000005000/0x5000)=nil, (0x2000), 0x3, 0x32, 0xffffffffffffffff, 0x0)\n",
			3,
			func(p *Prog, callIndex int) bool {
				return p.String() == "mmap-sched_yield-getpid"
			},
			"mmap(&(0x7f0000000000/0x7000)=nil, (0x7000), 0x0, 0x0, 0xffffffffffffffff, 0x0)\n" +
				"sched_yield()\n" +
				"getpid()\n",
			2,
		},
	}
	for ti, test := range tests {
		p, err := Deserialize([]byte(test.orig))
		if err != nil {
			t.Fatalf("failed to deserialize original program #%v: %v", ti, err)
		}
		p1, ci := Minimize(p, test.callIndex, test.pred, false)
		res := p1.Serialize()
		if string(res) != test.result {
			t.Fatalf("minimization produced wrong result #%v\norig:\n%v\nexpect:\n%v\ngot:\n%v\n",
				ti, test.orig, test.result, string(res))
		}
		if ci != test.resultCallIndex {
			t.Fatalf("minimization broke call index #%v: got %v, want %v",
				ti, ci, test.resultCallIndex)
		}
	}
}

func TestMinimizeRandom(t *testing.T) {
	rs, iters := initTest(t)
	for i := 0; i < iters; i++ {
		p := Generate(rs, 10, nil)
		Minimize(p, len(p.Calls)-1, func(p1 *Prog, callIndex int) bool {
			if err := p1.validate(); err != nil {
				t.Fatalf("invalid program: %v", err)
			}
			return false
		}, true)
		Minimize(p, len(p.Calls)-1, func(p1 *Prog, callIndex int) bool {
			if err := p1.validate(); err != nil {
				t.Fatalf("invalid program: %v", err)
			}
			return true
		}, true)
	}
	for i := 0; i < iters; i++ {
		p := Generate(rs, 10, nil)
		Minimize(p, len(p.Calls)-1, func(p1 *Prog, callIndex int) bool {
			if err := p1.validate(); err != nil {
				t.Fatalf("invalid program: %v", err)
			}
			return false
		}, false)
		Minimize(p, len(p.Calls)-1, func(p1 *Prog, callIndex int) bool {
			if err := p1.validate(); err != nil {
				t.Fatalf("invalid program: %v", err)
			}
			return true
		}, false)
	}
}
