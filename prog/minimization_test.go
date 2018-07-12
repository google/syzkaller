// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"math/rand"
	"testing"
)

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
			"mmap(&(0x7f0000000000/0x1000)=nil, 0x1000, 0x3, 0x32, 0xffffffffffffffff, 0x0)\n" +
				"sched_yield()\n" +
				"pipe2(&(0x7f0000000000), 0x0)\n",
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
			"mmap(&(0x7f0000000000/0x1000)=nil, 0x1000, 0x3, 0x32, 0xffffffffffffffff, 0x0)\n" +
				"sched_yield()\n" +
				"pipe2(&(0x7f0000000000), 0x0)\n",
			2,
		},
		// Remove a call.
		{
			"mmap(&(0x7f0000000000/0x1000)=nil, 0x1000, 0x3, 0x32, 0xffffffffffffffff, 0x0)\n" +
				"sched_yield()\n" +
				"pipe2(&(0x7f0000000000)={0xffffffffffffffff, 0xffffffffffffffff}, 0x0)\n",
			2,
			func(p *Prog, callIndex int) bool {
				// Aim at removal of sched_yield.
				return len(p.Calls) == 2 && p.Calls[0].Meta.Name == "mmap" && p.Calls[1].Meta.Name == "pipe2"
			},
			"mmap(&(0x7f0000000000/0x1000)=nil, 0x1000, 0x0, 0x10, 0xffffffffffffffff, 0x0)\n" +
				"pipe2(&(0x7f0000000000), 0x0)\n",
			1,
		},
		// Remove two dependent calls.
		{
			"mmap(&(0x7f0000000000/0x1000)=nil, 0x1000, 0x3, 0x32, 0xffffffffffffffff, 0x0)\n" +
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
			"mmap(&(0x7f0000000000/0x1000)=nil, 0x1000, 0x3, 0x32, 0xffffffffffffffff, 0x0)\n" +
				"pipe2(&(0x7f0000000000)={<r0=>0x0, 0x0}, 0x0)\n" +
				"write(r0, &(0x7f0000000000)=\"1155\", 0x2)\n" +
				"sched_yield()\n",
			3,
			func(p *Prog, callIndex int) bool {
				return p.String() == "mmap-write-sched_yield"
			},
			"mmap(&(0x7f0000000000/0x1000)=nil, 0x1000, 0x0, 0x10, 0xffffffffffffffff, 0x0)\n" +
				"write(0xffffffffffffffff, &(0x7f0000000000), 0x0)\n" +
				"sched_yield()\n",
			2,
		},
		// Remove a call and replace results.
		{
			"mmap(&(0x7f0000000000/0x1000)=nil, 0x1000, 0x3, 0x32, 0xffffffffffffffff, 0x0)\n" +
				"r0=open(&(0x7f0000000000)=\"1155\", 0x0, 0x0)\n" +
				"write(r0, &(0x7f0000000000)=\"1155\", 0x2)\n" +
				"sched_yield()\n",
			-1,
			func(p *Prog, callIndex int) bool {
				return p.String() == "mmap-write-sched_yield"
			},
			"mmap(&(0x7f0000000000/0x1000)=nil, 0x1000, 0x0, 0x10, 0xffffffffffffffff, 0x0)\n" +
				"write(0xffffffffffffffff, &(0x7f0000000000), 0x0)\n" +
				"sched_yield()\n",
			-1,
		},
	}
	target, _, _ := initTest(t)
	for ti, test := range tests {
		p, err := target.Deserialize([]byte(test.orig))
		if err != nil {
			t.Fatalf("failed to deserialize original program #%v: %v", ti, err)
		}
		p1, ci := Minimize(p, test.callIndex, false, test.pred)
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
	target, rs, iters := initTest(t)
	iters /= 10 // Long test.
	for i := 0; i < iters; i++ {
		for _, crash := range []bool{false, true} {
			p := target.Generate(rs, 5, nil)
			Minimize(p, len(p.Calls)-1, crash, func(p1 *Prog, callIndex int) bool {
				return false
			})
			Minimize(p, len(p.Calls)-1, crash, func(p1 *Prog, callIndex int) bool {
				return true
			})
		}
	}
}

func TestMinimizeCallIndex(t *testing.T) {
	target, rs, iters := initTest(t)
	r := rand.New(rs)
	for i := 0; i < iters; i++ {
		p := target.Generate(rs, 5, nil)
		ci := r.Intn(len(p.Calls))
		p1, ci1 := Minimize(p, ci, r.Intn(2) == 0, func(p1 *Prog, callIndex int) bool {
			return r.Intn(2) == 0
		})
		if ci1 < 0 || ci1 >= len(p1.Calls) || p.Calls[ci].Meta.Name != p1.Calls[ci1].Meta.Name {
			t.Fatalf("bad call index after minimization")
		}
	}
}
