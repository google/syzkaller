// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"math/rand"
	"testing"
)

func TestMinimize(t *testing.T) {
	tests := []struct {
		os              string
		arch            string
		orig            string
		callIndex       int
		pred            func(*Prog, int) bool
		result          string
		resultCallIndex int
	}{
		// Predicate always returns false, so must get the same program.
		{
			"linux", "amd64",
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
			"linux", "amd64",
			"mmap(&(0x7f0000000000/0x1000)=nil, 0x1000, 0x3, 0x32, 0xffffffffffffffff, 0x0)\n" +
				"sched_yield()\n" +
				"pipe2(&(0x7f0000000000)={0xffffffffffffffff, 0xffffffffffffffff}, 0x0)\n",
			2,
			func(p *Prog, callIndex int) bool {
				// Aim at removal of sched_yield.
				return len(p.Calls) == 2 && p.Calls[0].Meta.Name == "mmap" && p.Calls[1].Meta.Name == "pipe2"
			},
			"mmap(&(0x7f0000000000/0x1000)=nil, 0x1000, 0x0, 0x10, 0xffffffffffffffff, 0x0)\n" +
				"pipe2(0x0, 0x0)\n",
			1,
		},
		// Remove two dependent calls.
		{
			"linux", "amd64",
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
			"linux", "amd64",
			"mmap(&(0x7f0000000000/0x1000)=nil, 0x1000, 0x3, 0x32, 0xffffffffffffffff, 0x0)\n" +
				"pipe2(&(0x7f0000000000)={<r0=>0x0, 0x0}, 0x0)\n" +
				"write(r0, &(0x7f0000000000)=\"1155\", 0x2)\n" +
				"sched_yield()\n",
			3,
			func(p *Prog, callIndex int) bool {
				return p.String() == "mmap-write-sched_yield"
			},
			"mmap(&(0x7f0000000000/0x1000)=nil, 0x1000, 0x0, 0x10, 0xffffffffffffffff, 0x0)\n" +
				"write(0xffffffffffffffff, 0x0, 0x0)\n" +
				"sched_yield()\n",
			2,
		},
		// Remove a call and replace results.
		{
			"linux", "amd64",
			"mmap(&(0x7f0000000000/0x1000)=nil, 0x1000, 0x3, 0x32, 0xffffffffffffffff, 0x0)\n" +
				"r0=open(&(0x7f0000000000)=\"1155\", 0x0, 0x0)\n" +
				"write(r0, &(0x7f0000000000)=\"1155\", 0x2)\n" +
				"sched_yield()\n",
			-1,
			func(p *Prog, callIndex int) bool {
				return p.String() == "mmap-write-sched_yield"
			},
			"mmap(&(0x7f0000000000/0x1000)=nil, 0x1000, 0x0, 0x10, 0xffffffffffffffff, 0x0)\n" +
				"write(0xffffffffffffffff, 0x0, 0x0)\n" +
				"sched_yield()\n",
			-1,
		},
		// Minimize pointer.
		{
			"linux", "amd64",
			"pipe2(&(0x7f0000001000)={0xffffffffffffffff, 0xffffffffffffffff}, 0x0)\n",
			-1,
			func(p *Prog, callIndex int) bool {
				return len(p.Calls) == 1 && p.Calls[0].Meta.Name == "pipe2"
			},
			"pipe2(0x0, 0x0)\n",
			-1,
		},
		// Minimize pointee.
		{
			"linux", "amd64",
			"pipe2(&(0x7f0000001000)={0xffffffffffffffff, 0xffffffffffffffff}, 0x0)\n",
			-1,
			func(p *Prog, callIndex int) bool {
				return len(p.Calls) == 1 && p.Calls[0].Meta.Name == "pipe2" && p.Calls[0].Args[0].(*PointerArg).Address != 0
			},
			"pipe2(&(0x7f0000001000), 0x0)\n",
			-1,
		},
		// Make sure we don't hang when minimizing resources.
		{
			"test", "64",
			"r0 = test$res0()\n" +
				"test$res1(r0)\n",
			-1,
			func(p *Prog, callIndex int) bool {
				return false
			},
			"r0 = test$res0()\n" +
				"test$res1(r0)\n",
			-1,
		},
		{
			"test", "64",
			"minimize$0(0x1, 0x1)\n",
			-1,
			func(p *Prog, callIndex int) bool { return len(p.Calls) == 1 },
			"minimize$0(0x1, 0xffffffffffffffff)\n",
			-1,
		},
	}
	t.Parallel()
	for ti, test := range tests {
		target, err := GetTarget(test.os, test.arch)
		if err != nil {
			t.Fatal(err)
		}
		p, err := target.Deserialize([]byte(test.orig), Strict)
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
	ct := target.DefaultChoiceTable()
	r := rand.New(rs)
	for i := 0; i < iters; i++ {
		for _, crash := range []bool{false, true} {
			p := target.Generate(rs, 5, ct)
			copyP := p.Clone()
			minP, _ := Minimize(p, len(p.Calls)-1, crash, func(p1 *Prog, callIndex int) bool {
				if r.Intn(2) == 0 {
					return false
				}
				copyP = p1.Clone()
				return true
			})
			got := string(minP.Serialize())
			want := string(copyP.Serialize())
			if got != want {
				t.Fatalf("program:\n%s\ngot:\n%v\nwant:\n%s", string(p.Serialize()), got, want)
			}
		}
	}
}

func TestMinimizeCallIndex(t *testing.T) {
	target, rs, iters := initTest(t)
	ct := target.DefaultChoiceTable()
	r := rand.New(rs)
	for i := 0; i < iters; i++ {
		p := target.Generate(rs, 5, ct)
		ci := r.Intn(len(p.Calls))
		p1, ci1 := Minimize(p, ci, r.Intn(2) == 0, func(p1 *Prog, callIndex int) bool {
			return r.Intn(2) == 0
		})
		if ci1 < 0 || ci1 >= len(p1.Calls) || p.Calls[ci].Meta.Name != p1.Calls[ci1].Meta.Name {
			t.Fatalf("bad call index after minimization")
		}
	}
}
