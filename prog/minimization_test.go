// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/hash"
)

// nolint:gocyclo
func TestMinimize(t *testing.T) {
	attempt := 0
	// nolint: lll
	tests := []struct {
		os              string
		arch            string
		mode            MinimizeMode
		orig            string
		callIndex       int
		pred            func(*Prog, int) bool
		result          string
		resultCallIndex int
	}{
		// Predicate always returns false, so must get the same program.
		{
			"linux", "amd64", MinimizeCorpus,
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
			"linux", "amd64", MinimizeCorpus,
			"mmap(&(0x7f0000000000/0x1000)=nil, 0x1000, 0x3, 0x32, 0xffffffffffffffff, 0x0)\n" +
				"sched_yield()\n" +
				"pipe2(&(0x7f0000000000)={0xffffffffffffffff, 0xffffffffffffffff}, 0x0)\n",
			2,
			func(p *Prog, callIndex int) bool {
				// Aim at removal of sched_yield.
				return len(p.Calls) == 2 && p.Calls[0].Meta.Name == "mmap" && p.Calls[1].Meta.Name == "pipe2"
			},
			"mmap(&(0x7f0000000000/0x1000)=nil, 0x1000, 0x3, 0x32, 0xffffffffffffffff, 0x0)\n" +
				"pipe2(0x0, 0x0)\n",
			1,
		},
		// Remove two dependent calls.
		{
			"linux", "amd64", MinimizeCorpus,
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
			"linux", "amd64", MinimizeCorpus,
			"mmap(&(0x7f0000000000/0x1000)=nil, 0x1000, 0x3, 0x32, 0xffffffffffffffff, 0x0)\n" +
				"pipe2(&(0x7f0000000000)={<r0=>0x0, 0x0}, 0x0)\n" +
				"write(r0, &(0x7f0000000000)=\"1155\", 0x2)\n" +
				"sched_yield()\n",
			3,
			func(p *Prog, callIndex int) bool {
				return p.String() == "mmap-write-sched_yield"
			},
			"mmap(&(0x7f0000000000/0x1000)=nil, 0x1000, 0x3, 0x32, 0xffffffffffffffff, 0x0)\n" +
				"write(0xffffffffffffffff, 0x0, 0x0)\n" +
				"sched_yield()\n",
			2,
		},
		// Remove a call and replace results.
		{
			"linux", "amd64", MinimizeCorpus,
			"mmap(&(0x7f0000000000/0x1000)=nil, 0x1000, 0x3, 0x32, 0xffffffffffffffff, 0x0)\n" +
				"r0=open(&(0x7f0000000000)=\"1155\", 0x0, 0x0)\n" +
				"write(r0, &(0x7f0000000000)=\"1155\", 0x2)\n" +
				"sched_yield()\n",
			-1,
			func(p *Prog, callIndex int) bool {
				return p.String() == "mmap-write-sched_yield"
			},
			"mmap(&(0x7f0000000000/0x1000)=nil, 0x1000, 0x3, 0x32, 0xffffffffffffffff, 0x0)\n" +
				"write(0xffffffffffffffff, 0x0, 0x0)\n" +
				"sched_yield()\n",
			-1,
		},
		// Minimize pointer.
		{
			"linux", "amd64", MinimizeCorpus,
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
			"linux", "amd64", MinimizeCorpus,
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
			"test", "64", MinimizeCorpus,
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
			"test", "64", MinimizeCorpus,
			"minimize$0(0x1, 0x1)\n",
			-1,
			func(p *Prog, callIndex int) bool { return len(p.Calls) == 1 },
			"minimize$0(0x1, 0x1)\n",
			-1,
		},
		// Clear unneeded fault injection.
		{
			"linux", "amd64", MinimizeCorpus,
			"pipe2(0x0, 0x0) (fail_nth: 5)\n",
			-1,
			func(p *Prog, callIndex int) bool {
				return len(p.Calls) == 1 && p.Calls[0].Meta.Name == "pipe2"
			},
			"pipe2(0x0, 0x0)\n",
			-1,
		},
		// Keep important fault injection.
		{
			"linux", "amd64", MinimizeCorpus,
			"pipe2(0x0, 0x0) (fail_nth: 5)\n",
			-1,
			func(p *Prog, callIndex int) bool {
				return len(p.Calls) == 1 && p.Calls[0].Meta.Name == "pipe2" && p.Calls[0].Props.FailNth == 5
			},
			"pipe2(0x0, 0x0) (fail_nth: 5)\n",
			-1,
		},
		// Clear unneeded async flag.
		{
			"linux", "amd64", MinimizeCorpus,
			"pipe2(0x0, 0x0) (async)\n",
			-1,
			func(p *Prog, callIndex int) bool {
				return len(p.Calls) == 1 && p.Calls[0].Meta.Name == "pipe2"
			},
			"pipe2(0x0, 0x0)\n",
			-1,
		},
		// Keep important async flag.
		{
			"linux", "amd64", MinimizeCorpus,
			"pipe2(0x0, 0x0) (async)\n",
			-1,
			func(p *Prog, callIndex int) bool {
				return len(p.Calls) == 1 && p.Calls[0].Meta.Name == "pipe2" && p.Calls[0].Props.Async
			},
			"pipe2(0x0, 0x0) (async)\n",
			-1,
		},
		// Clear unneeded rerun.
		{
			"linux", "amd64", MinimizeCorpus,
			"pipe2(0x0, 0x0) (rerun: 100)\n",
			-1,
			func(p *Prog, callIndex int) bool {
				return len(p.Calls) == 1 && p.Calls[0].Meta.Name == "pipe2"
			},
			"pipe2(0x0, 0x0)\n",
			-1,
		},
		// Keep important rerun.
		{
			"linux", "amd64", MinimizeCorpus,
			"pipe2(0x0, 0x0) (rerun: 100)\n",
			-1,
			func(p *Prog, callIndex int) bool {
				return len(p.Calls) == 1 && p.Calls[0].Meta.Name == "pipe2" && p.Calls[0].Props.Rerun >= 100
			},
			"pipe2(0x0, 0x0) (rerun: 100)\n",
			-1,
		},
		// Undo target.SpecialFileLenghts mutation (reduce file name length).
		{
			"test", "64", MinimizeCrash,
			"mutate9(&(0x7f0000000000)='./file0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\\x00')\n",
			0,
			func(p *Prog, callIndex int) bool {
				return p.Calls[0].Args[0].(*PointerArg).Res != nil
			},
			"mutate9(&(0x7f0000000000)='./file0\\x00')\n",
			0,
		},
		// Ensure `no_minimize` calls are untouched.
		{
			"linux", "amd64", MinimizeCorpus,
			"syz_mount_image$ext4(&(0x7f0000000000)='ext4\\x00', &(0x7f0000000100)='./file0\\x00', 0x0, &(0x7f0000010020), 0x1, 0x15, &(0x7f0000000200)=\"$eJwqrqzKTszJSS0CBAAA//8TyQPi\")\n",
			0,
			func(p *Prog, callIndex int) bool {
				// Anything is allowed except removing a call.
				return len(p.Calls) > 0
			},
			"syz_mount_image$ext4(&(0x7f0000000000)='ext4\\x00', &(0x7f0000000100)='./file0\\x00', 0x0, &(0x7f0000010020), 0x1, 0x15, &(0x7f0000000200)=\"$eJwqrqzKTszJSS0CBAAA//8TyQPi\")\n",
			0,
		},
		// Test for removeUnrelatedCalls.
		// We test exact candidates we get on each step.
		// First candidate should be removal of the trailing calls, which we reject.
		// Next candidate is removal of unrelated calls, which we accept.
		{
			"linux", "amd64", MinimizeCorpus,
			`
getpid()
r0 = open(&(0x7f0000000040)='./file0', 0x0, 0x0)
r1 = open(&(0x7f0000000040)='./file1', 0x0, 0x0)
getuid()
read(r1, &(0x7f0000000040), 0x10)
read(r0, &(0x7f0000000040), 0x10)
pipe(&(0x7f0000000040)={<r2=>0x0, <r3=>0x0})
creat(&(0x7f0000000040)='./file0', 0x0)
close(r1)
sendfile(r0, r2, &(0x7f0000000040), 0x1)
getgid()
fcntl$getflags(r0, 0x0)
getpid()
close(r3)
getuid()
			`,
			11,
			func(p *Prog, callIndex int) bool {
				pp := strings.TrimSpace(string(p.Serialize()))
				if attempt == 0 {
					if pp == strings.TrimSpace(`
getpid()
r0 = open(&(0x7f0000000040)='./file0', 0x0, 0x0)
r1 = open(&(0x7f0000000040)='./file1', 0x0, 0x0)
getuid()
read(r1, &(0x7f0000000040), 0x10)
read(r0, &(0x7f0000000040), 0x10)
pipe(&(0x7f0000000040)={<r2=>0x0, 0x0})
creat(&(0x7f0000000040)='./file0', 0x0)
close(r1)
sendfile(r0, r2, &(0x7f0000000040), 0x1)
getgid()
fcntl$getflags(r0, 0x0)
					`) {
						return false
					}
				} else if attempt == 1 {
					if pp == strings.TrimSpace(`
r0 = open(&(0x7f0000000040)='./file0', 0x0, 0x0)
read(r0, &(0x7f0000000040), 0x10)
pipe(&(0x7f0000000040)={<r1=>0x0, <r2=>0x0})
creat(&(0x7f0000000040)='./file0', 0x0)
sendfile(r0, r1, &(0x7f0000000040), 0x1)
fcntl$getflags(r0, 0x0)
close(r2)
					`) {
						return true
					}
				} else {
					return false
				}
				panic(fmt.Sprintf("unexpected candidate on attempt %v:\n%v", attempt, pp))
			},
			`
r0 = open(&(0x7f0000000040)='./file0', 0x0, 0x0)
read(r0, &(0x7f0000000040), 0x10)
pipe(&(0x7f0000000040)={<r1=>0x0, <r2=>0x0})
creat(&(0x7f0000000040)='./file0', 0x0)
sendfile(r0, r1, &(0x7f0000000040), 0x1)
fcntl$getflags(r0, 0x0)
close(r2)
			`,
			5,
		},
	}
	t.Parallel()
	for ti, test := range tests {
		t.Run(fmt.Sprint(ti), func(t *testing.T) {
			target, err := GetTarget(test.os, test.arch)
			if err != nil {
				t.Fatal(err)
			}
			p, err := target.Deserialize([]byte(strings.TrimSpace(test.orig)), Strict)
			if err != nil {
				t.Fatalf("failed to deserialize original program #%v: %v", ti, err)
			}
			attempt = 0
			pred := func(p *Prog, callIndex int) bool {
				res := test.pred(p, callIndex)
				attempt++
				return res
			}
			p1, ci := Minimize(p, test.callIndex, test.mode, pred)
			res := strings.TrimSpace(string(p1.Serialize()))
			expect := strings.TrimSpace(test.result)
			if res != expect {
				t.Fatalf("minimization produced wrong result #%v\norig:\n%v\nexpect:\n%v\ngot:\n%v",
					ti, test.orig, expect, res)
			}
			if ci != test.resultCallIndex {
				t.Fatalf("minimization broke call index #%v: got %v, want %v",
					ti, ci, test.resultCallIndex)
			}
		})
	}
}

func TestMinimizeRandom(t *testing.T) {
	target, rs, iters := initTest(t)
	iters /= 10 // Long test.
	ct := target.DefaultChoiceTable()
	r := rand.New(rs)
	for i := 0; i < iters; i++ {
		for _, mode := range []MinimizeMode{MinimizeCorpus, MinimizeCrash} {
			p := target.Generate(rs, 5, ct)
			copyP := p.Clone()
			seen := make(map[string]bool)
			seen[hash.String(p.Serialize())] = true
			minP, _ := Minimize(p, len(p.Calls)-1, mode, func(p1 *Prog, callIndex int) bool {
				id := hash.String(p1.Serialize())
				if seen[id] {
					t.Fatalf("program:\n%s\nobserved the same candidate twice:\n%s",
						p.Serialize(), p1.Serialize())
				}
				seen[id] = true
				if r.Intn(2) == 0 {
					return false
				}
				copyP = p1.Clone()
				return true
			})
			got := string(minP.Serialize())
			want := string(copyP.Serialize())
			if got != want {
				t.Fatalf("program:\n%s\ngot:\n%s\nwant:\n%s", p.Serialize(), got, want)
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
		mode := MinimizeCorpus
		if r.Intn(2) == 0 {
			mode = MinimizeCrash
		}
		p1, ci1 := Minimize(p, ci, mode, func(p1 *Prog, callIndex int) bool {
			return r.Intn(2) == 0
		})
		if ci1 < 0 || ci1 >= len(p1.Calls) || p.Calls[ci].Meta.Name != p1.Calls[ci1].Meta.Name {
			t.Fatalf("bad call index after minimization")
		}
	}
}
