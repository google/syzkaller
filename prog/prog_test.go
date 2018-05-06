// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"bytes"
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"
)

func TestGeneration(t *testing.T) {
	target, rs, iters := initTest(t)
	for i := 0; i < iters; i++ {
		target.Generate(rs, 20, nil)
	}
}

func TestDefault(t *testing.T) {
	target, _, _ := initTest(t)
	for _, meta := range target.Syscalls {
		ForeachType(meta, func(typ Type) {
			arg := target.defaultArg(typ)
			if !target.isDefaultArg(arg) {
				t.Errorf("default arg is not default: %s\ntype: %#v\narg: %#v",
					typ, typ, arg)
			}
		})
	}
}

func TestDefaultCallArgs(t *testing.T) {
	target, _, _ := initTest(t)
	for _, meta := range target.SyscallMap {
		// Ensure that we can restore all arguments of all calls.
		prog := fmt.Sprintf("%v()", meta.Name)
		p, err := target.Deserialize([]byte(prog))
		if err != nil {
			t.Fatalf("failed to restore default args in prog %q: %v", prog, err)
		}
		if len(p.Calls) != 1 || p.Calls[0].Meta.Name != meta.Name {
			t.Fatalf("restored bad program from prog %q: %q", prog, p.Serialize())
		}
	}
}

func TestSerialize(t *testing.T) {
	target, rs, iters := initTest(t)
	for i := 0; i < iters; i++ {
		p := target.Generate(rs, 10, nil)
		data := p.Serialize()
		p1, err := target.Deserialize(data)
		if err != nil {
			t.Fatalf("failed to deserialize program: %v\n%s", err, data)
		}
		if p1 == nil {
			t.Fatalf("deserialized nil program:\n%s", data)
		}
		data1 := p1.Serialize()
		if len(p.Calls) != len(p1.Calls) {
			t.Fatalf("different number of calls")
		}
		if !bytes.Equal(data, data1) {
			t.Fatalf("program changed after serialize/deserialize\noriginal:\n%s\n\nnew:\n%s\n", data, data1)
		}
	}
}

func TestVmaType(t *testing.T) {
	target, rs, iters := initRandomTargetTest(t, "test", "64")
	meta := target.SyscallMap["syz_test$vma0"]
	r := newRand(target, rs)
	pageSize := target.PageSize
	for i := 0; i < iters; i++ {
		s := newState(target, nil)
		calls := r.generateParticularCall(s, meta)
		c := calls[len(calls)-1]
		if c.Meta.Name != "syz_test$vma0" {
			t.Fatalf("generated wrong call %v", c.Meta.Name)
		}
		if len(c.Args) != 6 {
			t.Fatalf("generated wrong number of args %v", len(c.Args))
		}
		check := func(v, l Arg, min, max uint64) {
			va, ok := v.(*PointerArg)
			if !ok {
				t.Fatalf("vma has bad type: %v", v)
			}
			la, ok := l.(*ConstArg)
			if !ok {
				t.Fatalf("len has bad type: %v", l)
			}
			if va.VmaSize < min || va.VmaSize > max {
				t.Fatalf("vma has bad size: %v, want [%v-%v]",
					va.VmaSize, min, max)
			}
			if la.Val < min || la.Val > max {
				t.Fatalf("len has bad value: %v, want [%v-%v]",
					la.Val, min, max)
			}
		}
		check(c.Args[0], c.Args[1], 1*pageSize, 1e5*pageSize)
		check(c.Args[2], c.Args[3], 5*pageSize, 5*pageSize)
		check(c.Args[4], c.Args[5], 7*pageSize, 9*pageSize)
	}
}

// TestCrossTarget ensures that a program serialized for one arch can be
// deserialized for another arch. This happens when managers exchange
// programs via hub.
func TestCrossTarget(t *testing.T) {
	t.Parallel()
	const OS = "linux"
	var archs []string
	for _, target := range AllTargets() {
		if target.OS == OS {
			archs = append(archs, target.Arch)
		}
	}
	for _, arch := range archs {
		target, err := GetTarget(OS, arch)
		if err != nil {
			t.Fatal(err)
		}
		var crossTargets []*Target
		for _, crossArch := range archs {
			if crossArch == arch {
				continue
			}
			crossTarget, err := GetTarget(OS, crossArch)
			if err != nil {
				t.Fatal(err)
			}
			crossTargets = append(crossTargets, crossTarget)
		}
		t.Run(fmt.Sprintf("%v/%v", OS, arch), func(t *testing.T) {
			t.Parallel()
			testCrossTarget(t, target, crossTargets)
		})
	}
}

func testCrossTarget(t *testing.T, target *Target, crossTargets []*Target) {
	seed := int64(time.Now().UnixNano())
	t.Logf("seed=%v", seed)
	rs := rand.NewSource(seed)
	iters := 100
	if testing.Short() {
		iters /= 10
	}
	for i := 0; i < iters; i++ {
		p := target.Generate(rs, 20, nil)
		testCrossArchProg(t, p, crossTargets)
		p, err := target.Deserialize(p.Serialize())
		if err != nil {
			t.Fatal(err)
		}
		testCrossArchProg(t, p, crossTargets)
		p.Mutate(rs, 20, nil, nil)
		testCrossArchProg(t, p, crossTargets)
		p, _ = Minimize(p, -1, false, func(*Prog, int) bool {
			return rs.Int63()%2 == 0
		})
		testCrossArchProg(t, p, crossTargets)
	}
}

func testCrossArchProg(t *testing.T, p *Prog, crossTargets []*Target) {
	serialized := p.Serialize()
	for _, crossTarget := range crossTargets {
		_, err := crossTarget.Deserialize(serialized)
		if err == nil || strings.Contains(err.Error(), "unknown syscall") {
			continue
		}
		t.Fatalf("failed to deserialize for %v/%v: %v\n%s",
			crossTarget.OS, crossTarget.Arch, err, serialized)
	}
}

func TestSpecialStructs(t *testing.T) {
	testEachTargetRandom(t, func(t *testing.T, target *Target, rs rand.Source, iters int) {
		for special, gen := range target.SpecialTypes {
			t.Run(special, func(t *testing.T) {
				var typ Type
				for i := 0; i < len(target.Syscalls) && typ == nil; i++ {
					ForeachType(target.Syscalls[i], func(t Type) {
						if t.Dir() == DirOut {
							return
						}
						if s, ok := t.(*StructType); ok && s.Name() == special {
							typ = s
						}
						if s, ok := t.(*UnionType); ok && s.Name() == special {
							typ = s
						}
					})
				}
				if typ == nil {
					t.Fatal("can't find struct description")
				}
				g := &Gen{newRand(target, rs), newState(target, nil)}
				for i := 0; i < iters/len(target.SpecialTypes); i++ {
					arg, _ := gen(g, typ, nil)
					gen(g, typ, arg)
				}
			})
		}
	})
}
