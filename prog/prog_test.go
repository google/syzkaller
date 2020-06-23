// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"bytes"
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

func TestGeneration(t *testing.T) {
	target, rs, iters := initTest(t)
	ct := target.DefaultChoiceTable()
	for i := 0; i < iters; i++ {
		target.Generate(rs, 20, ct)
	}
}

func TestDefault(t *testing.T) {
	target, _, _ := initTest(t)
	ForeachType(target.Syscalls, func(typ Type, ctx TypeCtx) {
		arg := typ.DefaultArg(ctx.Dir)
		if !isDefault(arg) {
			t.Errorf("default arg is not default: %s\ntype: %#v\narg: %#v",
				typ, typ, arg)
		}
	})
}

func TestDefaultCallArgs(t *testing.T) {
	testEachTarget(t, func(t *testing.T, target *Target) {
		for _, meta := range target.SyscallMap {
			if meta.Attrs.Disabled {
				continue
			}
			// Ensure that we can restore all arguments of all calls.
			prog := fmt.Sprintf("%v()", meta.Name)
			p, err := target.Deserialize([]byte(prog), NonStrict)
			if err != nil {
				t.Fatalf("failed to restore default args in prog %q: %v", prog, err)
			}
			if len(p.Calls) != 1 || p.Calls[0].Meta.Name != meta.Name {
				t.Fatalf("restored bad program from prog %q: %q", prog, p.Serialize())
			}
			s0 := string(p.Serialize())
			p.sanitizeFix()
			s1 := string(p.Serialize())
			if s0 != s1 {
				t.Fatalf("non-sanitized program or non-idempotent sanitize\nwas: %v\ngot: %v", s0, s1)
			}
		}
	})
}

func testSerialize(t *testing.T, verbose bool) {
	target, rs, iters := initTest(t)
	ct := target.DefaultChoiceTable()
	for i := 0; i < iters; i++ {
		p := target.Generate(rs, 10, ct)
		var data []byte
		mode := NonStrict
		if verbose {
			data = p.SerializeVerbose()
			mode = Strict
		} else {
			data = p.Serialize()
		}
		p1, err := target.Deserialize(data, mode)
		if err != nil {
			t.Fatalf("failed to deserialize program: %v\n%s", err, data)
		}
		if p1 == nil {
			t.Fatalf("deserialized nil program:\n%s", data)
		}
		var data1 []byte
		if verbose {
			data1 = p1.SerializeVerbose()
		} else {
			data1 = p1.Serialize()
		}
		if len(p.Calls) != len(p1.Calls) {
			t.Fatalf("different number of calls")
		}
		if !bytes.Equal(data, data1) {
			t.Fatalf("program changed after serialize/deserialize\noriginal:\n%s\n\nnew:\n%s\n", data, data1)
		}
	}
}

func TestSerialize(t *testing.T) {
	testSerialize(t, false)
}

func TestSerializeVerbose(t *testing.T) {
	testSerialize(t, true)
}

func TestVmaType(t *testing.T) {
	target, rs, iters := initRandomTargetTest(t, "test", "64")
	ct := target.DefaultChoiceTable()
	meta := target.SyscallMap["test$vma0"]
	r := newRand(target, rs)
	pageSize := target.PageSize
	for i := 0; i < iters; i++ {
		s := newState(target, ct, nil)
		calls := r.generateParticularCall(s, meta)
		c := calls[len(calls)-1]
		if c.Meta.Name != "test$vma0" {
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
	ct := target.DefaultChoiceTable()
	rs := randSource(t)
	iters := 100
	if testing.Short() {
		iters /= 10
	}
	for i := 0; i < iters; i++ {
		p := target.Generate(rs, 20, ct)
		testCrossArchProg(t, p, crossTargets)
		p, err := target.Deserialize(p.Serialize(), NonStrict)
		if err != nil {
			t.Fatal(err)
		}
		testCrossArchProg(t, p, crossTargets)
		p.Mutate(rs, 20, ct, nil)
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
		_, err := crossTarget.Deserialize(serialized, NonStrict)
		if err == nil || strings.Contains(err.Error(), "unknown syscall") {
			continue
		}
		t.Fatalf("failed to deserialize for %v/%v: %v\n%s",
			crossTarget.OS, crossTarget.Arch, err, serialized)
	}
}

func TestSpecialStructs(t *testing.T) {
	testEachTargetRandom(t, func(t *testing.T, target *Target, rs rand.Source, iters int) {
		_ = target.GenerateAllSyzProg(rs)
		ct := target.DefaultChoiceTable()
		for special, gen := range target.SpecialTypes {
			t.Run(special, func(t *testing.T) {
				var typ Type
				for i := 0; i < len(target.Syscalls) && typ == nil; i++ {
					ForeachCallType(target.Syscalls[i], func(t Type, ctx TypeCtx) {
						if ctx.Dir == DirOut {
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
				g := &Gen{newRand(target, rs), newState(target, ct, nil)}
				for i := 0; i < iters/len(target.SpecialTypes); i++ {
					var arg Arg
					for i := 0; i < 2; i++ {
						arg, _ = gen(g, typ, DirInOut, arg)
						if arg.Dir() != DirInOut {
							t.Fatalf("got wrong arg dir %v", arg.Dir())
						}
					}
				}
			})
		}
	})
}

func TestEscapingPaths(t *testing.T) {
	paths := map[string]bool{
		"/":                      true,
		"/\x00":                  true,
		"/file/..":               true,
		"/file/../..":            true,
		"./..":                   true,
		"..":                     true,
		"file/../../file":        true,
		"../file":                true,
		"./file/../../file/file": true,
		"":                       false,
		".":                      false,
		"file":                   false,
		"./file":                 false,
		"./file/..":              false,
	}
	for path, want := range paths {
		got := escapingFilename(path)
		if got != want {
			t.Errorf("path %q: got %v, want %v", path, got, want)
		}
	}
}

func TestFallbackSignal(t *testing.T) {
	type desc struct {
		prog string
		info []CallInfo
	}
	tests := []desc{
		// Test restored errno values and that non-executed syscalls don't get fallback signal.
		{
			`
fallback$0()
fallback$0()
fallback$0()
`,
			[]CallInfo{
				{
					Flags:  CallExecuted,
					Errno:  0,
					Signal: make([]uint32, 1),
				},
				{
					Flags:  CallExecuted,
					Errno:  42,
					Signal: make([]uint32, 1),
				},
				{},
			},
		},
		// Test different cases of argument-dependent signal and that unsuccessful calls don't get it.
		{
			`
r0 = fallback$0()
fallback$1(r0)
fallback$1(r0)
fallback$1(0xffffffffffffffff)
fallback$1(0x0)
fallback$1(0x0)
`,
			[]CallInfo{
				{
					Flags:  CallExecuted,
					Errno:  0,
					Signal: make([]uint32, 1),
				},
				{
					Flags:  CallExecuted,
					Errno:  1,
					Signal: make([]uint32, 1),
				},
				{
					Flags:  CallExecuted,
					Errno:  0,
					Signal: make([]uint32, 2),
				},
				{
					Flags:  CallExecuted,
					Errno:  0,
					Signal: make([]uint32, 1),
				},
				{
					Flags:  CallExecuted,
					Errno:  0,
					Signal: make([]uint32, 2),
				},
				{
					Flags:  CallExecuted,
					Errno:  2,
					Signal: make([]uint32, 1),
				},
			},
		},
		// Test that calls get no signal after a successful seccomp.
		{
			`
fallback$0()
fallback$0()
breaks_returns()
fallback$0()
breaks_returns()
fallback$0()
fallback$0()
`,
			[]CallInfo{
				{
					Flags:  CallExecuted,
					Errno:  0,
					Signal: make([]uint32, 1),
				},
				{
					Flags:  CallExecuted,
					Errno:  0,
					Signal: make([]uint32, 1),
				},
				{
					Flags:  CallExecuted,
					Errno:  1,
					Signal: make([]uint32, 1),
				},
				{
					Flags: CallExecuted,
					Errno: 0,
				},
				{
					Flags: CallExecuted,
					Errno: 0,
				},
				{
					Flags: CallExecuted,
				},
				{
					Flags: CallExecuted,
				},
			},
		},
		{
			`
fallback$0()
breaks_returns()
fallback$0()
breaks_returns()
fallback$0()
`,
			[]CallInfo{
				{
					Flags:  CallExecuted,
					Errno:  0,
					Signal: make([]uint32, 1),
				},
				{
					Flags:  CallExecuted,
					Errno:  1,
					Signal: make([]uint32, 1),
				},
				{
					Flags: CallExecuted,
					Errno: 0,
				},
				{
					Flags: CallExecuted,
					Errno: 0,
				},
				{
					Flags: CallExecuted,
				},
			},
		},
	}
	target, err := GetTarget("test", "64")
	if err != nil {
		t.Fatal(err)
	}
	for i, test := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			p, err := target.Deserialize([]byte(test.prog), Strict)
			if err != nil {
				t.Fatal(err)
			}
			if len(p.Calls) != len(test.info) {
				t.Fatalf("call=%v info=%v", len(p.Calls), len(test.info))
			}
			wantSignal := make([]int, len(test.info))
			for i := range test.info {
				wantSignal[i] = len(test.info[i].Signal)
				test.info[i].Signal = nil
			}
			p.FallbackSignal(test.info)
			for i := range test.info {
				if len(test.info[i].Signal) != wantSignal[i] {
					t.Errorf("call %v: signal=%v want=%v", i, len(test.info[i].Signal), wantSignal[i])
				}
				for _, sig := range test.info[i].Signal {
					call, errno := DecodeFallbackSignal(sig)
					if call != p.Calls[i].Meta.ID {
						t.Errorf("call %v: sig=%x id=%v want=%v", i, sig, call, p.Calls[i].Meta.ID)
					}
					if errno != test.info[i].Errno {
						t.Errorf("call %v: sig=%x errno=%v want=%v", i, sig, errno, test.info[i].Errno)
					}
				}
			}
		})
	}
}

func TestSanitizeRandom(t *testing.T) {
	testEachTargetRandom(t, func(t *testing.T, target *Target, rs rand.Source, iters int) {
		ct := target.DefaultChoiceTable()
		for i := 0; i < iters; i++ {
			p := target.Generate(rs, 10, ct)
			s0 := string(p.Serialize())
			p.sanitizeFix()
			s1 := string(p.Serialize())
			if s0 != s1 {
				t.Fatalf("non-sanitized program or non-idempotent sanitize\nwas: %v\ngot: %v", s0, s1)
			}
		}
	})
}
