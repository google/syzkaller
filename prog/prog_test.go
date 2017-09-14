// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"bytes"
	"fmt"
	"testing"
)

func TestGeneration(t *testing.T) {
	target, rs, iters := initTest(t)
	for i := 0; i < iters; i++ {
		target.Generate(rs, 20, nil)
	}
}

func TestDefault(t *testing.T) {
	target, _, _ := initTest(t)
	for _, meta := range target.SyscallMap {
		for _, t := range meta.Args {
			defaultArg(t)
		}
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
	target, rs, iters := initTest(t)
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
			if va.PagesNum < min || va.PagesNum > max {
				t.Fatalf("vma has bad number of pages: %v, want [%v-%v]", va.PagesNum, min, max)
			}
			if la.Val/pageSize < min || la.Val/pageSize > max {
				t.Fatalf("len has bad number of pages: %v, want [%v-%v]", la.Val/pageSize, min, max)
			}
		}
		check(c.Args[0], c.Args[1], 1, 1e5)
		check(c.Args[2], c.Args[3], 5, 5)
		check(c.Args[4], c.Args[5], 7, 9)
	}
}
