// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"bytes"
	"math/rand"
	"testing"
	"time"

	"github.com/google/syzkaller/sys"
)

func init() {
	debug = true
}

func initTest(t *testing.T) (rand.Source, int) {
	t.Parallel()
	iters := 10000
	if testing.Short() {
		iters = 100
	}
	seed := int64(time.Now().UnixNano())
	rs := rand.NewSource(seed)
	t.Logf("seed=%v", seed)
	return rs, iters
}

func TestGeneration(t *testing.T) {
	rs, iters := initTest(t)
	for i := 0; i < iters; i++ {
		Generate(rs, 20, nil)
	}
}

func TestSerialize(t *testing.T) {
	rs, iters := initTest(t)
	for i := 0; i < iters; i++ {
		p := Generate(rs, 10, nil)
		data := p.Serialize()
		p1, err := Deserialize(data)
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
	rs, iters := initTest(t)
	meta := sys.CallMap["syz_test$vma0"]
	r := newRand(rs)
	for i := 0; i < iters; i++ {
		s := newState(nil)
		calls := r.generateParticularCall(s, meta)
		c := calls[len(calls)-1]
		if c.Meta.Name != "syz_test$vma0" {
			t.Fatalf("generated wrong call %v", c.Meta.Name)
		}
		if len(c.Args) != 6 {
			t.Fatalf("generated wrong number of args %v", len(c.Args))
		}
		check := func(v, l *Arg, min, max uintptr) {
			if v.Kind != ArgPointer {
				t.Fatalf("vma has bad type: %v, want %v", v.Kind, ArgPointer)
			}
			if l.Kind != ArgPageSize {
				t.Fatalf("len has bad type: %v, want %v", l.Kind, ArgPageSize)
			}
			if v.AddrPagesNum < min || v.AddrPagesNum > max {
				t.Fatalf("vma has bad number of pages: %v, want [%v-%v]", v.AddrPagesNum, min, max)
			}
			if l.AddrPage < min || l.AddrPage > max {
				t.Fatalf("len has bad number of pages: %v, want [%v-%v]", l.AddrPage, min, max)
			}
		}
		check(c.Args[0], c.Args[1], 1, 1e5)
		check(c.Args[2], c.Args[3], 5, 5)
		check(c.Args[4], c.Args[5], 7, 9)
	}
}
