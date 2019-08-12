// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

func TestIsComplexPtr(t *testing.T) {
	target, rs, _ := initRandomTargetTest(t, "linux", "amd64")
	iters := 10
	if testing.Short() {
		iters = 1
	}
	r := newRand(target, rs)
	compl := make(map[string]bool)
	for _, meta := range target.Syscalls {
		for i := 0; i < iters; i++ {
			s := newState(target, nil, nil)
			calls := r.generateParticularCall(s, meta)
			p := &Prog{Target: target, Calls: calls}
			for _, arg := range p.complexPtrs() {
				compl[arg.Res.Type().String()] = true
			}
		}
	}
	var arr []string
	for id := range compl {
		arr = append(arr, id)
	}
	sort.Strings(arr)
	t.Log("complex types:\n" + strings.Join(arr, "\n"))
}

func TestSquash(t *testing.T) {
	target := initTargetTest(t, "test", "64")
	// nolint: lll
	tests := []struct {
		prog     string
		squashed string
	}{
		{
			`foo$any0(&(0x7f0000000000)={0x11, 0x11223344, 0x2233, 0x1122334455667788, {0x1, 0x7, 0x1, 0x1, 0x1bc, 0x4}, [{0x0, @res32=0x0, 0x0, @i8=0x44, "aabb"}, {0x0, @res64=0x1, 0x0, @i32=0x11223344, "1122334455667788"}]})`,
			`foo$any0(&(0x7f0000000000)=ANY=[@ANYBLOB="1100000044332211223300000000000088776655443322113d0079230000000000000000", @ANYRES32=0x0, @ANYBLOB="00000000000000000000000044aabb000000000000000000", @ANYRES64=0x1, @ANYBLOB="000000000000000044332211112233445566778800000000"])`,
		},
	}
	for i, test := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			p, err := target.Deserialize([]byte(test.prog), Strict)
			if err != nil {
				t.Fatalf("failed to deserialize prog: %v", err)
			}
			ptrArg := p.Calls[0].Args[0].(*PointerArg)
			if !target.isComplexPtr(ptrArg) {
				t.Fatalf("arg is not complex")
			}
			if target.ArgContainsAny(ptrArg) {
				t.Fatalf("arg is already squashed")
			}
			target.squashPtr(ptrArg, true)
			if !target.ArgContainsAny(ptrArg) {
				t.Fatalf("arg is not squashed")
			}
			p1 := strings.TrimSpace(string(p.Serialize()))
			target.squashPtr(ptrArg, true)
			p2 := strings.TrimSpace(string(p.Serialize()))
			if p1 != p2 {
				t.Fatalf("double squash changed program:\n%v\nvs:\n%v", p1, p2)
			}
			if p1 != test.squashed {
				t.Fatalf("bad squash result:\n%v\nwant:\n%v", p1, test.squashed)
			}
		})
	}
}
