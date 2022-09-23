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
	ct := target.DefaultChoiceTable()
	iters := 10
	if testing.Short() {
		iters = 1
	}
	r := newRand(target, rs)
	compl := make(map[string]bool)
	for _, meta := range target.Syscalls {
		if meta.Attrs.Disabled || meta.Attrs.NoGenerate {
			continue
		}
		for i := 0; i < iters; i++ {
			s := newState(target, ct, nil)
			calls := r.generateParticularCall(s, meta)
			p := &Prog{Target: target, Calls: calls}
			for _, arg := range p.complexPtrs() {
				compl[arg.arg.Res.Type().String()] = true
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
		squashed string // leave empty if the arg must not be squashed
	}{
		{
			`foo$any0(&(0x7f0000000000)={0x11, 0x11223344, 0x2233, 0x1122334455667788, {0x1, 0x7, 0x1, 0x1, 0x1bc, 0x4}, [{@res32=0x0, @i8=0x44, "aabb"}, {@res64=0x1, @i32=0x11223344, "1122334455667788"}, {@res8=0x2, @i8=0x55, "cc"}]})`,
			`foo$any0(&(0x7f0000000000)=ANY=[@ANYBLOB="1100000044332211223300000000000088776655443322117d00bc11", @ANYRES32=0x0, @ANYBLOB="0000000044aabb00", @ANYRES64=0x1, @ANYBLOB="443322111122334455667788", @ANYRES8=0x2, @ANYBLOB="0000000000000055cc0000"])`,
		},
		{
			// Squashing of structs with out_overlay is not supported yet
			// (used to panic, see isComplexPtr).
			`
overlay_any(&(0x7f0000000000)=@overlay2={0x0, 0x0, <r0=>0x0, 0x0})
overlay_uses(0x0, 0x0, 0x0, r0)
`,
			``,
		},
	}
	for i, test := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			p, err := target.Deserialize([]byte(test.prog), Strict)
			if err != nil {
				t.Fatalf("failed to deserialize prog: %v", err)
			}
			ptrArg := p.Calls[0].Args[0].(*PointerArg)
			if test.squashed == "" {
				if target.isComplexPtr(ptrArg) {
					t.Fatalf("arg is complex and can be squashed")
				}
				return
			}
			if !target.isComplexPtr(ptrArg) {
				t.Fatalf("arg is not complex")
			}
			if target.ArgContainsAny(ptrArg) {
				t.Fatalf("arg is already squashed")
			}
			target.squashPtr(ptrArg)
			if !target.ArgContainsAny(ptrArg) {
				t.Fatalf("arg is not squashed")
			}
			p1 := strings.TrimSpace(string(p.Serialize()))
			target.squashPtr(ptrArg)
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
