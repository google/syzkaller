// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package kconfig

import (
	"fmt"
	"reflect"
	"testing"
)

func TestParseExpr(t *testing.T) {
	type Test struct {
		in   string
		out  string
		deps map[string]bool
		err  bool
	}
	tests := []Test{
		{
			in:  ` `,
			err: true,
		},
		{
			in:   `A`,
			out:  `A`,
			deps: map[string]bool{"A": true},
		},
		{
			in:   `A=B`,
			out:  `(A = B)`,
			deps: map[string]bool{"A": true, "B": true},
		},
		{
			in:   `!A && B`,
			out:  `(!(A) && B)`,
			deps: map[string]bool{"B": true},
		},
		{
			in:  `$(A "B")`,
			out: `$(A "B")`,
		},
		{
			in:  `"A"`,
			out: `"A"`,
		},
		{
			in:  `A||B&&C`,
			out: `(A || (B && C))`,
		},
	}
	for i, test := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			t.Logf("input: %v", test.in)
			in := test.in
			if !test.err {
				in += " Z"
			}
			p := newParser([]byte(in), "file")
			if !p.nextLine() {
				t.Fatal("nextLine failed")
			}
			ex := p.parseExpr()
			if test.err {
				if p.err == nil {
					t.Fatal("not failed")
				}
				return
			}
			if p.err != nil {
				t.Fatalf("failed: %v", p.err)
			}
			if ex.String() != test.out {
				t.Fatalf("\ngot:  %q\nwant: %q", ex, test.out)
			}
			deps := make(map[string]bool)
			ex.collectDeps(deps)
			if len(deps) != 0 && len(test.deps) != 0 && !reflect.DeepEqual(deps, test.deps) {
				t.Fatalf("\ndeps: %v\nwant: %v", deps, test.deps)
			}
			if p.Ident() != "Z" {
				t.Fatal("parsing consumed unrelated token")
			}
		})
	}
}

func TestFuzzParseExpr(t *testing.T) {
	for _, data := range []string{
		``,
		`A`,
		`A = B`,
		`A || B && C`,
		`$(A"B")`,
	} {
		FuzzParseExpr([]byte(data)[:len(data):len(data)])
	}
}
