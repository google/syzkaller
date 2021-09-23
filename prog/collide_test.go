// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"math/rand"
	"testing"
)

func TestAssignRandomAsync(t *testing.T) {
	tests := []struct {
		os    string
		arch  string
		orig  string
		check func(*Prog) bool
	}{
		{
			"linux", "amd64",
			`r0 = openat(0xffffffffffffff9c, &AUTO='./file1\x00', 0x42, 0x1ff)
write(r0, &AUTO="01010101", 0x4)
read(r0, &AUTO=""/4, 0x4)
close(r0)
`,
			func(p *Prog) bool {
				return !p.Calls[0].Props.Async
			},
		},
		{
			"linux", "amd64",
			`r0 = openat(0xffffffffffffff9c, &AUTO='./file1\x00', 0x42, 0x1ff)
nanosleep(&AUTO={0x0,0x4C4B40}, &AUTO={0,0})
write(r0, &AUTO="01010101", 0x4)
read(r0, &AUTO=""/4, 0x4)
close(r0)
`,
			func(p *Prog) bool {
				return !p.Calls[0].Props.Async || !p.Calls[1].Props.Async
			},
		},
		{
			"linux", "amd64",
			`r0 = openat(0xffffffffffffff9c, &AUTO='./file1\x00', 0x42, 0x1ff)
r1 = dup(r0)
r2 = dup(r1)
r3 = dup(r2)
r4 = dup(r3)
`,
			func(p *Prog) bool {
				for _, call := range p.Calls[0 : len(p.Calls)-1] {
					if call.Props.Async {
						return false
					}
				}
				return true
			},
		},
	}
	_, rs, iters := initTest(t)
	r := rand.New(rs)
	anyAsync := false
	for _, test := range tests {
		target, err := GetTarget(test.os, test.arch)
		if err != nil {
			t.Fatal(err)
		}
		p, err := target.Deserialize([]byte(test.orig), Strict)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < iters; i++ {
			collided := AssignRandomAsync(p, r)
			if !test.check(collided) {
				t.Fatalf("bad async assignment:\n%s\n", collided.Serialize())
			}
			for _, call := range collided.Calls {
				anyAsync = anyAsync || call.Props.Async
			}
		}
	}
	if !anyAsync {
		t.Fatalf("not a single async was assigned")
	}
}
