// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
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
				t.Fatalf("bad async assignment:\n%s", collided.Serialize())
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

func TestDoubleExecCollide(t *testing.T) {
	tests := []struct {
		os         string
		arch       string
		orig       string
		duplicated string
		shouldFail bool
	}{
		{
			"linux", "amd64",
			`r0 = openat(0xffffffffffffff9c, &AUTO='./file1\x00', 0x42, 0x1ff)
r1 = dup(r0)
r2 = dup(r1)
r3 = dup(r2)
r4 = dup(r2)
r5 = dup(r3)
`,
			`r0 = openat(0xffffffffffffff9c, &(0x7f0000000040)='./file1\x00', 0x42, 0x1ff)
r1 = dup(r0)
r2 = dup(r1)
r3 = dup(r2)
dup(r2)
dup(r3)
openat(0xffffffffffffff9c, &(0x7f0000000040)='./file1\x00', 0x42, 0x1ff)
dup(r0)
dup(r1)
dup(r2)
dup(r2)
dup(r3)
`,
			false,
		},
	}
	_, rs, iters := initTest(t)
	r := rand.New(rs)
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
			collided, err := DoubleExecCollide(p, r)
			if test.shouldFail && err == nil {
				t.Fatalf("expected to fail, but it hasn't")
			} else if !test.shouldFail && err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
			if test.duplicated != "" {
				woProps := collided.Clone()
				for _, c := range woProps.Calls {
					c.Props = CallProps{}
				}
				serialized := string(woProps.Serialize())
				if serialized != test.duplicated {
					t.Fatalf("expected:%s\ngot:%s", test.duplicated, serialized)
				}
			}
			// TODO: also test the `async` assignment.
		}
	}
}

func TestDupCallCollide(t *testing.T) {
	tests := []struct {
		os   string
		arch string
		orig string
		rets []string
	}{
		{
			"linux", "amd64",
			`r0 = openat(0xffffffffffffff9c, &AUTO='./file1\x00', 0x42, 0x1ff)
r1 = dup(r0)
r2 = dup(r1)
dup(r2)
`,
			[]string{
				`r0 = openat(0xffffffffffffff9c, &(0x7f0000000040)='./file1\x00', 0x42, 0x1ff)
dup(r0) (async)
r1 = dup(r0)
r2 = dup(r1)
dup(r2)
`,
				`r0 = openat(0xffffffffffffff9c, &(0x7f0000000040)='./file1\x00', 0x42, 0x1ff)
r1 = dup(r0)
r2 = dup(r1)
dup(r2) (async)
dup(r2)
`,
			},
		},
	}
	_, rs, iters := initTest(t)
	// Let's save resources -- we don't need that many for these small tests.
	iters = min(iters, 100)
	r := rand.New(rs)
	for _, test := range tests {
		target, err := GetTarget(test.os, test.arch)
		if err != nil {
			t.Fatal(err)
		}
		p, err := target.Deserialize([]byte(test.orig), Strict)
		if err != nil {
			t.Fatal(err)
		}
		detected := map[string]struct{}{}
		for i := 0; i < iters; i++ {
			collided, err := DupCallCollide(p, r)
			assert.NoError(t, err)
			detected[string(collided.Serialize())] = struct{}{}
		}
		for _, variant := range test.rets {
			_, exists := detected[variant]
			assert.True(t, exists)
		}
	}
}
