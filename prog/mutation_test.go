// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"bytes"
	"fmt"
	"math/rand"
	"sync"
	"testing"
)

func TestClone(t *testing.T) {
	target, rs, iters := initTest(t)
	for i := 0; i < iters; i++ {
		p := target.Generate(rs, 10, nil)
		p1 := p.Clone()
		data := p.Serialize()
		data1 := p1.Serialize()
		if !bytes.Equal(data, data1) {
			t.Fatalf("program changed after clone\noriginal:\n%s\n\nnew:\n%s\n", data, data1)
		}
	}
}

func TestMutateRandom(t *testing.T) {
	testEachTargetRandom(t, func(t *testing.T, target *Target, rs rand.Source, iters int) {
	next:
		for i := 0; i < iters; i++ {
			p := target.Generate(rs, 10, nil)
			data0 := p.Serialize()
			p1 := p.Clone()
			// There is a chance that mutation will produce the same program.
			// So we check that at least 1 out of 20 mutations actually change the program.
			for try := 0; try < 20; try++ {
				p1.Mutate(rs, 10, nil, nil)
				data := p.Serialize()
				if !bytes.Equal(data0, data) {
					t.Fatalf("program changed after mutate\noriginal:\n%s\n\nnew:\n%s\n",
						data0, data)
				}
				data1 := p1.Serialize()
				if bytes.Equal(data, data1) {
					continue
				}
				if _, err := target.Deserialize(data1); err != nil {
					t.Fatalf("Deserialize failed after Mutate: %v\n%s", err, data1)
				}
				continue next
			}
			t.Fatalf("mutation does not change program:\n%s", data0)
		}
	})
}

func TestMutateCorpus(t *testing.T) {
	target, rs, iters := initTest(t)
	var corpus []*Prog
	for i := 0; i < 100; i++ {
		p := target.Generate(rs, 10, nil)
		corpus = append(corpus, p)
	}
	for i := 0; i < iters; i++ {
		p1 := target.Generate(rs, 10, nil)
		p1.Mutate(rs, 10, nil, corpus)
	}
}

func TestMutateTable(t *testing.T) {
	target := initTargetTest(t, "test", "64")
	tests := [][2]string{
		// Insert a call.
		{`
mutate0()
mutate2()
`, `
mutate0()
mutate1()
mutate2()
`},
		// Remove calls and update args.
		{`
r0 = mutate5(&(0x7f0000000000)="2e2f66696c653000", 0x0)
mutate0()
mutate6(r0, &(0x7f0000000000)="00", 0x1)
mutate1()
`, `
mutate0()
mutate6(0xffffffffffffffff, &(0x7f0000000000)="00", 0x1)
mutate1()
`},
		// Mutate flags.
		{`
r0 = mutate5(&(0x7f0000000000)="2e2f66696c653000", 0x0)
mutate0()
mutate6(r0, &(0x7f0000000000)="00", 0x1)
mutate1()
`, `
r0 = mutate5(&(0x7f0000000000)="2e2f66696c653000", 0xcdcdcdcdcdcdcdcd)
mutate0()
mutate6(r0, &(0x7f0000000000)="00", 0x1)
mutate1()
`},
		// Mutate data (delete byte and update size).
		{`
mutate4(&(0x7f0000000000)="11223344", 0x4)
`, `
mutate4(&(0x7f0000000000)="112244", 0x3)
`},
		// Mutate data (insert byte and update size).
		// TODO: this is not working, because Mutate constantly tends
		// update addresses and insert mmap's.
		/*
					{`
			mutate4(&(0x7f0000000000)="1122", 0x2)
			`, `
			mutate4(&(0x7f0000000000)="112200", 0x3)
			`},
		*/
		// Mutate data (change byte).
		{`
mutate4(&(0x7f0000000000)="1122", 0x2)
`, `
mutate4(&(0x7f0000000000)="1100", 0x2)
`},
		// Change filename.
		{`
mutate5(&(0x7f0000001000)="2e2f66696c653000", 0x22c0)
mutate5(&(0x7f0000001000)="2e2f66696c653000", 0x22c0)
`, `
mutate5(&(0x7f0000001000)="2e2f66696c653000", 0x22c0)
mutate5(&(0x7f0000001000)="2e2f66696c653100", 0x22c0)
`},
		// Extend an array.
		{`
mutate3(&(0x7f0000000000)=[0x1, 0x1], 0x2)
`, `
mutate3(&(0x7f0000000000)=[0x1, 0x1, 0x1], 0x3)
`},
		// Mutate size from it's natural value.
		{`
mutate7(&(0x7f0000000000)='123', 0x3)
`, `
mutate7(&(0x7f0000000000)='123', 0x2)
`},
		// Mutate proc to the special value.
		{`
mutate8(0x2)
`, `
mutate8(0xffffffffffffffff)
`},
	}
	for ti, test := range tests {
		test := test
		t.Run(fmt.Sprint(ti), func(t *testing.T) {
			t.Parallel()
			p, err := target.Deserialize([]byte(test[0]))
			if err != nil {
				t.Fatalf("failed to deserialize original program: %v", err)
			}
			goal, err := target.Deserialize([]byte(test[1]))
			if err != nil {
				t.Fatalf("failed to deserialize goal program: %v", err)
			}
			want := goal.Serialize()
			enabled := make(map[*Syscall]bool)
			for _, c := range p.Calls {
				enabled[c.Meta] = true
			}
			for _, c := range goal.Calls {
				enabled[c.Meta] = true
			}
			ct := target.BuildChoiceTable(nil, enabled)
			rs := rand.NewSource(0)
			for i := 0; i < 1e5; i++ {
				p1 := p.Clone()
				p1.Mutate(rs, len(goal.Calls), ct, nil)
				data1 := p1.Serialize()
				if bytes.Equal(want, data1) {
					t.Logf("success on iter %v", i)
					return
				}
			}
			t.Fatalf("failed to achieve goal, original:%s\ngoal:%s", test[0], test[1])
		})
	}
}

func BenchmarkMutate(b *testing.B) {
	olddebug := debug
	debug = false
	defer func() { debug = olddebug }()
	target, err := GetTarget("linux", "amd64")
	if err != nil {
		b.Fatal(err)
	}
	ct := linuxAmd64ChoiceTable(target)
	const progLen = 30
	p := target.Generate(rand.NewSource(0), progLen, nil)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		rs := rand.NewSource(0)
		for pb.Next() {
			p.Clone().Mutate(rs, progLen, ct, nil)
		}
	})
}

func BenchmarkGenerate(b *testing.B) {
	olddebug := debug
	debug = false
	defer func() { debug = olddebug }()
	target, err := GetTarget("linux", "amd64")
	if err != nil {
		b.Fatal(err)
	}
	ct := linuxAmd64ChoiceTable(target)
	const progLen = 30
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		rs := rand.NewSource(0)
		for pb.Next() {
			target.Generate(rs, progLen, ct)
		}
	})
}

var (
	linuxCTOnce sync.Once
	linuxCT     *ChoiceTable
)

func linuxAmd64ChoiceTable(target *Target) *ChoiceTable {
	linuxCTOnce.Do(func() {
		linuxCT = target.BuildChoiceTable(target.CalculatePriorities(nil), nil)
	})
	return linuxCT
}
