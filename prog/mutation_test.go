// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"bytes"
	"fmt"
	"math/rand"
	"testing"
)

func TestMutationFlags(t *testing.T) {
	tests := [][2]string{
		// Mutate flags (bitmask = true).
		{
			`r0 = mutate_flags(&(0x7f0000000000)="2e2f66696c653000", 0x0, 0x1, 0x1)`,
			`r0 = mutate_flags(&(0x7f0000000000)="2e2f66696c653000", 0x20, 0x1, 0x9)`,
		},
		{
			`r0 = mutate_flags2(&(0x7f0000000000)="2e2f66696c653000", 0x0)`,
			`r0 = mutate_flags2(&(0x7f0000000000)="2e2f66696c653000", 0xd9)`,
		},
		// Mutate flags (bitmask = false).
		{
			`r0 = mutate_flags3(&(0x7f0000000000)="2e2f66696c653000", 0x0)`,
			`r0 = mutate_flags3(&(0x7f0000000000)="2e2f66696c653000", 0xddddeeee)`,
		},
		{
			`r0 = mutate_flags3(&(0x7f0000000000)="2e2f66696c653000", 0xddddeeee)`,
			`r0 = mutate_flags3(&(0x7f0000000000)="2e2f66696c653000", 0xaaaaaaaa)`,
		},
	}
	runMutationTests(t, tests, true)
}

func TestChooseCall(t *testing.T) {
	tests := [][2]string{
		// The call with many arguments has a higher mutation probability.
		{
			`mutate0()
mutate_integer(0x0, 0x1, 0x1, 0x1, 0x0, 0x1, 0x0, 0x0, 0x1)
mutate_integer2(0x00, 0x00, 0x20, 0x00, 0x01)`,
			`mutate0()
mutate_integer(0x0, 0x1, 0x1, 0x1, 0x0, 0x1, 0x0, 0x0, 0xffffffff)
mutate_integer2(0x00, 0x00, 0x20, 0x00, 0x01)`,
		},
		// Calls with the same probability.
		{
			`mutate_integer(0x0, 0x1, 0x1, 0x1, 0x0, 0x1, 0x0, 0x0, 0x1)
mutate_integer(0x0, 0x1, 0x1, 0x1, 0x0, 0x1, 0x0, 0x0, 0x1)
mutate_integer(0x0, 0x1, 0x1, 0x1, 0x0, 0x1, 0x0, 0x0, 0x1)
mutate_integer(0x0, 0x1, 0x1, 0x1, 0x0, 0x1, 0x0, 0x0, 0x1)
mutate_integer(0x0, 0x1, 0x1, 0x1, 0x0, 0x1, 0x0, 0x0, 0x1)`,
			`mutate_integer(0x0, 0x1, 0x1, 0x1, 0x0, 0x1, 0x0, 0x0, 0x1)
mutate_integer(0x0, 0x1, 0x1, 0x1, 0x0, 0x1, 0x0, 0x0, 0x1)
mutate_integer(0x0, 0x1, 0x1, 0x1, 0x0, 0x1, 0x0, 0x0, 0xff)
mutate_integer(0x0, 0x1, 0x1, 0x1, 0x0, 0x1, 0x0, 0x0, 0x1)
mutate_integer(0x0, 0x1, 0x1, 0x1, 0x0, 0x1, 0x0, 0x0, 0x1)`,
		},
		// The call with a lower probability can be mutated.
		{
			`mutate7(&(0x7f0000000000)='123', 0x3)
mutate_integer(0x0, 0x1, 0x1, 0x1, 0x0, 0x1, 0x0, 0x0, 0x1)
r0 = mutate_flags(&(0x7f0000000000)="2e2f66696c653000", 0x0, 0x1, 0x1)`,
			`mutate7(&(0x7f0000000000)='123', 0x2)
mutate_integer(0x0, 0x1, 0x1, 0x1, 0x0, 0x1, 0x0, 0x0, 0x1)
r0 = mutate_flags(&(0x7f0000000000)="2e2f66696c653000", 0x0, 0x1, 0x1)`,
		},
		// Complex arguments.
		{
			`test$struct(&(0x7f0000000000)={0x0, {0x0}})
test$array0(&(0x7f0000001000)={0x1, [@f0=0x2, @f1=0x3], 0x4})
mutate_integer(0x0, 0x1, 0x1, 0x1, 0x0, 0x1, 0x0, 0x0, 0x1)`,
			`test$struct(&(0x7f0000000000)={0xff, {0x0}})
test$array0(&(0x7f0000001000)={0x1, [@f0=0x2, @f1=0x3], 0x4})
mutate_integer(0x0, 0x1, 0x1, 0x1, 0x0, 0x1, 0x0, 0x0, 0x1)`,
		},
	}
	runMutationTests(t, tests, true)
}

func TestMutateArgument(t *testing.T) {
	tests := [][2]string{
		// Mutate an integer with a higher priority than the boolean arguments.
		{
			`mutate_integer(0x0, 0x1, 0x1, 0x1, 0x0, 0x1, 0x0, 0x0, 0x1)`,
			`mutate_integer(0x0, 0x1, 0x1, 0x1, 0x0, 0x1, 0x0, 0x0, 0xffffffff)`,
		},
		// Mutate a boolean.
		{
			`mutate_integer(0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0)`,
			`mutate_integer(0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0)`,
		},
		// Mutate flags (bitmask = true).
		{
			`r0 = mutate_flags(&(0x7f0000000000)="2e2f66696c653000", 0x0, 0x1, 0x1)`,
			`r0 = mutate_flags(&(0x7f0000000000)="2e2f66696c653000", 0x20, 0x1, 0x9)`,
		},
		// Mutate an int8 from a set of other arguments with higher priority.
		{
			`mutate_integer2(0x00, 0x00, 0x20, 0x00, 0x01)`,
			`mutate_integer2(0x00, 0x00, 0x20, 0x00, 0x07)`,
		},
		// Mutate an array of structs.
		{
			`mutate_array2(&(0x7f0000000000)=[{0x0}, {0x0}, {0x0}, {0x0}, {0x0}])`,
			`mutate_array2(&(0x7f0000000000)=[{0x0}, {0x0}, {0x3}, {0x0}, {0x0}])`,
		},
		// Mutate a non-special union that have more than 1 option.
		{
			`mutate_union(&(0x7f0000000000)=@f1=[0x0, 0x1, 0x2, 0x3, 0x0, 0x1, 0x2, 0x3, 0x0, 0x0])`,
			`mutate_union(&(0x7f0000000000)=@f0=0x2)`,
		},
		// Mutate the value of the current option in union.
		{
			`mutate_union(&(0x7f0000000000)=@f1=[0x0, 0x1, 0x2, 0x3, 0x0, 0x1, 0x2, 0x3, 0x0, 0x0])`,
			`mutate_union(&(0x7f0000000000)=@f1=[0x0, 0x1, 0xff, 0x3, 0x0, 0x1, 0x2, 0x3, 0x0, 0x0])`,
		},
	}

	target := initTargetTest(t, "test", "64")
	for ti, test := range tests {
		test := test
		t.Run(fmt.Sprint(ti), func(t *testing.T) {
			t.Parallel()
			rs, ct, p, goal, err := buildTestContext(test, target)
			if err != nil {
				t.Fatalf("failed to deserialize the program: %v", err)
			}
			want := goal.Serialize()
			for i := 0; i < 1e5; i++ {
				p1 := p.Clone()
				ctx := &mutator{
					p:      p1,
					r:      newRand(p1.Target, rs),
					ncalls: 2 * len(p.Calls),
					ct:     ct,
					corpus: nil,
				}
				ctx.mutateArg()
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

func TestSizeMutateArg(t *testing.T) {
	target, rs, iters := initRandomTargetTest(t, "test", "64")
	r := newRand(target, rs)
	ct := target.DefaultChoiceTable()
	for i := 0; i < iters; i++ {
		p := target.Generate(rs, 10, ct)
		for it := 0; it < 10; it++ {
			p1 := p.Clone()
			ctx := &mutator{
				p:      p1,
				r:      r,
				ncalls: 2 * len(p.Calls),
				ct:     ct,
				corpus: nil,
			}
			ctx.mutateArg()
			ForeachArg(p.Calls[0], func(arg Arg, ctx *ArgCtx) {
				if _, ok := arg.Type().(*IntType); !ok {
					return
				}
				bits := arg.Type().TypeBitSize()
				limit := uint64(1<<bits - 1)
				val := arg.(*ConstArg).Val
				if val > limit {
					t.Fatalf("Invalid argument value: %d. (arg size: %d; max value: %d)", val, arg.Size(), limit)
				}
			})
		}
	}
}

func TestClone(t *testing.T) {
	target, rs, iters := initTest(t)
	ct := target.DefaultChoiceTable()
	for i := 0; i < iters; i++ {
		p := target.Generate(rs, 10, ct)
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
		ct := target.DefaultChoiceTable()
	next:
		for i := 0; i < iters; i++ {
			p := target.Generate(rs, 10, ct)
			data0 := p.Serialize()
			p1 := p.Clone()
			// There is a chance that mutation will produce the same program.
			// So we check that at least 1 out of 20 mutations actually change the program.
			for try := 0; try < 20; try++ {
				p1.Mutate(rs, 10, ct, nil)
				data := p.Serialize()
				if !bytes.Equal(data0, data) {
					t.Fatalf("program changed after mutate\noriginal:\n%s\n\nnew:\n%s\n",
						data0, data)
				}
				data1 := p1.Serialize()
				if bytes.Equal(data, data1) {
					continue
				}
				if _, err := target.Deserialize(data1, NonStrict); err != nil {
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
	ct := target.DefaultChoiceTable()
	var corpus []*Prog
	for i := 0; i < 100; i++ {
		p := target.Generate(rs, 10, ct)
		corpus = append(corpus, p)
	}
	for i := 0; i < iters; i++ {
		p1 := target.Generate(rs, 10, ct)
		p1.Mutate(rs, 10, ct, corpus)
	}
}

func TestMutateTable(t *testing.T) {
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
r0 = mutate5(&(0x7f0000000000)="2e2f66696c653000", 0xcdcdcdcd)
mutate0()
mutate6(r0, &(0x7f0000000000)="00", 0x1)
mutate1()
`},
		// Mutate data (delete byte and update size).
		{`
mutate4(&(0x7f0000000000)="11223344", 0x4)
`, `
mutate4(&(0x7f0000000000)="113344", 0x3)
`},
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
		// Mutate the array.
		{`
mutate_array(0x1, 0x30, &(0x7f0000000000)=[0x1, 0x1, 0x1, 0x1, 0x1])
`, `
mutate_array(0x1, 0x30, &(0x7f0000000000)=[0x1, 0x1, 0x1, 0x1])
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
		// Increase buffer length.
		{`
mutate_buffer(&(0x7f0000000000)=""/100)
`, `
mutate_buffer(&(0x7f0000000000)=""/200)
`},
		// Decrease buffer length.
		{`
mutate_buffer(&(0x7f0000000000)=""/800)
`, `
mutate_buffer(&(0x7f0000000000)=""/4)
`},
		// Mutate a ranged buffer.
		{`
mutate_rangedbuffer(&(0x7f00000000c0)=""/10)
`, `
mutate_rangedbuffer(&(0x7f00000000c0)=""/7)
`},
	}

	runMutationTests(t, tests, true)
}

func TestNegativeMutations(t *testing.T) {
	tests := [][2]string{
		// Mutate buffer size outside the range limits.
		{`
mutate_rangedbuffer(&(0x7f00000000c0)=""/7)
`, `
mutate_rangedbuffer(&(0x7f00000000c0)=""/4)
`},
		{`
mutate_rangedbuffer(&(0x7f00000000c0)=""/7)
`, `
mutate_rangedbuffer(&(0x7f00000000c0)=""/11)
`},
	}
	runMutationTests(t, tests, false)
}

func BenchmarkMutate(b *testing.B) {
	target, cleanup := initBench(b)
	defer cleanup()
	ct := target.DefaultChoiceTable()
	const progLen = 30
	p := target.Generate(rand.NewSource(0), progLen, ct)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		rs := rand.NewSource(0)
		for pb.Next() {
			p.Clone().Mutate(rs, progLen, ct, nil)
		}
	})
}

func BenchmarkGenerate(b *testing.B) {
	target, cleanup := initBench(b)
	defer cleanup()
	ct := target.DefaultChoiceTable()
	const progLen = 30
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		rs := rand.NewSource(0)
		for pb.Next() {
			target.Generate(rs, progLen, ct)
		}
	})
}

func runMutationTests(t *testing.T, tests [][2]string, valid bool) {
	target := initTargetTest(t, "test", "64")
	for ti, test := range tests {
		test := test
		t.Run(fmt.Sprint(ti), func(t *testing.T) {
			t.Parallel()
			rs, ct, p, goal, err := buildTestContext(test, target)
			if err != nil {
				t.Fatalf("failed to deserialize the program: %v", err)
			}
			want := goal.Serialize()
			iters := iterCount()
			if valid {
				iters = 1e6 // it will stop after reaching the goal
			}
			for i := 0; i < iters; i++ {
				p1 := p.Clone()
				p1.Mutate(rs, len(goal.Calls), ct, nil)
				data1 := p1.Serialize()
				if bytes.Equal(want, data1) {
					if !valid {
						t.Fatalf("failed on iter %v", i)
					}
					t.Logf("success on iter %v", i)
					return
				}
			}
			if valid {
				t.Fatalf("failed to achieve goal, original:%s\ngoal:%s", test[0], test[1])
			}
		})
	}
}

func buildTestContext(test [2]string, target *Target) (rs rand.Source, ct *ChoiceTable, p, goal *Prog, err error) {
	p, err = target.Deserialize([]byte(test[0]), Strict)
	if err != nil {
		return
	}
	goal, err = target.Deserialize([]byte(test[1]), Strict)
	if err != nil {
		return
	}
	enabled := make(map[*Syscall]bool)
	for _, c := range p.Calls {
		enabled[c.Meta] = true
	}
	for _, c := range goal.Calls {
		enabled[c.Meta] = true
	}
	ct = target.BuildChoiceTable(nil, enabled)
	rs = rand.NewSource(0)
	return
}

func BenchmarkStoreLoadInt(b *testing.B) {
	// To get unaligned data on heap (compiler manages to align it on stack).
	data := make([]byte, 9)
	sink = data
	data = sink.([]byte)[1:]
	for i := 0; i < b.N; i++ {
		for size := 1; size <= 8; size *= 2 {
			storeInt(data, uint64(i), size)
			v := loadInt(data, size)
			if uint8(v) != uint8(i) {
				panic("bad")
			}
		}
	}
}

var sink interface{}
