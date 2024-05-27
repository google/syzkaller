// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateConditionalFields(t *testing.T) {
	// Ensure that we reach different combinations of conditional fields.
	target, rs, _ := initRandomTargetTest(t, "test", "64")
	ct := target.DefaultChoiceTable()
	r := newRand(target, rs)

	combinations := [][]bool{
		{false, false},
		{false, false},
	}
	b2i := func(b bool) int {
		if b {
			return 1
		}
		return 0
	}
	for i := 0; i < 150; i++ {
		p := genConditionalFieldProg(target, ct, r)
		f1, f2 := parseConditionalStructCall(t, p.Calls[len(p.Calls)-1])
		combinations[b2i(f1)][b2i(f2)] = true
	}
	for _, first := range []int{0, 1} {
		for _, second := range []int{0, 1} {
			if !combinations[first][second] {
				t.Fatalf("did not generate a combination f1=%v f2=%v", first, second)
			}
		}
	}
}

func TestConditionalResources(t *testing.T) {
	// Let's stress test the code and rely on various internal checks.
	target, rs, _ := initRandomTargetTest(t, "test", "64")
	ct := target.BuildChoiceTable(nil, map[*Syscall]bool{
		target.SyscallMap["test$create_cond_resource"]: true,
		target.SyscallMap["test$use_cond_resource"]:    true,
	})
	iters := 500
	if testing.Short() {
		iters /= 10
	}
	for i := 0; i < iters; i++ {
		p := target.Generate(rs, 10, ct)
		p.Mutate(rs, 10, ct, nil, nil)
	}
}

func TestMutateConditionalFields(t *testing.T) {
	target, rs, _ := initRandomTargetTest(t, "test", "64")
	ct := target.DefaultChoiceTable()
	r := newRand(target, rs)
	iters := 500
	if testing.Short() {
		iters /= 10
	}
	nonAny := 0
	for i := 0; i < iters; i++ {
		prog := genConditionalFieldProg(target, ct, r)
		for j := 0; j < 5; j++ {
			prog.Mutate(rs, 10, ct, nil, nil)
			hasAny := bytes.Contains(prog.Serialize(), []byte("ANY="))
			if hasAny {
				// No sense to verify these.
				break
			}
			nonAny++
			validateConditionalProg(t, prog)
		}
	}
	assert.Greater(t, nonAny, 10) // Just in case.
}

func TestEvaluateConditionalFields(t *testing.T) {
	target := InitTargetTest(t, "test", "64")
	tests := []struct {
		good []string
		bad  []string
	}{
		{
			good: []string{
				`test$conditional_struct(&AUTO={0x0, @void, @void})`,
				`test$conditional_struct(&AUTO={0x4, @void, @value=0x123})`,
				`test$conditional_struct(&AUTO={0x6, @value={AUTO}, @value=0x123})`,
			},
			bad: []string{
				`test$conditional_struct(&AUTO={0x0, @void, @value=0x123})`,
				`test$conditional_struct(&AUTO={0x0, @value={AUTO}, @value=0x123})`,
			},
		},
		{
			good: []string{
				`test$parent_conditions(&AUTO={0x0, @without_flag1=0x123, {0x0, @void}})`,
				`test$parent_conditions(&AUTO={0x2, @with_flag1=0x123, {0x0, @void}})`,
				`test$parent_conditions(&AUTO={0x4, @without_flag1=0x123, {0x0, @value=0x0}})`,
				`test$parent_conditions(&AUTO={0x6, @with_flag1=0x123, {0x0, @value=0x0}})`,
				// The @without_flag1 option is still possible.
				`test$parent_conditions(&AUTO={0x2, @without_flag1=0x123, {0x0, @void}})`,
			},
			bad: []string{
				`test$parent_conditions(&AUTO={0x0, @with_flag1=0x123, {0x0, @void}})`,
				`test$parent_conditions(&AUTO={0x4, @with_flag1=0x123, {0x0, @void}})`,
				`test$parent_conditions(&AUTO={0x4, @with_flag1=0x123, {0x0, @value=0x0}})`,
			},
		},
	}

	for i, test := range tests {
		t.Run(fmt.Sprintf("%d", i), func(tt *testing.T) {
			for _, good := range test.good {
				_, err := target.Deserialize([]byte(good), Strict)
				assert.NoError(tt, err)
			}
			for _, bad := range test.bad {
				_, err := target.Deserialize([]byte(bad), Strict)
				assert.ErrorIs(tt, err, ErrViolatedConditions,
					"prog: %s", bad)
			}
		})
	}
}

func TestConditionalMinimize(t *testing.T) {
	tests := []struct {
		input  string
		pred   func(*Prog, int) bool
		output string
	}{
		{
			input: `test$conditional_struct(&AUTO={0x6, @value={AUTO}, @value=0x123})`,
			pred: func(p *Prog, _ int) bool {
				return len(p.Calls) == 1 && p.Calls[0].Meta.Name == `test$conditional_struct`
			},
			output: `test$conditional_struct(0x0)`,
		},
		{
			input: `test$conditional_struct(&(0x7f0000000040)={0x6, @value, @value=0x123})`,
			pred: func(p *Prog, _ int) bool {
				return bytes.Contains(p.Serialize(), []byte("0x123"))
			},
			// We don't drop individual bits from integers, so there's no chance
			// to turn 0x6 into 0x4.
			output: `test$conditional_struct(&(0x7f0000000040)={0x6, @value, @value=0x123})`,
		},
		{
			input: `test$conditional_struct_minimize(&(0x7f0000000040)={0x1, @value=0xaa, 0x1, @value=0xbb})`,
			pred: func(p *Prog, _ int) bool {
				return bytes.Contains(p.Serialize(), []byte("0xaa"))
			},
			output: `test$conditional_struct_minimize(&(0x7f0000000040)={0x1, @value=0xaa})`,
		},
		{
			input: `test$conditional_struct_minimize(&(0x7f0000000040)={0x1, @value=0xaa, 0x1, @value=0xbb})`,
			pred: func(p *Prog, _ int) bool {
				return bytes.Contains(p.Serialize(), []byte("0xbb"))
			},
			output: `test$conditional_struct_minimize(&(0x7f0000000040)={0x0, @void, 0x1, @value=0xbb})`,
		},
		{
			input: `test$conditional_struct_minimize(&(0x7f0000000040)={0x1, @value=0xaa, 0x1, @value=0xbb})`,
			pred: func(p *Prog, _ int) bool {
				serialized := p.Serialize()
				return bytes.Contains(serialized, []byte("0xaa")) &&
					bytes.Contains(serialized, []byte("0xbb"))
			},
			output: `test$conditional_struct_minimize(&(0x7f0000000040)={0x1, @value=0xaa, 0x1, @value=0xbb})`,
		},
	}

	for i, test := range tests {
		t.Run(fmt.Sprintf("%d", i), func(tt *testing.T) {
			target, err := GetTarget("test", "64")
			assert.NoError(tt, err)
			p, err := target.Deserialize([]byte(test.input), Strict)
			assert.NoError(tt, err)
			p1, _ := Minimize(p, 0, MinimizeParams{}, test.pred)
			res := p1.Serialize()
			assert.Equal(tt, test.output, strings.TrimSpace(string(res)))
		})
	}
}

func genConditionalFieldProg(target *Target, ct *ChoiceTable, r *randGen) *Prog {
	s := newState(target, ct, nil)
	calls := r.generateParticularCall(s, target.SyscallMap["test$conditional_struct"])
	return &Prog{
		Target: target,
		Calls:  calls,
	}
}

const FLAG1 = 2
const FLAG2 = 4

func validateConditionalProg(t *testing.T, p *Prog) {
	for _, call := range p.Calls {
		if call.Meta.Name == "test$conditional_struct" {
			parseConditionalStructCall(t, call)
		}
	}
}

// Validates a test$conditional_struct call.
func parseConditionalStructCall(t *testing.T, c *Call) (bool, bool) {
	if c.Meta.Name != "test$conditional_struct" {
		t.Fatalf("generated wrong call %v", c.Meta.Name)
	}
	if len(c.Args) != 1 {
		t.Fatalf("generated wrong number of args %v", len(c.Args))
	}
	va, ok := c.Args[0].(*PointerArg)
	if !ok {
		t.Fatalf("expected PointerArg: %v", c.Args[0])
	}
	if va.Res == nil {
		// Cannot validate.
		return false, false
	}
	ga, ok := va.Res.(*GroupArg)
	if !ok {
		t.Fatalf("expected GroupArg: %v", va.Res)
	}
	if len(ga.Inner) != 3 {
		t.Fatalf("wrong number of struct args %v", len(ga.Inner))
	}
	mask := ga.Inner[0].(*ConstArg).Val
	f1 := ga.Inner[1].(*UnionArg).Index == 0
	f2 := ga.Inner[2].(*UnionArg).Index == 0
	assert.Equal(t, mask&FLAG1 != 0, f1, "flag1 must only be set if mask&FLAG1")
	assert.Equal(t, mask&FLAG2 != 0, f2, "flag2 must only be set if mask&FLAG2")
	return f1, f2
}

func TestConditionalUnionFields(t *testing.T) {
	// Ensure that we reach different combinations of conditional fields.
	target, rs, _ := initRandomTargetTest(t, "test", "64")
	ct := target.DefaultChoiceTable()
	r := newRand(target, rs)

	var zeroU1, zeroU2 int
	var nonzeroU2 int
	for i := 0; i < 100; i++ {
		s := newState(target, ct, nil)
		p := &Prog{
			Target: target,
			Calls:  r.generateParticularCall(s, target.SyscallMap["test$conditional_union"]),
		}
		if len(p.Calls) > 1 {
			continue
		}
		text := string(p.SerializeVerbose())
		if strings.Contains(text, "{0x0,") {
			if strings.Contains(text, "@u1") {
				zeroU1++
			} else if strings.Contains(text, "@u2") {
				zeroU2++
			}
		} else {
			assert.NotContains(t, text, "@u1")
			nonzeroU2++
		}
	}
	assert.Greater(t, zeroU1, 0)
	assert.Greater(t, zeroU2, 0)
	assert.Greater(t, nonzeroU2, 0)
}
