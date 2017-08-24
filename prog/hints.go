// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

// A hint is basically a tuple consisting of a pointer to an argument
// in one of the syscalls of a program and a value, which should be
// assigned to that argument (we call it a replacer).

// A simplified version of hints workflow looks like this:
//		1. Fuzzer launches a program (we call it a hint seed) and collects all
// the comparisons' data for every syscall in the program.
//		2. Next it tries to match the obtained comparison operands' values
// vs. the input arguments' values.
//		3. For every such match the fuzzer mutates the program by
// replacing the pointed argument with the saved value.
//		4. If a valid program is obtained, then fuzzer launches it and
// checks if new coverage is obtained.
// For more insights on particular mutations please see prog/hints_test.go.

type uint64Set map[uint64]bool

// Example: for comparisons {(op1, op2), (op1, op3), (op1, op4), (op2, op1)}
// this map will store the following:
// m = {
//		op1: {map[op2]: true, map[op3]: true, map[op4]: true},
//		op2: {map[op1]: true}
// }.
type CompMap map[uint64]uint64Set

var (
	specialIntsSet uint64Set

	// A set of calls for which hints should not be generated.
	hintNamesBlackList = map[string]bool{
		"mmap":  true,
		"open":  true,
		"close": true,
	}
)

func (m CompMap) AddComp(arg1, arg2 uint64) {
	if _, ok := specialIntsSet[arg2]; ok {
		// We don't want to add arg2 because it's in the set of
		// "special" values, which the fuzzer will try anyways.
		return
	}
	if _, ok := m[arg1]; !ok {
		m[arg1] = make(uint64Set)
	}
	m[arg1][arg2] = true
}

// Mutates the program using the comparison operands stored in compMaps.
// For each of the mutants executes the exec callback.
func (p *Prog) MutateWithHints(compMaps []CompMap, exec func(newP *Prog)) {
	for i, c := range p.Calls {
		if _, ok := hintNamesBlackList[c.Meta.CallName]; ok {
			continue
		}
		foreachArg(c, func(arg, _ Arg, _ *[]Arg) {
			generateHints(p, compMaps[i], c, arg, exec)
		})
	}
}

func generateHints(p *Prog, compMap CompMap, c *Call, arg Arg, exec func(newP *Prog)) {
	candidate := func(newArg Arg) {
		newP, argMap := p.cloneImpl(true)
		oldArg := argMap[arg]
		newP.replaceArg(c, oldArg, newArg, nil)
		if err := newP.validate(); err != nil {
			panic("a program generated with hints did not pass validation: " +
				err.Error())
		}
		exec(newP)
	}
	switch a := arg.(type) {
	case *ConstArg:
		checkConstArg(a, compMap, candidate)
		// case *DataArg:
		// 	checkDataArg(a, compMap, candidate)
	}
}

func checkConstArg(arg *ConstArg, compMap CompMap, cb func(newArg Arg)) {
	for v, _ := range compMap[arg.Val] {
		cb(constArg(arg.typ, v))
	}
}

func init() {
	specialIntsSet = make(uint64Set)
	for _, v := range specialInts {
		specialIntsSet[v] = true
	}
}
