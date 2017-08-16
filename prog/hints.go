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

var specialIntsSet uint64Set

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

func init() {
	specialIntsSet = make(uint64Set)
	for _, v := range specialInts {
		specialIntsSet[v] = true
	}
}
