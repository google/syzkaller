// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

type uintptrSet map[uintptr]bool

// Example: for comparisons {(op1, op2), (op1, op3), (op1, op4), (op2, op1)}
// this map will store the following:
// m = {
//		op1: {map[op2]: true, map[op3]: true, map[op4]: true},
//		op2: {map[op1]: true}
// }.
type ComparisonMapOfSets map[uintptr]uintptrSet

var SpecialIntsSet uintptrSet

func (m ComparisonMapOfSets) AddComp(arg1, arg2 uintptr) {
	if _, ok := m[arg1]; !ok {
		m[arg1] = make(uintptrSet)
	}
	m[arg1][arg2] = true
}

func init() {
	SpecialIntsSet = make(uintptrSet)
	for _, v := range specialInts {
		SpecialIntsSet[v] = true
	}
}
