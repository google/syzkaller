// Copyright 2017 syzkaller project authors. All rights reserved.
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

var (
	SpecialIntsSet uintptrSet

	// A set of calls for which hints should not be generated.
	hintNamesBlackList = map[string]bool{
		"mmap":  true,
		"open":  true,
		"close": true,
	}
)

func (m ComparisonMapOfSets) AddComp(arg1, arg2 uintptr) {
	if _, ok := m[arg1]; !ok {
		m[arg1] = make(uintptrSet)
	}
	m[arg1][arg2] = true
}

// Mutates the program using the comparison operands stored in compMaps.
// For each of the mutants executes the exec callback.
func (p *Prog) MutateWithHints(compMaps []ComparisonMapOfSets, exec func(newP *Prog)) {
	for i, c := range p.Calls {
		if _, ok := hintNamesBlackList[c.Meta.CallName]; ok {
			continue
		}
		foreachArg(c, func(arg, _ Arg, _ *[]Arg) {
			generateHints(p, compMaps[i], c, arg, exec)
		})
	}
}

func generateHints(p *Prog, compMap ComparisonMapOfSets, c *Call, arg Arg, exec func(newP *Prog)) {
	candidate := func(arg, newArg Arg) {
		newP, argMap := p.cloneImpl(true)
		oldArg := argMap[arg]
		newP.replaceArg(c, oldArg, newArg, nil)
		exec(newP)
	}
	switch a := arg.(type) {
	case *ConstArg:
		checkConstArg(a, compMap, candidate)
	case *DataArg:
		checkDataArg(a, compMap, candidate)
	}
}

func checkConstArg(arg *ConstArg, compMap ComparisonMapOfSets, cb func(arg, newArg Arg)) {
	v := arg.Val
	compSet, ok := compMap[v]
	if !ok {
		return
	}
	for newV, _ := range compSet {
		newArg := constArg(arg.typ, newV)
		cb(arg, newArg)
	}
}

func checkDataArg(arg *DataArg, compMap ComparisonMapOfSets, cb func(arg, newArg Arg)) {
	cb(arg, arg)
}

func init() {
	SpecialIntsSet = make(uintptrSet)
	for _, v := range specialInts {
		SpecialIntsSet[v] = true
	}
}
