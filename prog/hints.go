// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// A hint is basically a tuple consisting of a pointer to an argument
// in one of the syscalls of a program and a value, which should be
// assigned to that argument.

// A simplified version of hints workflow looks like this:
//		1. Fuzzer launches a program (we call it a hint seed) and collects all
// the comparisons' data for every syscall in the program.
//		2. Next it tries to match the obtained comparison operands' values
// vs. the input arguments' values.
//		3. For every such match the fuzzer mutates the program by
// replacing the pointed argument with the saved value.
//		4. If a valid program is obtained, then fuzzer launches it and
// checks if new coverage is obtained.

package prog

import (
	"encoding/binary"
)

type uint64Set map[uint64]bool

// Example: for comparisons {(op1, op2), (op1, op3), (op1, op4), (op2, op1)}
// this map will store the following:
// m = {
//		op1: {map[op2]: true, map[op3]: true, map[op4]: true},
//		op2: {map[op1]: true}
// }.
type CompMap map[uint64]uint64Set

var (
	SpecialIntsSet uint64Set

	// A set of calls for which hints should not be generated.
	hintNamesBlackList = map[string]bool{
		"mmap":  true,
		"open":  true,
		"close": true,
	}

	// These maps are used for mutations of ConstArg values.
	leftHalves = map[int]uint64{
		2: 0xff00,
		4: 0xffff0000,
		8: 0xffffffff00000000,
	}
	rightHalves = map[int]uint64{
		2: 0xff,
		4: 0xffff,
		8: 0xffffffff,
	}
)

func (m CompMap) AddComp(arg1, arg2 uint64) {
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
	candidate := func(arg, newArg Arg) {
		newP, argMap := p.cloneImpl(true)
		oldArg := argMap[arg]
		newP.replaceArg(c, oldArg, newArg, nil)
		if newP.validate() == nil {
			exec(newP)
		}
	}
	switch a := arg.(type) {
	case *ConstArg:
		checkConstArg(a, compMap, candidate)
		// case *DataArg:
		// 	checkDataArg(a, compMap, candidate)
	}
}

func checkConstArg(arg *ConstArg, compMap CompMap, cb func(arg, newArg Arg)) {
	replacersSet := make(uint64Set)

	f := func(transform func(uint64) uint64) {
		value := transform(arg.Val)
		originalsSet := make(uint64Set)
		// Get all different mutations of value.
		vals := getMutationsForConstVal(value)
		diff := addArrayToSet(originalsSet, vals)
		// Search for each unseen mutation.
		for _, v := range diff {
			compSet, ok := compMap[v]
			if !ok {
				continue
			}
			for newV, _ := range compSet {
				// Transform the second operand the same way as the first one.
				newV = transform(newV)
				replacersSet[newV] = true
			}
		}
	}

	transforms := []func(uint64) uint64{
		func(v uint64) uint64 { return v },
		func(v uint64) uint64 { return reverse(v, false) },
		func(v uint64) uint64 { return reverse(v, true) },
	}
	for _, t := range transforms {
		f(t)
	}

	for newV, _ := range replacersSet {
		newArg := constArg(arg.typ, newV)
		cb(arg, newArg)
	}
}

// Returns an array of different mutations of an ConstArg value. Each of these
// mutations should be matched against comparison operands.
func getMutationsForConstVal(v uint64) []uint64 {
	values := []uint64{v}
	mutations := []func(uint64) []uint64{
		shrinkMutation,
		expandMutation,
	}
	for _, m := range mutations {
		values = append(values, m(v)...)
	}
	return values
}

// Mutation 1: shrink values. Useful in cases like:
//	void f(int64 v64) {
//		v32 = (int32) v32;
//		if (v32 == -1) {...};
//	}
// If v64 < 0 and v64's value fits into 32 bits (e.g. v64 = -2), then:
// uint64(v64) = 0xfffffffffffffffe and uint64(v32) = 0xfffffffe.
// Thus, the comparison will be (0xfffffffe vs 0xffffffff), and we'll be
// unable to find the operand in the input stream.
// This is why we need to check for the 0xff... prefix.
// If v64 >= 0, we want to match comparisons of type int8(v64) == 0x42,
// thus we need to drop 7 bytes of v64 (they might be filled with random trash).
// A solution for both cases is to just drop the higher bytes.
func shrinkMutation(v uint64) (values []uint64) {
	for _, half := range rightHalves {
		values = append(values, v&half)
	}
	return
}

// Mutation 2: expand values. Useful in cases like:
//	void f(int32 v32) {
//		v64 = (int64) v32;
//		if (v32 == -1) {...};
//	}
// Same logic as for mutation 1 applies.
func expandMutation(v uint64) (values []uint64) {
	if v == 0 {
		return
	}
	// Find the most significant byte and its index, to check if the value < 0.
	msByteValue, msByteIndex, _ := getMostSignificantByte(v)
	if !valueIsNegative(msByteValue, msByteIndex) {
		return
	}
	sizes := []int{2, 4, 8}
	for _, size := range sizes {
		if size > msByteIndex+1 {
			v = v | leftHalves[size]
			values = append(values, v)
		}
	}
	return
}

func checkDataArg(arg *DataArg, compMap CompMap, cb func(arg, newArg Arg)) {
	cb(arg, arg)
}

// Reverses the byte order of v.
// If cutBytes == true, then cuts the trailing bytes, e.g.:
// reverse(0xefbeadde, true) = 0xdeadbeef
// reverse(0xefbeadde, false) = 0xdeadbeef00000000
func reverse(v uint64, cutBytes bool) uint64 {
	_, msByteIndex, bytes := getMostSignificantByte(v)
	r := binary.BigEndian.Uint64(bytes)
	if cutBytes {
		shiftCount := uint(0)
		if msByteIndex == 0 {
			shiftCount = 56 // it's a byte value
		} else if msByteIndex == 1 {
			shiftCount = 48 // it's a 2-byte value
		} else if msByteIndex <= 3 {
			shiftCount = 32 // it's a 4-byte value
		} // else is'a 8-byte value, shiftCount stays 0
		r = r >> shiftCount
	}
	return r

}

func getMostSignificantByte(v uint64) (value byte, index int, bytes []byte) {
	bytes = make([]byte, 8)
	// We will anyways try both Little Endian and Big Endian in checkConstArg,
	// so it doesn't matter here. We use LE for convenience.
	binary.LittleEndian.PutUint64(bytes, v)
	for i, b := range bytes {
		if b != 0 {
			value = b
			index = i
		}
	}
	return
}

func valueIsNegative(msByteValue byte, msByteIndex int) bool {
	return !(msByteIndex != 0 &&
		msByteIndex != 1 &&
		msByteIndex != 3 &&
		msByteIndex != 7 &&
		msByteValue <= 0x7f)
}

// Adds all of the elements of an array to the set.
// Returns an array of elements, which weren't in the set.
func addArrayToSet(set uint64Set, arr []uint64) (diff []uint64) {
	for _, x := range arr {
		if _, ok := set[x]; !ok {
			set[x] = true
			diff = append(diff, x)
		}
	}
	return
}

func init() {
	SpecialIntsSet = make(uint64Set)
	for _, x := range specialInts {
		SpecialIntsSet[x] = true
	}
}
