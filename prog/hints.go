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

const (
	maxDataLength = 100
)

var specialIntsSet uint64Set

func (m CompMap) AddComp(arg1, arg2 uint64) {
	if _, ok := m[arg1]; !ok {
		m[arg1] = make(uint64Set)
	}
	m[arg1][arg2] = true
}

// Mutates the program using the comparison operands stored in compMaps.
// For each of the mutants executes the exec callback.
func (p *Prog) MutateWithHints(callIndex int, comps CompMap, exec func(newP *Prog)) {
	c := p.Calls[callIndex]
	if c.Meta == p.Target.MmapSyscall {
		return
	}
	foreachArg(c, func(arg, _ Arg, _ *[]Arg) {
		generateHints(p, comps, c, arg, exec)
	})
}

func generateHints(p *Prog, compMap CompMap, c *Call, arg Arg, exec func(p *Prog)) {
	if arg.Type().Dir() == DirOut {
		return
	}
	switch arg.Type().(type) {
	case *ProcType:
		// Random proc will not pass validation.
		// We can mutate it, but only if the resulting value is within the legal range.
		return
	case *CsumType:
		// Csum will not pass validation and is always computed.
		return
	case *LenType:
		// Mutating len type causes panics during mmap/mremap analysis:
		// panic: address is out of bounds: page=7 len=34359738367 bound=4096
		// We can mutate len theoretically, but we need to be careful.
		return
	}

	newP, argMap := p.cloneImpl(true)
	var originalArg Arg
	validateExec := func() {
		if err := newP.validate(); err != nil {
			panic("a program generated with hints did not pass validation: " +
				err.Error())
		}
		exec(newP)
	}
	constArgCandidate := func(newArg Arg) {
		oldArg := argMap[arg]
		newP.replaceArg(c, oldArg, newArg, nil)
		validateExec()
		newP.replaceArg(c, oldArg, originalArg, nil)
	}

	dataArgCandidate := func(newArg Arg) {
		// Data arg mutations are done in-place. No need to restore the original
		// value - it gets restored in checkDataArg().
		// dataArgCandidate is only needed for unit tests.
		validateExec()
	}

	switch a := arg.(type) {
	case *ConstArg:
		originalArg = MakeConstArg(a.Type(), a.Val)
		checkConstArg(a, compMap, constArgCandidate)
	case *DataArg:
		originalArg = dataArg(a.Type(), a.Data)
		checkDataArg(a, compMap, dataArgCandidate)
	}
}

func checkConstArg(arg *ConstArg, compMap CompMap, cb func(newArg Arg)) {
	for replacer := range shrinkExpand(arg.Val, compMap) {
		cb(MakeConstArg(arg.typ, replacer))
	}
}

func checkDataArg(arg *DataArg, compMap CompMap, cb func(newArg Arg)) {
	bytes := make([]byte, 8)
	original := make([]byte, 8)
	for i := 0; i < min(len(arg.Data), maxDataLength); i++ {
		copy(original, arg.Data[i:])
		val := sliceToUint64(arg.Data[i:])
		for replacer := range shrinkExpand(val, compMap) {
			binary.LittleEndian.PutUint64(bytes, replacer)
			copy(arg.Data[i:], bytes)
			cb(arg)
			copy(arg.Data[i:], original)
		}
	}
}

// Shrink and expand mutations model the cases when the syscall arguments
// are casted to narrower (and wider) integer types.
// ======================================================================
// Motivation for shrink:
// void f(u16 x) {
//		u8 y = (u8)x;
//		if (y == 0xab) {...}
// }
// If we call f(0x1234), then we'll see a comparison 0x34 vs 0xab and we'll
// be unable to match the argument 0x1234 with any of the comparison operands.
// Thus we shrink 0x1234 to 0x34 and try to match 0x34.
// If there's a match for the shrank value, then we replace the corresponding
// bytes of the input (in the given example we'll get 0x12ab).
// Sometimes the other comparison operand will be wider than the shrank value
// (in the example above consider comparison if (y == 0xdeadbeef) {...}).
// In this case we ignore such comparison because we couldn't come up with
// any valid code example that does similar things. To avoid such comparisons
// we check the sizes with leastSize().
// ======================================================================
// Motivation for expand:
// void f(i8 x) {
//		i16 y = (i16)x;
//		if (y == -2) {...}
// }
// Suppose we call f(-1), then we'll see a comparison 0xffff vs 0xfffe and be
// unable to match input vs any operands. Thus we sign extend the input and
// check the extension.
// As with shrink we ignore cases when the other operand is wider.
// Note that executor sign extends all the comparison operands to int64.
// ======================================================================
func shrinkExpand(v uint64, compMap CompMap) uint64Set {
	replacers := make(uint64Set)
	// Map: key is shrank/extended value, value is the maximal number of bits
	// that can be replaced.
	res := make(map[uint64]uint)
	for _, size := range []uint{8, 16, 32} {
		res[v&((1<<size)-1)] = size
		if v&(1<<(size-1)) != 0 {
			res[v|^((1<<size)-1)] = size
		}
	}
	res[v] = 64

	for mutant, size := range res {
		for newV := range compMap[mutant] {
			mask := uint64(1<<size - 1)
			if newHi := newV & ^mask; newHi == 0 || newHi^^mask == 0 {
				if !specialIntsSet[newV&mask] {
					// Replace size least significant bits of v with
					// corresponding bits of newV. Leave the rest of v as it was.
					replacer := (v &^ mask) | (newV & mask)
					// TODO(dvyukov): should we try replacing with arg+/-1?
					// This could trigger some off-by-ones.
					replacers[replacer] = true
				}
			}
		}
	}
	return replacers
}

func init() {
	specialIntsSet = make(uint64Set)
	for _, v := range specialInts {
		specialIntsSet[v] = true
	}
}

// Transforms a slice of bytes into uint64 using Little Endian.
// Works fine if len(s) != 8.
func sliceToUint64(s []byte) uint64 {
	padded := pad(s, 0x0, 8)
	return binary.LittleEndian.Uint64(padded)
}

// If len(arr) >= size returns a subslice of arr.
// Else creates a copy of arr padded with value to size.
func pad(arr []byte, value byte, size int) []byte {
	if len(arr) >= size {
		return arr[0:size]
	}
	block := make([]byte, size)
	copy(block, arr)
	for j := len(arr); j < size; j++ {
		block[j] = value
	}
	return block
}

func min(a, b int) int {
	if a <= b {
		return a
	}
	return b
}
