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
	"bytes"
	"encoding/binary"
	"fmt"
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

func (m CompMap) String() string {
	buf := new(bytes.Buffer)
	for v, comps := range m {
		if len(buf.Bytes()) != 0 {
			fmt.Fprintf(buf, ", ")
		}
		fmt.Fprintf(buf, "0x%x:", v)
		for c := range comps {
			fmt.Fprintf(buf, " 0x%x", c)
		}
	}
	return buf.String()
}

// Mutates the program using the comparison operands stored in compMaps.
// For each of the mutants executes the exec callback.
func (p *Prog) MutateWithHints(callIndex int, comps CompMap, exec func(p *Prog)) {
	p = p.Clone()
	c := p.Calls[callIndex]
	execValidate := func() {
		if debug {
			if err := p.validate(); err != nil {
				panic(fmt.Sprintf("invalid hints candidate: %v", err))
			}
		}
		exec(p)
	}
	ForeachArg(c, func(arg Arg, _ *ArgCtx) {
		generateHints(comps, arg, execValidate)
	})
}

func generateHints(compMap CompMap, arg Arg, exec func()) {
	typ := arg.Type()
	if typ == nil || typ.Dir() == DirOut {
		return
	}
	switch typ.(type) {
	case *ProcType:
		// Random proc will not pass validation.
		// We can mutate it, but only if the resulting value is within the legal range.
		return
	case *CsumType:
		// Csum will not pass validation and is always computed.
		return
	}

	switch a := arg.(type) {
	case *ConstArg:
		checkConstArg(a, compMap, exec)
	case *DataArg:
		checkDataArg(a, compMap, exec)
	}
}

func checkConstArg(arg *ConstArg, compMap CompMap, exec func()) {
	original := arg.Val
	for replacer := range shrinkExpand(original, compMap) {
		arg.Val = replacer
		exec()
	}
	arg.Val = original
}

func checkDataArg(arg *DataArg, compMap CompMap, exec func()) {
	bytes := make([]byte, 8)
	data := arg.Data()
	size := len(data)
	if size > maxDataLength {
		size = maxDataLength
	}
	for i := 0; i < size; i++ {
		original := make([]byte, 8)
		copy(original, data[i:])
		val := binary.LittleEndian.Uint64(original)
		for replacer := range shrinkExpand(val, compMap) {
			binary.LittleEndian.PutUint64(bytes, replacer)
			copy(data[i:], bytes)
			exec()
		}
		copy(data[i:], original)
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
func shrinkExpand(v uint64, compMap CompMap) (replacers uint64Set) {
	for _, iwidth := range []int{8, 4, 2, 1, -4, -2, -1} {
		var width int
		var size, mutant uint64
		if iwidth > 0 {
			width = iwidth
			size = uint64(width) * 8
			mutant = v & ((1 << size) - 1)
		} else {
			width = -iwidth
			size = uint64(width) * 8
			mutant = v | ^((1 << size) - 1)
		}
		// Use big-endian match/replace for both blobs and ints.
		// Sometimes we have unmarked blobs (no little/big-endian info);
		// for ANYBLOBs we intentionally lose all marking;
		// but even for marked ints we may need this too.
		// Consider that kernel code does not convert the data
		// (i.e. not ntohs(pkt->proto) == ETH_P_BATMAN),
		// but instead converts the constant (i.e. pkt->proto == htons(ETH_P_BATMAN)).
		// In such case we will see dynamic operand that does not match what we have in the program.
		for _, bigendian := range []bool{false, true} {
			if bigendian {
				if width == 1 {
					continue
				}
				mutant = swapInt(mutant, width)
			}
			for newV := range compMap[mutant] {
				mask := uint64(1<<size - 1)
				newHi := newV & ^mask
				newV = newV & mask
				if newHi != 0 && newHi^^mask != 0 {
					continue
				}
				if bigendian {
					newV = swapInt(newV, width)
				}
				if specialIntsSet[newV] {
					continue
				}
				// Replace size least significant bits of v with
				// corresponding bits of newV. Leave the rest of v as it was.
				replacer := (v &^ mask) | newV
				// TODO(dvyukov): should we try replacing with arg+/-1?
				// This could trigger some off-by-ones.
				if replacers == nil {
					replacers = make(uint64Set)
				}
				replacers[replacer] = true
			}
		}
	}
	return
}

func init() {
	specialIntsSet = make(uint64Set)
	for _, v := range specialInts {
		specialIntsSet[v] = true
	}
}
