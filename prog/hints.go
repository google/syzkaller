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
	"sort"

	"github.com/google/syzkaller/pkg/image"
)

// Example: for comparisons {(op1, op2), (op1, op3), (op1, op4), (op2, op1)}
// this map will store the following:
//
//	m = {
//			op1: {map[op2]: true, map[op3]: true, map[op4]: true},
//			op2: {map[op1]: true}
//	}.
type CompMap map[uint64]map[uint64]bool

const (
	maxDataLength = 100
)

var specialIntsSet map[uint64]bool

func (m CompMap) AddComp(arg1, arg2 uint64) {
	if _, ok := m[arg1]; !ok {
		m[arg1] = make(map[uint64]bool)
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

// InplaceIntersect() only leaves the value pairs that are also present in other.
func (m CompMap) InplaceIntersect(other CompMap) {
	for val1, nested := range m {
		for val2 := range nested {
			if !other[val1][val2] {
				delete(nested, val2)
			}
		}
		if len(nested) == 0 {
			delete(m, val1)
		}
	}
}

// Mutates the program using the comparison operands stored in compMaps.
// For each of the mutants executes the exec callback.
// The callback must return whether we should continue substitution (true)
// or abort the process (false).
func (p *Prog) MutateWithHints(callIndex int, comps CompMap, exec func(p *Prog) bool) {
	p = p.Clone()
	c := p.Calls[callIndex]
	doMore := true
	execValidate := func() bool {
		// Don't try to fix the candidate program.
		// Assuming the original call was sanitized, we've got a bad call
		// as the result of hint substitution, so just throw it away.
		if p.Target.sanitize(c, false) != nil {
			return true
		}
		if p.checkConditions() != nil {
			// Patching unions that no longer satisfy conditions would
			// require much deeped changes to prog arguments than
			// generateHints() expects.
			// Let's just ignore such mutations.
			return true
		}
		p.debugValidate()
		doMore = exec(p)
		return doMore
	}
	ForeachArg(c, func(arg Arg, ctx *ArgCtx) {
		if !doMore {
			ctx.Stop = true
			return
		}
		generateHints(comps, arg, ctx.Field, execValidate)
	})
}

func generateHints(compMap CompMap, arg Arg, field *Field, exec func() bool) {
	typ := arg.Type()
	if typ == nil || arg.Dir() == DirOut {
		return
	}
	switch t := typ.(type) {
	case *ProcType:
		// Random proc will not pass validation.
		// We can mutate it, but only if the resulting value is within the legal range.
		return
	case *ConstType:
		if IsPad(typ) {
			return
		}
	case *CsumType:
		// Csum will not pass validation and is always computed.
		return
	case *BufferType:
		switch t.Kind {
		case BufferFilename:
			// This can generate escaping paths and is probably not too useful anyway.
			return
		case BufferString, BufferGlob:
			if len(t.Values) != 0 {
				// These are frequently file names or complete enumerations.
				// Mutating these may be useful iff we intercept strcmp
				// (and filter out file names).
				return
			}
		}
	}

	switch a := arg.(type) {
	case *ConstArg:
		if arg.Type().TypeBitSize() <= 8 {
			// Very small arg, hopefully we can guess it w/o hints help.
			return
		}
		checkConstArg(a, field, compMap, exec)
	case *DataArg:
		if arg.Size() <= 3 {
			// Let's assume it either does not contain anything interesting,
			// or we can guess everything eventually by brute force.
			return
		}
		if typ.(*BufferType).Kind == BufferCompressed {
			checkCompressedArg(a, compMap, exec)
		} else {
			checkDataArg(a, compMap, exec)
		}
	}
}

func checkConstArg(arg *ConstArg, field *Field, compMap CompMap, exec func() bool) {
	original := arg.Val
	// Note: because shrinkExpand returns a map, order of programs is non-deterministic.
	// This can affect test coverage reports.
replacerLoop:
	for _, replacer := range shrinkExpand(original, compMap, arg.Type().TypeBitSize(), false) {
		if field != nil && len(field.relatedFields) != 0 {
			for related := range field.relatedFields {
				if related.(uselessHinter).uselessHint(replacer) {
					continue replacerLoop
				}
			}
		} else if arg.Type().(uselessHinter).uselessHint(replacer) {
			continue
		}
		arg.Val = replacer
		if !exec() {
			break
		}
	}
	arg.Val = original
}

func checkDataArg(arg *DataArg, compMap CompMap, exec func() bool) {
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
		for _, replacer := range shrinkExpand(val, compMap, 64, false) {
			binary.LittleEndian.PutUint64(bytes, replacer)
			copy(data[i:], bytes)
			if !exec() {
				break
			}
		}
		copy(data[i:], original)
	}
}

func checkCompressedArg(arg *DataArg, compMap CompMap, exec func() bool) {
	data0 := arg.Data()
	data, dtor := image.MustDecompress(data0)
	defer dtor()
	// Images are very large so the generic algorithm for data arguments
	// can produce too many mutants. For images we consider only
	// 4/8-byte aligned ints. This is enough to handle all magic
	// numbers and checksums. We also ignore 0 and ^uint64(0) source bytes,
	// because there are too many of these in lots of images.
	bytes := make([]byte, 8)
	for i := 0; i < len(data); i += 4 {
		original := make([]byte, 8)
		copy(original, data[i:])
		val := binary.LittleEndian.Uint64(original)
		for _, replacer := range shrinkExpand(val, compMap, 64, true) {
			binary.LittleEndian.PutUint64(bytes, replacer)
			copy(data[i:], bytes)
			arg.SetData(image.Compress(data))
			if !exec() {
				break
			}
		}
		copy(data[i:], original)
	}
	arg.SetData(data0)
}

// Shrink and expand mutations model the cases when the syscall arguments
// are casted to narrower (and wider) integer types.
//
// Motivation for shrink:
//
//	void f(u16 x) {
//			u8 y = (u8)x;
//			if (y == 0xab) {...}
//	}
//
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
//
// Motivation for expand:
//
//	void f(i8 x) {
//			i16 y = (i16)x;
//			if (y == -2) {...}
//	}
//
// Suppose we call f(-1), then we'll see a comparison 0xffff vs 0xfffe and be
// unable to match input vs any operands. Thus we sign extend the input and
// check the extension.
// As with shrink we ignore cases when the other operand is wider.
// Note that executor sign extends all the comparison operands to int64.
func shrinkExpand(v uint64, compMap CompMap, bitsize uint64, image bool) []uint64 {
	v = truncateToBitSize(v, bitsize)
	limit := uint64(1<<bitsize - 1)
	var replacers map[uint64]bool
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
			if size > bitsize {
				size = bitsize
			}
			if v&(1<<(size-1)) == 0 {
				continue
			}
			mutant = v | ^((1 << size) - 1)
		}
		if image {
			// For images we can produce too many mutants for small integers.
			if width < 4 {
				continue
			}
			if mutant == 0 || (mutant|^((1<<size)-1)) == ^uint64(0) {
				continue
			}
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
				// Check the limit for negative numbers.
				if newV > limit && ((^(limit >> 1) & newV) != ^(limit >> 1)) {
					continue
				}
				mask := uint64(1<<size - 1)
				newHi := newV & ^mask
				newV = newV & mask
				if newHi != 0 && newHi^^mask != 0 {
					continue
				}
				if bigendian {
					newV = swapInt(newV, width)
				}
				// We insert special ints (like 0) with high probability,
				// so we don't try to replace to special ints them here.
				// Images are large so it's hard to guess even special
				// ints with random mutations.
				if !image && specialIntsSet[newV] {
					continue
				}
				// Replace size least significant bits of v with
				// corresponding bits of newV. Leave the rest of v as it was.
				replacer := (v &^ mask) | newV
				if replacer == v {
					continue
				}
				replacer = truncateToBitSize(replacer, bitsize)
				// TODO(dvyukov): should we try replacing with arg+/-1?
				// This could trigger some off-by-ones.
				if replacers == nil {
					replacers = make(map[uint64]bool)
				}
				replacers[replacer] = true
			}
		}
	}
	if replacers == nil {
		return nil
	}
	res := make([]uint64, 0, len(replacers))
	for v := range replacers {
		res = append(res, v)
	}
	sort.Slice(res, func(i, j int) bool {
		return res[i] < res[j]
	})
	return res
}

func init() {
	specialIntsSet = make(map[uint64]bool)
	for _, v := range specialInts {
		specialIntsSet[v] = true
	}
}
