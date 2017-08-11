package prog

import (
	"encoding/binary"
	"fmt"

	"github.com/google/syzkaller/sys"
)

// A set of calls for which hints will not be generated
var hintNamesBlackList = map[string]bool{
	"mmap":  true,
	"open":  true,
	"close": true,
}

// Size in bytes for each type of comparison exported from KCOV
var sizeMap = map[KcovComparisonType]uint{
	KCOV_TYPE_CMP1:       1,
	KCOV_TYPE_CMP2:       2,
	KCOV_TYPE_CMP4:       4,
	KCOV_TYPE_CMP8:       8,
	KCOV_TYPE_SWITCH1:    1,
	KCOV_TYPE_SWITCH2:    2,
	KCOV_TYPE_SWITCH4:    4,
	KCOV_TYPE_SWITCH8:    8,
	KCOV_TYPE_CONST_CMP1: 1,
	KCOV_TYPE_CONST_CMP2: 2,
	KCOV_TYPE_CONST_CMP4: 4,
	KCOV_TYPE_CONST_CMP8: 8,
}

// A set of special values for which the hints should not be created
// Taken from prog/rand.go specialInts array
// Created as a global constant map for performance reasons
var specialIntsMap = map[uintptr]bool{
	0:             true,
	1:             true,
	31:            true,
	32:            true,
	63:            true,
	64:            true,
	127:           true,
	128:           true,
	129:           true,
	255:           true,
	256:           true,
	257:           true,
	511:           true,
	512:           true,
	1023:          true,
	1024:          true,
	1025:          true,
	2047:          true,
	2048:          true,
	4095:          true,
	4096:          true,
	(1 << 15) - 1: true,
	(1 << 15):     true,
	(1 << 15) + 1: true,
	(1 << 16) - 1: true,
	(1 << 16):     true,
	(1 << 16) + 1: true,
	(1 << 31) - 1: true,
	(1 << 31):     true,
	(1 << 31) + 1: true,
	(1 << 32) - 1: true,
	(1 << 32):     true,
	(1 << 32) + 1: true,
}

type ArgKey struct {
	value uintptr // all the values are promoted to uintptr
	size  uint
}
type ArgVal struct {
	// array of indices to locate the value (array needed to handle nested data)
	// e.g. if the value is stored in:
	// the third field of a struct, which is
	// the fifth element of an array, which is
	// the second argument of a syscall
	// then the array will look like: {1, 5, 2}
	indices []uint
}

// Maps of this type are used to store the arguments' values for each
// executed syscall
type ArgMap map[ArgKey][]*ArgVal

// Casts an uintptr value to an integer of given size
// size is given in bytes
func castToSize(val uintptr, size uint) uintptr {
	castVal := val & ((1 << (size * 8)) - 1)
	return castVal
}

// If the mutation is valid - returns the mutated program
// otherwise returns nil
func (p *Prog) MutateWithHint(hint *Hint) *Prog {
	newP := p.Clone()
	if len(hint.Indices) == 0 {
		return nil
	}
	if len(newP.Calls) <= int(hint.CallIndex) {
		return nil
	}
	if len(newP.Calls[hint.CallIndex].Args) <= int(hint.Indices[0]) {
		return nil
	}
	arg := newP.Calls[hint.CallIndex].Args[hint.Indices[0]]
	// iterate to find actual inner argument
	indices := hint.Indices[1:]
	var dataIndex uint
	for i, index := range indices {
		if ptrArg, ok := arg.(*PointerArg); ok {
			// dereference here without moving further in the indices array
			arg = ptrArg.Res
			if arg == nil {
				return nil
			}
		}
		if groupArg, ok := arg.(*GroupArg); ok {
			if int(index) >= len(groupArg.Inner) {
				return nil
			}
			arg = groupArg.Inner[index]
		} else if _, ok := arg.(*DataArg); ok && i == (len(indices)-2) {
			dataIndex = indices[i+1]
			break
		} else if _, ok = arg.(*ConstArg); ok && i == (len(indices)-1) {
			break
		} else {
			// something bad happened
			return nil
		}
	}

	if constArg, ok := arg.(*ConstArg); ok {
		constArg.Val = hint.Value
	} else if dataArg, ok := arg.(*DataArg); ok {
		switch hint.Size {
		case 1:
			dataArg.Data[dataIndex] = byte(hint.Value)
		// here we always write in little endian, because both of the values
		// (LE and BE) are previously added to the hints array
		case 2:
			binary.LittleEndian.PutUint16(dataArg.Data[dataIndex:],
				uint16(hint.Value))
		case 4:
			binary.LittleEndian.PutUint32(dataArg.Data[dataIndex:],
				uint32(hint.Value))
		case 8:
			binary.LittleEndian.PutUint64(dataArg.Data[dataIndex:],
				uint64(hint.Value))
		default:
			return nil
		}
	} else {
		return nil
	}
	if newP.validate() == nil {
		return newP
	}
	return nil
}

// Helper functions for GenerateHints function:

// Searches for all arguments in argMap with value == oldVal and returns
// an array of hints with argVal replaced with newVal
func createHintsForOneKey(callIndex uint, argMap ArgMap, oldVal, newVal uintptr,
	size uint) (hints []*Hint) {
	argVals, ok := argMap[ArgKey{oldVal, size}]
	if !ok {
		return
	}
	// we don't want the "special" values in the hints list
	// fuzzer will anyways try them sometimes
	if ok, _ := specialIntsMap[newVal]; ok {
		return
	}
	hints = make([]*Hint, len(argVals))
	for i, argVal := range argVals {
		hints[i] = &Hint{
			CallIndex: callIndex,
			Indices:   argVal.indices,
			Value:     newVal,
			OldValue:  oldVal,
			Size:      size,
		}
	}
	return
}

// Parses a composite argument of DataArg type (a blob of data)
// and adds all of the values encountered into argMap.
// Searches for values of all sizes (1/2/4/8 bytes) both little and big endian.
func addSubArgsForBlob(argMap ArgMap, arg *DataArg, prevIndices []uint) {
	addValueOfSize := func(curIndex int, argSize uint) {
		if curIndex+int(argSize) > len(arg.Data) {
			return
		}
		var big, little uintptr
		switch argSize {
		case 1:
			big = uintptr(arg.Data[curIndex])
			little = big
		case 2:
			big = uintptr(binary.BigEndian.Uint16(arg.Data[curIndex:]))
			little = uintptr(binary.LittleEndian.Uint16(arg.Data[curIndex:]))
		case 4:
			big = uintptr(binary.BigEndian.Uint32(arg.Data[curIndex:]))
			little = uintptr(binary.LittleEndian.Uint32(arg.Data[curIndex:]))
		case 8:
			big = uintptr(binary.BigEndian.Uint64(arg.Data[curIndex:]))
			little = uintptr(binary.LittleEndian.Uint64(arg.Data[curIndex:]))
		default:
			return
		}

		big = castToSize(big, argSize)
		little = castToSize(little, argSize)
		newIndices := append(prevIndices, uint(curIndex))

		key := ArgKey{little, argSize}
		argMap[key] = append(argMap[key], &ArgVal{newIndices})

		if big != little {
			key := ArgKey{big, argSize}
			argMap[key] = append(argMap[key], &ArgVal{newIndices})
		}

	}
	for k := 0; k < len(arg.Data); k++ {
		addValueOfSize(k, 1)
		addValueOfSize(k, 2)
		addValueOfSize(k, 4)
		addValueOfSize(k, 8)
	}
}

// A recursive function that adds all of the argument's subfields to argMap
func addArgRecursive(argMap ArgMap, root Arg, prevIndices []uint) {
	if ptrArg, ok := root.(*PointerArg); ok {
		// if root is a pointer, then dereference it, without changing
		// the indices array
		root = ptrArg.Res
		if root == nil {
			return
		}
		if root.Type().Dir() != sys.DirIn &&
			root.Type().Dir() != sys.DirInOut {
			// we want only userspace->kernel data
			return
		}
	}
	// fmt.Printf("PROG: add an arg of type: %v\n", root.Type.Name())
	if constArg, ok := root.(*ConstArg); ok {
		// if root is a const, then just add it to argMap
		size := uint(constArg.Type().Size())
		val := castToSize(constArg.Val, size)
		key := ArgKey{val, size}
		argMap[key] = append(argMap[key], &ArgVal{prevIndices})
	} else if dataArg, ok := root.(*DataArg); ok {
		// if root is a blob of data, then scan it to find values
		addSubArgsForBlob(argMap, dataArg, prevIndices)
	} else if groupArg, ok := root.(*GroupArg); ok {
		// if root is a group (array/struct), then call the function
		// recursively for all the sub arguments
		for i, subArg := range groupArg.Inner {
			if subArg.Type().Name() == "pad" {
				continue
			}
			newIndices := make([]uint, len(prevIndices)+1)
			copy(newIndices, prevIndices)
			newIndices[len(prevIndices)] = uint(i)
			addArgRecursive(argMap, subArg, newIndices)
		}
	}
}

// Adds an argument to the argMap
func addArg(argMap ArgMap, arg Arg, argIndex uint) {
	indices := []uint{argIndex}
	addArgRecursive(argMap, arg, indices)
}

func dumpArgMap(argMap ArgMap) {
	for k, values := range argMap {
		for _, v := range values {
			fmt.Printf("PROG: argMap[(0x%x, %v)] = [", k.value, k.size)
			for _, x := range v.indices {
				fmt.Printf("%v, ", x)
			}
			fmt.Printf("]\n")
		}
	}
}

// Parses the comparisons data extracted from KCOV to identify
// matches between comparison operands and syscalls' arguments.
// For each such match creates a hint with the syscall's argument
// replaced with the other comparison operand.
// Returns an array of created hints.
func (p *Prog) GenerateHints(info []CallInfo) (hints []*Hint) {
	for i, inf := range info {
		if _, ok := hintNamesBlackList[p.Calls[i].Meta.CallName]; ok {
			continue
		}
		// generate a map with all values of syscall's arguments
		argMap := make(ArgMap)
		for j, arg := range p.Calls[i].Args {
			addArg(argMap, arg, uint(j))
		}
		// if there's no interesting values return
		if len(argMap) == 0 {
			continue
		}
		// dumpArgMap(argMap)
		// match comparison operands vs syscall arguments
		// and generate the corresponding hints
		for _, comp := range inf.Comps {
			size, _ := sizeMap[comp.CompType]
			arg1 := castToSize(uintptr(comp.Arg1), size)
			arg2 := castToSize(uintptr(comp.Arg2), size)
			if arg1 == arg2 {
				continue
			}
			// fmt.Printf("PROG: got a cmp: 0x%x 0x%x\n", arg1, arg2)
			// check if either of the comparison's operands
			// was used as a syscall argument
			if !IsKcovSwitch(comp.CompType) && !IsKcovConstCmp(comp.CompType) {
				// if one of the operands is a constant, then we don't want
				// to waste time on searching it
				hints = append(hints,
					createHintsForOneKey(uint(i), argMap, arg1, arg2, size)...)
			}
			hints = append(hints,
				createHintsForOneKey(uint(i), argMap, arg2, arg1, size)...)
		}
	}
	return
}
