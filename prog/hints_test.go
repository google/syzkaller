package prog

import (
	"encoding/binary"
	"fmt"
	"testing"
)

var (
	progText = "syz_test$hint_test_call(&(0x7f0000000000)=" + fmt.Sprintf(
		"{0x%x, 0x%x, 0x%x, 0x%x, {[0x%x, 0x%x, 0x%x], {0x%x}}})",
		0xab,       // s.b int8
		0xcafe,     // s.w int16
		0x11111111, // s.d int32
		0xdeadbeef, // s.q int64
		0x11111111, // s.arr[0] int32
		0x22222222, // s.arr[1] int32
		0x33333333, // s.arr[2] int32
		0x11111111, // s.s.x int32
	)
	expectedHints = []*Hint{
		// Hint{CallIndex, Indices, Value, OldValue, Size}
		&Hint{0, []uint{0, 0}, 0xba, 0xab, 1},
		// because there's a pad field with index 1 in the struct
		// all the subsequent indices are incremented
		&Hint{0, []uint{0, 2}, 0xfeca, 0xcafe, 2},
		&Hint{0, []uint{0, 3}, 0x99999999, 0x11111111, 4},
		&Hint{0, []uint{0, 4}, 0xbeefdead, 0xdeadbeef, 8},
		&Hint{0, []uint{0, 5, 0, 0}, 0x99999999, 0x11111111, 4},
		&Hint{0, []uint{0, 5, 1, 0}, 0x99999999, 0x11111111, 4},
	}
)

func count(slice []uintptr, value uintptr) uint {
	var c uint = 0
	for _, v := range slice {
		if v == value {
			c++
		}
	}
	return c
}

func TestHintsCastToSize(t *testing.T) {
	runs := []struct {
		got      uintptr
		expected uintptr
	}{
		{castToSize(0xdeadbeef, 1), 0xef},
		{castToSize(0xdeadbeef, 2), 0xbeef},
		{castToSize(0xdeadbeef, 4), 0xdeadbeef},
		{castToSize(0xdeadbeef, 8), 0xdeadbeef},
	}
	for _, run := range runs {
		if run.got != run.expected {
			t.Error("Expected", run.expected, "Got", run.got)
		}
	}
}

// Parses the byte array and checks the following things:
// 1. All the values of size 1,2,4,8 bytes were added
//		in both little and big endian
// 2. If there's multiple occurrences of a value, then all of them are added
// 3. The indices for all values are correct
func TestHintsAddSubArgForBlob(t *testing.T) {
	// setup:
	argMap := make(ArgMap)
	indices := []uint{}
	data := []byte{0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x1, 0x2, 0x3, 0x4}
	type S struct {
		index uint
		value uintptr
	}
	var (
		byteValues  []S
		wordValues  []S
		dwordValues []S
		qwordValues []S
	)
	for i := range data {
		newSlice := data[i:]
		index := uint(i)
		byteValues = append(byteValues, S{index, uintptr(newSlice[0])})
		if i <= len(data)-2 {
			wordValues = append(wordValues,
				S{index, uintptr(binary.LittleEndian.Uint16(newSlice))},
				S{index, uintptr(binary.BigEndian.Uint16(newSlice))},
			)
		}
		if i <= len(data)-4 {
			dwordValues = append(dwordValues,
				S{index, uintptr(binary.LittleEndian.Uint32(newSlice))},
				S{index, uintptr(binary.BigEndian.Uint32(newSlice))},
			)
		}
		if i <= len(data)-8 {
			qwordValues = append(qwordValues,
				S{index, uintptr(binary.LittleEndian.Uint64(newSlice))},
				S{index, uintptr(binary.BigEndian.Uint64(newSlice))},
			)
		}
	}
	arg := DataArg{Data: data}
	// fill the argMap
	addSubArgsForBlob(argMap, &arg, indices)

	check := func(values []S, size uint) {
		for _, s := range values {
			value := s.value
			index := s.index
			key := ArgKey{value, size}
			argVals, ok := argMap[key]

			// 1. Check that all values are added in both BE and LE
			if !ok {
				t.Error("Value", value, "of size", size, "not found in argMap")
			}

			// 2. Check multiple occurences
			count := int(0)
			for _, v := range values {
				if v.value == value {
					count++
				}
			}
			if count != len(argVals) {
				t.Error("Value", value, "of size", size,
					"has wrong nr. of occurrences",
					"expected", count, "got", len(argVals))
			}

			// 3. Check indices
			argValFound := false
			foundIndices := make([]uint, len(argVals))
			for i, argVal := range argVals {
				if len(argVal.indices) != 1 {
					t.Error("Value", value, "of size", size,
						"has wrong size of indices array:", len(argVal.indices))
					break
				}
				if argVal.indices[0] == index {
					argValFound = true
					break
				}
				foundIndices[i] = argVal.indices[0]
			}
			if argValFound == false {
				t.Error("Value", value, "of size", size,
					"has wrong index",
					"expected", index, "got", foundIndices)
			}
		}
	}
	check(byteValues, 1)
	check(wordValues, 2)
	check(dwordValues, 4)
	check(qwordValues, 8)
}

// Tests addArg() and addArgRecursive() implementations for complicated
// nested structures. Checks:
// 1. That all the leaf values (values of primitive types) are added to argMap.
// 2. That all the indices arrays for leaf values are created properly.
// 3. That the pad fields are not included into argMap.
// 4. That if there's multiple occurrences of a value, then all the occurrences
//		are added.
func TestHintsAddArg(t *testing.T) {
	// setup
	p, err := Deserialize([]byte(progText))
	if err != nil {
		t.Error("Got an error in Deserialize:", err)
	}
	got := make(ArgMap)
	expected := ArgMap{
		ArgKey{0xab, 1}: []*ArgVal{&ArgVal{[]uint{0, 0}}},
		// because there's a pad field with index 1 in the struct
		// all the subsequent indices are incremented
		ArgKey{0xcafe, 2}: []*ArgVal{&ArgVal{[]uint{0, 2}}},
		ArgKey{0x11111111, 4}: []*ArgVal{
			&ArgVal{[]uint{0, 3}},
			&ArgVal{[]uint{0, 5, 0, 0}},
			&ArgVal{[]uint{0, 5, 1, 0}},
		},
		ArgKey{0xdeadbeef, 8}: []*ArgVal{&ArgVal{[]uint{0, 4}}},
		ArgKey{0x22222222, 4}: []*ArgVal{&ArgVal{[]uint{0, 5, 0, 1}}},
		ArgKey{0x33333333, 4}: []*ArgVal{&ArgVal{[]uint{0, 5, 0, 2}}},
	}
	addArg(got, p.Calls[0].Args[0], 0)
	if len(got) != len(expected) {
		t.Error("Got and expected are of diffent sizes!")
	}
	for k, argValsE := range expected {
		argValsG, ok := got[k]
		if !ok {
			t.Error("Key", k, "is present in expected, but not in got")
		}
		if len(argValsG) != len(argValsE) {
			t.Error("Expected and got argVals have different lengths",
				"got", got, "expected", expected)
		}
		for i := range argValsG {
			argValG := argValsG[i]
			argValE := argValsE[i]
			if len(argValG.indices) != len(argValE.indices) {
				t.Error(
					"Expected and got argVal have different indices lengths",
					"got", got, "expected", expected,
				)
			}
			for j := range argValG.indices {
				if argValG.indices[j] != argValE.indices[j] {
					t.Error("Different index at position", j,
						"got", argValG.indices, "expected", argValE.indices)
				}
			}
		}
	}
}

// Tests the hints creation in GenerateHints() and createHintForOneKey().
// Checks:
// 1. That all the comparison operands were matched and replaced correctly.
// 2. That for switch statements the switch cases are not searched.
// 3. That the constant comparisons operands are not searched.
// 4. That no values are replaced with constants from specialIntsMap.
func TestHintsGenerateHints(t *testing.T) {
	// setup
	comps := []KcovComparison{
		KcovComparison{KCOV_TYPE_CMP1, 0xab, 0xba},
		KcovComparison{KCOV_TYPE_CMP2, 0xcafe, 0xfeca},
		KcovComparison{KCOV_TYPE_CMP4, 0x11111111, 0x99999999},
		KcovComparison{KCOV_TYPE_CMP8, 0xdeadbeef, 0xbeefdead},
		// following comps' operands should not appear in resulting hints
		KcovComparison{KCOV_TYPE_CONST_CMP4, 0x11111111, 0xaaaaaaaa},
		KcovComparison{KCOV_TYPE_SWITCH1, 0xab, 0x99},
		KcovComparison{KCOV_TYPE_CMP4, 0x11111111, 1}, // special int
	}
	callInfo := []CallInfo{CallInfo{Comps: comps}}
	p, err := Deserialize([]byte(progText))
	if err != nil {
		t.Error("Got an error in Deserialize:", err)
	}
	expected := expectedHints
	got := p.GenerateHints(callInfo)
	// check results
	if len(got) != len(expected) {
		t.Error("Got and expected have different lenghts", "got", got,
			"expected", expected)
	}
	for _, hintGot := range got {
		found := false
		for _, hintExpected := range expected {
			if hintGot.equals(hintExpected) {
				found = true
				break
			}
		}
		if !found {
			t.Error("Hint", hintGot, "was not found in the expected array",
				"expected", expected, "got", got)
		}
	}
}

// Test that program mutations based on hints are done correctly
// For each hint checks:
// 1. That the proper argument was replaced with proper value.
// 2. That for correct hints a non-nil result is returned.
// 3. That for incorrect hints a nil result is returned.
func TestHintsMutateWithHint(t *testing.T) {
	// TODO(tchibo): add tests for data arguments
	p, err := Deserialize([]byte(progText))
	if err != nil {
		t.Error("Got an error in Deserialize:", err)
	}

	// first check a correct hint
	hint := &Hint{0, []uint{0, 5, 1, 0}, 0x99999999, 0x11111111, 4}
	newP := p.MutateWithHint(hint)
	// check the result manually to avoid bugs in tests
	if newP == nil {
		t.Error("The mutated program is nil")
	}
	arg := newP.Calls[0].Args[0]
	// if any of the following conversions fail, then the test will fail
	// so no need to check their correctness
	ptrArg := arg.(*PointerArg)
	groupArg := ptrArg.Res.(*GroupArg)
	arg = groupArg.Inner[5]
	groupArg = arg.(*GroupArg)
	arg = groupArg.Inner[1]
	groupArg = arg.(*GroupArg)
	arg = groupArg.Inner[0]
	constArg := arg.(*ConstArg)
	if constArg.Val != hint.Value {
		t.Error("The hint and the arg values differ",
			"hint value:", hint.Value, "arg value:", constArg.Val)
	}

	// Check incorrect hints.
	// Each of them should result in a nil program returned.
	incorrectHints := []*Hint{
		// incorrect syscall index
		&Hint{42, []uint{}, 0, 0, 0},
		// incorrect argument index
		&Hint{0, []uint{42}, 0, 0, 0},
		// index chain ends with a non-const, non-data argument
		&Hint{0, []uint{0, 5}, 0, 0, 0},
		// incorrect field index inside a structure
		&Hint{0, []uint{0, 5, 42}, 0, 0, 0},
	}
	for _, hint := range incorrectHints {
		newP = p.MutateWithHint(hint)
		if newP != nil {
			t.Error("The mutated program is not nil", hint)
		}
	}
}
