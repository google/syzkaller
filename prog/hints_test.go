package prog

import (
	_ "encoding/binary"
	"fmt"
	"sort"
	"testing"
)

var (
	simpleProgText = "syz_test$simple_test_call(0x%x)\n"
	dataInProgText = "syz_test$data_in_test_call(&(0x7f0000000000)=\"%v\")\n"
)

// Dumb test.
func TestHintsSimple(t *testing.T) {
	m := CompMap{
		0xdeadbeef: uint64Set{0xcafebabe: true},
	}
	expected := []string{
		getSimpleProgText(0xcafebabe),
	}
	runSimpleTest(m, expected, t, 0xdeadbeef)
}

// Test for cases when there's multiple comparisons (op1, op2), (op1, op3), ...
// Checks that for every such operand a program is generated.
func TestHintsMultipleOps(t *testing.T) {
	m := CompMap{
		0xabcd: uint64Set{0x1: true, 0x2: true, 0x3: true},
	}
	expected := []string{
		getSimpleProgText(0x1),
		getSimpleProgText(0x2),
		getSimpleProgText(0x3),
	}
	runSimpleTest(m, expected, t, 0xabcd)
}

// Test for cases, described in shrinkMutation() function.
func TestHintsConstArgShrinkSize(t *testing.T) {
	m := CompMap{
		0xab: uint64Set{0x1: true},
	}
	expected := []string{
		getSimpleProgText(0x1),
	}

	// Code for positive values - drop the trash from highest bytes.
	runSimpleTest(m, expected, t, 0x12ab)
	runSimpleTest(m, expected, t, 0x123456ab)
	runSimpleTest(m, expected, t, 0x1234567890abcdab)

	// Code for negative values - drop the 0xff.. prefix
	runSimpleTest(m, expected, t, 0xffab)
	runSimpleTest(m, expected, t, 0xffffffab)
	runSimpleTest(m, expected, t, 0xffffffffffffffab)
}

// Test for cases, described in expandMutation() function.
func TestHintsConstArgExpandSize(t *testing.T) {
	m := CompMap{
		0xffffffffffffffab: uint64Set{0x1: true},
	}
	expected := []string{
		getSimpleProgText(0x1),
	}
	runSimpleTest(m, expected, t, 0xab)
	runSimpleTest(m, expected, t, 0xffab)
	runSimpleTest(m, expected, t, 0xffffffab)

	m = CompMap{
		0xffffffab: uint64Set{0x1: true},
	}
	expected = []string{
		getSimpleProgText(0x1),
	}
	runSimpleTest(m, expected, t, 0xab)
	runSimpleTest(m, expected, t, 0xffab)

	m = CompMap{
		0xffab: uint64Set{0x1: true},
	}
	expected = []string{
		getSimpleProgText(0x1),
	}
	runSimpleTest(m, expected, t, 0xab)
}

// Test for Little/Big Endian conversions.
func TestHintsConstArgEndianness(t *testing.T) {
	m := CompMap{
		0xbeef:             uint64Set{0x1234: true},
		0xefbe:             uint64Set{0xabcd: true},
		0xefbe000000000000: uint64Set{0xabcd: true},
		0xdeadbeef:         uint64Set{0x1234: true},
		0xefbeadde:         uint64Set{0xabcd: true},
		0xefbeadde00000000: uint64Set{0xabcd: true},
		0x1234567890abcdef: uint64Set{0x1234: true},
		0xefcdab9078563412: uint64Set{0xabcd: true},
	}
	expected := []string{
		getSimpleProgText(0x1234),
		getSimpleProgText(0xcdab),
		getSimpleProgText(0xcdab000000000000),
	}
	runSimpleTest(m, expected, t, 0xbeef)
	runSimpleTest(m, expected, t, 0xdeadbeef)
	runSimpleTest(m, expected, t, 0x1234567890abcdef)

	m = CompMap{
		0xab:               uint64Set{0x1234: true},
		0xab00000000000000: uint64Set{0x1234: true},
	}
	expected = []string{
		getSimpleProgText(0x1234),
		getSimpleProgText(0x3412),
		getSimpleProgText(0x3412000000000000),
	}
	runSimpleTest(m, expected, t, 0xab)
}

// Test for reverse() function.
func TestHintsReverse(t *testing.T) {
	// Cut bytes = true.
	vals := []uint64{0xab, 0xcafe, 0xdeadbeef, 0x1234567890abcdef}
	expected := []uint64{0xab, 0xfeca, 0xefbeadde, 0xefcdab9078563412}
	for i, v := range vals {
		r := reverse(v, true)
		if r != expected[i] {
			t.Errorf("Got 0x%x expected 0x%x", r, expected[i])
		}
	}

	// Cut bytes = false.
	vals = []uint64{0xab, 0xcafe, 0xdeadbeef, 0x1234567890abcdef}
	expected = []uint64{
		0xab00000000000000,
		0xfeca000000000000,
		0xefbeadde00000000,
		0xefcdab9078563412,
	}
	for i, v := range vals {
		r := reverse(v, false)
		if r != expected[i] {
			t.Errorf("Got 0x%x expected 0x%x", r, expected[i])
		}
	}
}

// Test for getMostSignificantByte() function.
func TestHintsMostSignificantByte(t *testing.T) {
	vals := []uint64{0x0, 0x01, 0xa2, 0xa3ab, 0xa4abab, 0xa5ababab,
		0xa6abababab, 0xa7ababababab, 0xa8abababababab, 0xa9ababababababab}
	type R struct {
		value byte
		index int
		bytes []byte
	}
	exp := []R{
		R{0x00, 0, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		R{0x01, 0, []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		R{0xa2, 0, []byte{0xa2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		R{0xa3, 1, []byte{0xab, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		R{0xa4, 2, []byte{0xab, 0xab, 0xa4, 0x00, 0x00, 0x00, 0x00, 0x00}},
		R{0xa5, 3, []byte{0xab, 0xab, 0xab, 0xa5, 0x00, 0x00, 0x00, 0x00}},
		R{0xa6, 4, []byte{0xab, 0xab, 0xab, 0xab, 0xa6, 0x00, 0x00, 0x00}},
		R{0xa7, 5, []byte{0xab, 0xab, 0xab, 0xab, 0xab, 0xa7, 0x00, 0x00}},
		R{0xa8, 6, []byte{0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xa8, 0x00}},
		R{0xa9, 7, []byte{0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xa9}},
	}
	for i, v := range vals {
		value, index, bytes := getMostSignificantByte(v)
		bytesEqual := !byteArraysDifferent(bytes, exp[i].bytes)
		if !bytesEqual || value != exp[i].value || index != exp[i].index {
			t.Error("got", value, index, bytes, "expected", exp[i])
		}
	}
}

// Test for pad() function.
func TestHintsPadding(t *testing.T) {
	type T struct {
		arr   []byte
		value byte
		size  int
	}
	tests := []T{
		T{[]byte{0x01}, 0xff, 8},
		T{[]byte{0x01, 0x02}, 0xff, 8},
		T{[]byte{0x01, 0x02, 0x03}, 0xff, 8},
		T{[]byte{0x01, 0x02, 0x03, 0x04}, 0xff, 8},
		T{[]byte{0x01, 0x02, 0x03, 0x04, 0x05}, 0xff, 8},
		T{[]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}, 0xff, 8},
		T{[]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}, 0xff, 8},
		T{[]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}, 0xff, 8},
	}
	expected := [][]byte{
		[]byte{0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		[]byte{0x01, 0x02, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		[]byte{0x01, 0x02, 0x03, 0xff, 0xff, 0xff, 0xff, 0xff},
		[]byte{0x01, 0x02, 0x03, 0x04, 0xff, 0xff, 0xff, 0xff},
		[]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0xff, 0xff, 0xff},
		[]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0xff, 0xff},
		[]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0xff},
		[]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
	}
	for i, e := range expected {
		g := pad(tests[i].arr, tests[i].value, tests[i].size)
		if byteArraysDifferent(g, e) {
			t.Error("test", tests[i], "got", g, "expected", e)
		}
	}

}

// Tests for checkDataArg() when the DataArg has DirIn direction.
// We test that:
//		1. Each block of size 1,2,4,8 is seen.
//		2. Each first subblock of smaller size of all blocks is seen.
//		3. Each block from points 1,2 is replaced with corresponding values
//	and their subblocks of corresponding size (see comments in hints.go).
//		4. Point 3 is also done for the reversed values.
//		5. There's no duplicate mutants.
// We don't test that:
//		1. The shrink and expand mutations work as expected. This is done in
//  corresponding tests.
// Note that all ints are converted to byte arrays using Little Endian.

// Test for 1 byte data.
func TestHintsDataIn1(t *testing.T) {
	m := CompMap{
		0x1: uint64Set{0xab: true, 0xdeadbeef: true},
	}
	expected := []string{
		// Comp (0x1, 0x2) - replace 0x1 with 0xab.
		getDataInProgText([]byte{0xab}),
		// Comp (0x1, 0xdeadbeef) - replace 0x1 with the first byte (0xef).
		// Then reverse and replace with the last byte (0xde).
		getDataInProgText([]byte{0xde}),
		getDataInProgText([]byte{0xef}),
	}
	runDataInTest(m, expected, t, []byte{0x1})
}

// Test for 2 byte data, 1 byte comp arg.
func TestHintsDataIn2(t *testing.T) {
	m := CompMap{
		0x01: uint64Set{0xab: true, 0xcafe: true},
	}
	expected := []string{
		// Comp (0x01, 0xab): replace the 0th byte.
		getDataInProgText([]byte{0xab, 0x01}),
		// Comp (0x01, 0xab): replace the 1st byte.
		getDataInProgText([]byte{0x01, 0xab}),

		// Comp (0x01, 0xcafe): replace the 0th and 1st byte.
		getDataInProgText([]byte{0xca, 0xfe}),
		// Comp (0x01, 0xcafe): replace the 0th byte with subblock 0xca.
		getDataInProgText([]byte{0xca, 0x01}),
		// Comp (0x01, 0xcafe): replace the 1st byte with subblock 0xca.
		getDataInProgText([]byte{0x01, 0xca}),
		// 0x01 = reverse(0x01) => do the same for reversed values.
		getDataInProgText([]byte{0xfe, 0xca}),
		getDataInProgText([]byte{0xfe, 0x01}),
		getDataInProgText([]byte{0x01, 0xfe}),
	}
	runDataInTest(m, expected, t, []byte{0x01, 0x01})
}

// Test for 2 byte data, 2 byte comp arg.
func TestHintsDataIn3(t *testing.T) {
	m := CompMap{
		// Choose a symmetrical number, so one comparison matches both
		// Little Endian and Big Endian.
		0x0101: uint64Set{0xcafe: true},
	}
	expected := []string{
		// Comp (0x0101, 0xcafe) - replace 0x0101 with 0xcafe and its
		// first subblock: 0xca.
		getDataInProgText([]byte{0xca, 0xfe}),
		getDataInProgText([]byte{0xca, 0x01}),
		// Then reverse and replace with 0xfeca and its first subblock: 0xfe.
		getDataInProgText([]byte{0xfe, 0xca}),
		getDataInProgText([]byte{0xfe, 0x01}),
	}
	runDataInTest(m, expected, t, []byte{0x01, 0x01})
}

// Test for 2 byte data, 2 byte vs 8 byte comp.
func TestHintsDataIn4(t *testing.T) {
	m := CompMap{
		// Choose a symmetrical number, so one comparison matches both
		// Little Endian and Big Endian.
		0x0101: uint64Set{0xdeadbeeffacefeed: true},
	}
	expected := []string{
		// Comp (0x0101, 0xdeadbeeffacefeed) - replace with 0xdead and its
		// first subblock: 0xde.
		getDataInProgText([]byte{0xde, 0xad}),
		getDataInProgText([]byte{0xde, 0x01}),
		// Reverse and do the same.
		getDataInProgText([]byte{0xed, 0xfe}),
		getDataInProgText([]byte{0xed, 0x01}),
	}
	runDataInTest(m, expected, t, []byte{0x01, 0x01})
}

// Test for 4 byte data, 4 byte vs 8 byte comp.
func TestHintsDataIn5(t *testing.T) {
	m := CompMap{
		// Choose a symmetrical number, so one comparison matches both
		// Little Endian and Big Endian.
		0x01010101: uint64Set{0xdeadbeeffacefeed: true},
	}
	expected := []string{
		// Comp (0x01010101, 0xdeadbeeffacefeed) - replace with 0xdeadbeef
		// and its 2 subblocks: 0xde, 0xdead.
		getDataInProgText([]byte{0xde, 0xad, 0xbe, 0xef}),
		getDataInProgText([]byte{0xde, 0xad, 0x01, 0x01}),
		getDataInProgText([]byte{0xde, 0x01, 0x01, 0x01}),
		// Reverse and do the same.
		getDataInProgText([]byte{0xed, 0xfe, 0xce, 0xfa}),
		getDataInProgText([]byte{0xed, 0xfe, 0x01, 0x01}),
		getDataInProgText([]byte{0xed, 0x01, 0x01, 0x01}),
	}
	runDataInTest(m, expected, t, []byte{0x01, 0x01, 0x01, 0x01})
}

// Test for 8 byte data, 2 byte vs 8 byte comp.
func TestHintsDataIn6(t *testing.T) {
	m := CompMap{
		// Choose a symmetrical number, so one comparison matches both
		// Little Endian and Big Endian.
		0x0101: uint64Set{0xdeadbeeffacefeed: true},
	}
	expected := []string{
		// Comp (0x0101, 0xdeadbeeffacefeed) - replace first occurence with
		// 0xdeadbeeffacefeed and its 3 subblocks: 0xde, 0xdead, 0xdeadbeef.
		getDataInProgText(
			[]byte{0xde, 0xad, 0xbe, 0xef, 0xfa, 0xce, 0xfe, 0xed}),
		getDataInProgText(
			[]byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00}),
		getDataInProgText(
			[]byte{0xde, 0xad, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00}),
		getDataInProgText(
			[]byte{0xde, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00}),
		// Comp (0x0101, 0xdeadbeeffacefeed) - replace second occurence with
		// the 3 subblocks: 0xde, 0xdead, 0xdeadbeef.
		getDataInProgText(
			[]byte{0x01, 0x01, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00}),
		getDataInProgText(
			[]byte{0x01, 0x01, 0xde, 0xad, 0x00, 0x00, 0x00, 0x00}),
		getDataInProgText(
			[]byte{0x01, 0x01, 0xde, 0x01, 0x00, 0x00, 0x00, 0x00}),
		// Reverse and do the same.
		// First occurence.
		getDataInProgText(
			[]byte{0xed, 0xfe, 0xce, 0xfa, 0xef, 0xbe, 0xad, 0xde}),
		getDataInProgText(
			[]byte{0xed, 0xfe, 0xce, 0xfa, 0x00, 0x00, 0x00, 0x00}),
		getDataInProgText(
			[]byte{0xed, 0xfe, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00}),
		getDataInProgText(
			[]byte{0xed, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00}),
		// Second occurence.
		getDataInProgText(
			[]byte{0x01, 0x01, 0xed, 0xfe, 0xce, 0xfa, 0x00, 0x00}),
		getDataInProgText(
			[]byte{0x01, 0x01, 0xed, 0xfe, 0x00, 0x00, 0x00, 0x00}),
		getDataInProgText(
			[]byte{0x01, 0x01, 0xed, 0x01, 0x00, 0x00, 0x00, 0x00}),
	}
	// Note that there's two occurences of 0x0101.
	runDataInTest(m, expected, t,
		[]byte{0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00})
}

// Test for 8 byte data, 4 byte vs 8 byte comp.
func TestHintsDataIn7(t *testing.T) {
	m := CompMap{
		// Choose a symmetrical number, so one comparison matches both
		// Little Endian and Big Endian.
		0x01010101: uint64Set{0xdeadbeeffacefeed: true},
	}
	expected := []string{
		// Comp (0x01010101, 0xdeadbeeffacefeed) - replace entire string with
		// 0xdeadbeeffacefeed and its 3 subblocks: 0xde, 0xdead, 0xdeadbeef.
		getDataInProgText(
			[]byte{0xde, 0xad, 0xbe, 0xef, 0xfa, 0xce, 0xfe, 0xed}),
		getDataInProgText(
			[]byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00}),
		getDataInProgText(
			[]byte{0xde, 0xad, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00}),
		getDataInProgText(
			[]byte{0xde, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00}),
		// Reverse and do the same.
		getDataInProgText(
			[]byte{0xed, 0xfe, 0xce, 0xfa, 0xef, 0xbe, 0xad, 0xde}),
		getDataInProgText(
			[]byte{0xed, 0xfe, 0xce, 0xfa, 0x00, 0x00, 0x00, 0x00}),
		getDataInProgText(
			[]byte{0xed, 0xfe, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00}),
		getDataInProgText(
			[]byte{0xed, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00}),
	}
	runDataInTest(m, expected, t,
		[]byte{0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00})
}

// Helper functions.
func byteArraysDifferent(a, b []byte) bool {
	if len(a) != len(b) {
		return true
	}
	for i := range a {
		if a[i] != b[i] {
			return true
		}
	}
	return false
}

func getSimpleProgText(a uint64) string {
	return fmt.Sprintf(simpleProgText, a)
}

func runSimpleTest(m CompMap, expected []string, t *testing.T, a uint64) {
	runTest(m, expected, t, getSimpleProgText(a))
}

func getDataProgText(data []byte, progTemplate string) string {
	s := fmt.Sprintf("%x", data)
	return fmt.Sprintf(progTemplate, s)
}

func getDataInProgText(data []byte) string {
	return getDataProgText(data, dataInProgText)
}

func runDataInTest(m CompMap, expected []string, t *testing.T, d []byte) {
	runTest(m, expected, t, getDataProgText(d, dataInProgText))
}

func runTest(m CompMap, expected []string, t *testing.T, progText string) {
	p, _ := Deserialize([]byte(progText))
	got := make([]string, 0)
	f := func(newP *Prog) {
		got = append(got, string(newP.Serialize()))
	}
	p.MutateWithHints([]CompMap{m}, f)
	sort.Strings(got)
	sort.Strings(expected)
	if len(got) != len(expected) {
		t.Fatal("Lengths of got and expected differ", "got", got,
			"expected", expected)
	}
	failed := false
	for i := range expected {
		if expected[i] != got[i] {
			failed = true
			break
		}
	}
	if failed {
		t.Error("Got", got, "expected", expected)
	}
}
