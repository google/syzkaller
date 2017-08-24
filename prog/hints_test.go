package prog

import (
	_ "encoding/binary"
	"fmt"
	"sort"
	"testing"
)

var (
	simpleProgText = "syz_test$simple_test_call(0x%x)\n"
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
