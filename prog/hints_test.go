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
		0xdeadbeef: uintptrSet{0xcafebabe: true},
	}
	expected := []string{
		getSimpleProgText(0xcafebabe),
	}
	runTest(m, expected, t, 0xdeadbeef)
}

// Test for cases when there's multiple comparisons (op1, op2), (op1, op3), ...
// Checks that for every such operand a program is generated.
func TestHintsMultipleOps(t *testing.T) {
	m := CompMap{
		0xabcd: uintptrSet{0x1: true, 0x2: true, 0x3: true},
	}
	expected := []string{
		getSimpleProgText(0x1),
		getSimpleProgText(0x2),
		getSimpleProgText(0x3),
	}
	runTest(m, expected, t, 0xabcd)
}

// Test for cases, described in shrinkMutation() function.
func TestHintsConstArgShrinkSize(t *testing.T) {
	m := CompMap{
		0xab: uintptrSet{0x1: true},
	}
	expected := []string{
		getSimpleProgText(0x1),
	}

	// Code for positive values - drop the trash from highest bytes.
	runTest(m, expected, t, 0x12ab)
	runTest(m, expected, t, 0x123456ab)
	runTest(m, expected, t, 0x1234567890abcdab)

	// Code for negative values - drop the 0xff.. prefix
	runTest(m, expected, t, 0xffab)
	runTest(m, expected, t, 0xffffffab)
	runTest(m, expected, t, 0xffffffffffffffab)
}

// Test for cases, described in expandMutation() function.
func TestHintsConstArgExpandSize(t *testing.T) {
	m := CompMap{
		0xffffffffffffffab: uintptrSet{0x1: true},
	}
	expected := []string{
		getSimpleProgText(0x1),
	}
	runTest(m, expected, t, 0xab)
	runTest(m, expected, t, 0xffab)
	runTest(m, expected, t, 0xffffffab)

	m = CompMap{
		0xffffffab: uintptrSet{0x1: true},
	}
	expected = []string{
		getSimpleProgText(0x1),
	}
	runTest(m, expected, t, 0xab)
	runTest(m, expected, t, 0xffab)

	m = CompMap{
		0xffab: uintptrSet{0x1: true},
	}
	expected = []string{
		getSimpleProgText(0x1),
	}
	runTest(m, expected, t, 0xab)
}

// Test for Little/Big Endian conversions.
func TestHintsConstArgEndianness(t *testing.T) {
	m := CompMap{
		0xbeef:             uintptrSet{0x1234: true},
		0xefbe:             uintptrSet{0xabcd: true},
		0xefbe000000000000: uintptrSet{0xabcd: true},
		0xdeadbeef:         uintptrSet{0x1234: true},
		0xefbeadde:         uintptrSet{0xabcd: true},
		0xefbeadde00000000: uintptrSet{0xabcd: true},
		0x1234567890abcdef: uintptrSet{0x1234: true},
		0xefcdab9078563412: uintptrSet{0xabcd: true},
	}
	expected := []string{
		getSimpleProgText(0x1234),
		getSimpleProgText(0xcdab),
		getSimpleProgText(0xcdab000000000000),
	}
	runTest(m, expected, t, 0xbeef)
	runTest(m, expected, t, 0xdeadbeef)
	runTest(m, expected, t, 0x1234567890abcdef)

	m = CompMap{
		0xab:               uintptrSet{0x1234: true},
		0xab00000000000000: uintptrSet{0x1234: true},
	}
	expected = []string{
		getSimpleProgText(0x1234),
		getSimpleProgText(0x3412),
		getSimpleProgText(0x3412000000000000),
	}
	runTest(m, expected, t, 0xab)
}

// Test for reverse() function.
func TestHintsReverse(t *testing.T) {
	// Cut bytes = true.
	vals := []uintptr{0xab, 0xcafe, 0xdeadbeef, 0x1234567890abcdef}
	expected := []uintptr{0xab, 0xfeca, 0xefbeadde, 0xefcdab9078563412}
	for i, v := range vals {
		r := reverse(v, true)
		if r != expected[i] {
			t.Errorf("Got 0x%x expected 0x%x", r, expected[i])
		}
	}

	// Cut bytes = false.
	vals = []uintptr{0xab, 0xcafe, 0xdeadbeef, 0x1234567890abcdef}
	expected = []uintptr{
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
	vals := []uintptr{0x0, 0x01, 0xa2, 0xa3ab, 0xa4abab, 0xa5ababab,
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
		bytesEqual := true
		for j, b := range bytes {
			if exp[i].bytes[j] != b {
				bytesEqual = false
				break
			}
		}
		if !bytesEqual || value != exp[i].value || index != exp[i].index {
			t.Error("got", value, index, bytes, "expected", exp[i])
		}
	}
}

func getSimpleProgText(a uintptr) string {
	return fmt.Sprintf(simpleProgText, a)
}

func runTest(m CompMap, expected []string, t *testing.T, a uintptr) {
	progText := getSimpleProgText(a)
	p, _ := Deserialize([]byte(progText))
	got := make([]string, 0)
	f := func(newP *Prog) {
		got = append(got, string(newP.Serialize()))
	}
	p.MutateWithHints([]CompMap{m}, f)
	if len(got) != len(expected) {
		t.Fatal("Lengths of got and expected differ", "got", got,
			"expected", expected)
	}
	sort.Strings(got)
	sort.Strings(expected)
	for i := range expected {
		if expected[i] != got[i] {
			t.Error("Got", got[i], "expected", expected[i])
		}
	}
}
