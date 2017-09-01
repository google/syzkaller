// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/google/syzkaller/sys"
)

type ConstArgTest struct {
	name  string
	in    uint64
	comps CompMap
	res   uint64Set
}

type DataArgTest struct {
	name  string
	in    string
	comps CompMap
	res   map[string]bool
}

// Tests checkConstArg(). Is not intended to check correctness of any mutations.
// Mutation are checked in their own tests.
func TestHintsCheckConstArg(t *testing.T) {
	var tests = []ConstArgTest{
		{
			"One replacer test",
			0xdeadbeef,
			CompMap{0xdeadbeef: uint64Set{0xcafebabe: true}},
			uint64Set{0xcafebabe: true},
		},
		// Test for cases when there's multiple comparisons (op1, op2), (op1, op3), ...
		// Checks that for every such operand a program is generated.
		{
			"Multiple replacers test",
			0xabcd,
			CompMap{0xabcd: uint64Set{0x2: true, 0x3: true}},
			uint64Set{0x2: true, 0x3: true},
		},
		// Checks that special ints are not used.
		{
			"Special ints test",
			0xabcd,
			CompMap{0xabcd: uint64Set{0x1: true, 0x2: true}},
			uint64Set{0x2: true},
		},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("%v", test.name), func(t *testing.T) {
			res := uint64Set{}
			constArg := &ConstArg{ArgCommon{nil}, test.in}
			checkConstArg(constArg, test.comps, func(arg Arg) {
				res[arg.(*ConstArg).Val] = true
			})
			if !reflect.DeepEqual(res, test.res) {
				t.Fatalf("\ngot : %v\nwant: %v", res, test.res)
			}
		})
	}
}

// Tests checkDataArg(). Is not intended to check correctness of any mutations.
// Mutation are checked in their own tests.
func TestHintsCheckDataArg(t *testing.T) {
	// All inputs are in Little-Endian.
	var tests = []DataArgTest{
		{
			"One replacer test",
			"\xef\xbe\xad\xde",
			CompMap{0xdeadbeef: uint64Set{0xcafebabe: true}},
			map[string]bool{
				"\xbe\xba\xfe\xca": true,
			},
		},
		// Test for cases when there's multiple comparisons (op1, op2), (op1, op3), ...
		// Checks that for every such operand a program is generated.
		{
			"Multiple replacers test",
			"\xcd\xab",
			CompMap{0xabcd: uint64Set{0x2: true, 0x3: true}},
			map[string]bool{
				"\x02\x00": true, "\x03\x00": true,
			},
		},
		// Checks that special ints are not used.
		{
			"Special ints test",
			"\xcd\xab",
			CompMap{0xabcd: uint64Set{0x1: true, 0x2: true}},
			map[string]bool{
				"\x02\x00": true,
			},
		},
		// Checks that ints of various sizes are extracted.
		{
			"Different sizes test",
			"\xef\xcd\xab\x90\x78\x56\x34\x12",
			CompMap{
				0xef:               uint64Set{0x11: true},
				0xcdef:             uint64Set{0x2222: true},
				0x90abcdef:         uint64Set{0x33333333: true},
				0x1234567890abcdef: uint64Set{0x4444444444444444: true},
			},
			map[string]bool{
				"\x11\xcd\xab\x90\x78\x56\x34\x12": true,
				"\x22\x22\xab\x90\x78\x56\x34\x12": true,
				"\x33\x33\x33\x33\x78\x56\x34\x12": true,
				"\x44\x44\x44\x44\x44\x44\x44\x44": true,
			},
		},
		// Checks that values with different offsets are extracted.
		{
			"Different offsets test",
			"\xab\xab\xab\xab\xab\xab\xab\xab\xab",
			CompMap{
				0xab:               uint64Set{0x11: true},
				0xabab:             uint64Set{0x2222: true},
				0xabababab:         uint64Set{0x33333333: true},
				0xabababababababab: uint64Set{0x4444444444444444: true},
			},
			map[string]bool{
				"\x11\xab\xab\xab\xab\xab\xab\xab\xab": true,
				"\xab\x11\xab\xab\xab\xab\xab\xab\xab": true,
				"\xab\xab\x11\xab\xab\xab\xab\xab\xab": true,
				"\xab\xab\xab\x11\xab\xab\xab\xab\xab": true,
				"\xab\xab\xab\xab\x11\xab\xab\xab\xab": true,
				"\xab\xab\xab\xab\xab\x11\xab\xab\xab": true,
				"\xab\xab\xab\xab\xab\xab\x11\xab\xab": true,
				"\xab\xab\xab\xab\xab\xab\xab\x11\xab": true,
				"\xab\xab\xab\xab\xab\xab\xab\xab\x11": true,
				"\x22\x22\xab\xab\xab\xab\xab\xab\xab": true,
				"\xab\x22\x22\xab\xab\xab\xab\xab\xab": true,
				"\xab\xab\x22\x22\xab\xab\xab\xab\xab": true,
				"\xab\xab\xab\x22\x22\xab\xab\xab\xab": true,
				"\xab\xab\xab\xab\x22\x22\xab\xab\xab": true,
				"\xab\xab\xab\xab\xab\x22\x22\xab\xab": true,
				"\xab\xab\xab\xab\xab\xab\x22\x22\xab": true,
				"\xab\xab\xab\xab\xab\xab\xab\x22\x22": true,
				"\x33\x33\x33\x33\xab\xab\xab\xab\xab": true,
				"\xab\x33\x33\x33\x33\xab\xab\xab\xab": true,
				"\xab\xab\x33\x33\x33\x33\xab\xab\xab": true,
				"\xab\xab\xab\x33\x33\x33\x33\xab\xab": true,
				"\xab\xab\xab\xab\x33\x33\x33\x33\xab": true,
				"\xab\xab\xab\xab\xab\x33\x33\x33\x33": true,
				"\x44\x44\x44\x44\x44\x44\x44\x44\xab": true,
				"\xab\x44\x44\x44\x44\x44\x44\x44\x44": true,
			},
		},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("%v", test.name), func(t *testing.T) {
			res := make(map[string]bool)
			// Whatever type here. It's just needed to pass the
			// dataArg.Type().Dir() == sys.DirIn check.
			typ := sys.ArrayType{sys.TypeCommon{"", "", sys.DirIn, false}, nil, 0, 0, 0}
			argCommon := ArgCommon{&typ}
			dataArg := &DataArg{argCommon, []byte(test.in)}
			checkDataArg(dataArg, test.comps, func(arg Arg) {
				res[string(arg.(*DataArg).Data)] = true
			})
			if !reflect.DeepEqual(res, test.res) {
				s := "\ngot: ["
				for x := range res {
					s += fmt.Sprintf("0x%x, ", x)
				}
				s += "]\nwant: ["
				for x := range test.res {
					s += fmt.Sprintf("0x%x, ", x)
				}
				s += "]\n"
				t.Fatalf(s)
			}
		})
	}
}

func TestHintsShrinkExpand(t *testing.T) {
	// Naming conventions:
	// b  - byte  variable (i8 or u8)
	// w  - word  variable (i16 or u16)
	// dw - dword variable (i32 or u32)
	// qw - qword variable (i64 or u64)
	// -----------------------------------------------------------------
	// Shrink tests:
	var tests = []ConstArgTest{
		{
			// Models the following code:
			// void f(u16 w) {
			//		u8 b = (u8) w;
			//		if (b == 0xab) {...}
			//		if (w == 0xcdcd) {...}
			//  }; f(0x1234);
			"Shrink 16 test",
			0x1234,
			CompMap{
				0x34:   uint64Set{0xab: true},
				0x1234: uint64Set{0xcdcd: true},
			},
			uint64Set{0x12ab: true, 0xcdcd: true},
		},
		{
			// Models the following code:
			// void f(u32 dw) {
			//		u8 b = (u8) dw
			//		i16 w = (i16) dw
			//		if (a == 0xab) {...}
			//		if (b == 0xcdcd) {...}
			//		if (dw == 0xefefefef) {...}
			//  }; f(0x12345678);
			"Shrink 32 test",
			0x12345678,
			CompMap{
				0x78:       uint64Set{0xab: true},
				0x5678:     uint64Set{0xcdcd: true},
				0x12345678: uint64Set{0xefefefef: true},
			},
			uint64Set{0x123456ab: true, 0x1234cdcd: true, 0xefefefef: true},
		},
		{
			// Models the following code:
			// void f(u64 qw) {
			//		u8 b = (u8) qw
			//		u16 w = (u16) qw
			//		u32 dw = (u32) qw
			//		if (a == 0xab) {...}
			//		if (b == 0xcdcd) {...}
			//		if (dw == 0xefefefef) {...}
			//		if (qw == 0x0101010101010101) {...}
			//  }; f(0x1234567890abcdef);
			"Shrink 64 test",
			0x1234567890abcdef,
			CompMap{
				0xef:               uint64Set{0xab: true},
				0xcdef:             uint64Set{0xcdcd: true},
				0x90abcdef:         uint64Set{0xefefefef: true},
				0x1234567890abcdef: uint64Set{0x0101010101010101: true},
			},
			uint64Set{
				0x1234567890abcdab: true,
				0x1234567890abcdcd: true,
				0x12345678efefefef: true,
				0x0101010101010101: true,
			},
		},
		{
			// Models the following code:
			// void f(i16 w) {
			//		i8 b = (i8) w;
			//		i16 other = 0xabab;
			//		if (b == other) {...}
			//  }; f(0x1234);
			// In such code the comparison will never be true, so we don't
			// generate a hint for it.
			"Shrink with a wider replacer test1",
			0x1234,
			CompMap{0x34: uint64Set{0x1bab: true}},
			uint64Set{},
		},
		{
			// Models the following code:
			// void f(i16 w) {
			//		i8 b = (i8) w;
			//		i16 other = 0xfffd;
			//		if (b == other) {...}
			//  }; f(0x1234);
			// In such code b will be sign extended to 0xff34 and, if we replace
			// the lower byte, then the if statement will be true.
			// Note that executor sign extends all the comparison operands to
			// int64, so we model this accordingly.
			"Shrink with a wider replacer test2",
			0x1234,
			CompMap{0x34: uint64Set{0xfffffffffffffffd: true}},
			uint64Set{0x12fd: true},
		},
		// -----------------------------------------------------------------
		// Extend tests:
		// Note that executor sign extends all the comparison operands to int64,
		// so we model this accordingly.
		{
			// Models the following code:
			// void f(i8 b) {
			//		i64 qw = (i64) b;
			//		if (qw == -2) {...};
			// }; f(-1);
			"Extend 8 test",
			0xff,
			CompMap{0xffffffffffffffff: uint64Set{0xfffffffffffffffe: true}},
			uint64Set{0xfe: true},
		},
		{
			// Models the following code:
			// void f(i16 w) {
			//		i64 qw = (i64) w;
			//		if (qw == -2) {...};
			// }; f(-1);
			"Extend 16 test",
			0xffff,
			CompMap{0xffffffffffffffff: uint64Set{0xfffffffffffffffe: true}},
			uint64Set{0xfffe: true},
		},
		{
			// Models the following code:
			// void f(i32 dw) {
			//		i64 qw = (i32) dw;
			//		if (qw == -2) {...};
			// }; f(-1);
			"Extend 32 test",
			0xffffffff,
			CompMap{0xffffffffffffffff: uint64Set{0xfffffffffffffffe: true}},
			uint64Set{0xfffffffe: true},
		},
		{
			// Models the following code:
			// void f(i8 b) {
			//		i16 w = (i16) b;
			//		if (w == (i16) 0xfeff) {...};
			// }; f(-1);
			// There's no value for b that will make the comparison true,
			// so we don't generate hints.
			"Extend with a wider replacer test",
			0xff,
			CompMap{0xffffffffffffffff: uint64Set{0xfffffffffffffeff: true}},
			uint64Set{},
		},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("%v", test.name), func(t *testing.T) {
			res := shrinkExpand(test.in, test.comps)
			if !reflect.DeepEqual(res, test.res) {
				t.Fatalf("\ngot : %v\nwant: %v", res, test.res)
			}
		})
	}
}
