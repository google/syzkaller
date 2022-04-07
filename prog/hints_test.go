// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"reflect"
	"sort"
	"testing"
)

type ConstArgTest struct {
	name    string
	in      uint64
	size    uint64
	bitsize uint64
	comps   CompMap
	res     []uint64
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
	target := initTargetTest(t, "test", "64")
	var tests = []ConstArgTest{
		{
			name:  "one-replacer-test",
			in:    0xdeadbeef,
			size:  4,
			comps: CompMap{0xdeadbeef: compSet(0xdeadbeef, 0xcafebabe)},
			res:   []uint64{0xcafebabe},
		},
		// Test for cases when there's multiple comparisons (op1, op2), (op1, op3), ...
		// Checks that for every such operand a program is generated.
		{
			name:  "multiple-replacers-test",
			in:    0xabcd,
			size:  2,
			comps: CompMap{0xabcd: compSet(0x2, 0x3)},
			res:   []uint64{0x2, 0x3},
		},
		// Checks that special ints are not used.
		{
			name:  "special-ints-test",
			in:    0xabcd,
			size:  2,
			comps: CompMap{0xabcd: compSet(0x1, 0x2)},
			res:   []uint64{0x2},
		},

		// The following tests check the size limits for each replacer and for the initial value
		// of the argument. The checks are made for positive and negative values and also for bitfields.
		{
			name: "int8-invalid-positive-value",
			in:   0x1234,
			size: 1,
			comps: CompMap{
				// void test8(i8 el) {
				//		i16 w = (i16) el
				//		if (w == 0x88) {...}
				//		i16 other = 0xfffe
				//		if (w == other)
				//  }; test8(i8(0x1234));
				0x34: compSet(0x88, 0x1122, 0xfffffffffffffffe, 0xffffffffffffff0a),
				// This following args should be iggnored.
				0x1234:             compSet(0xa1),
				0xffffffffffffff34: compSet(0xaa),
			},
			res: []uint64{0x88, 0xfe},
		},
		{
			name: "int8-invalid-negative-value",
			in:   0x12ab,
			size: 1,
			comps: CompMap{
				0xab:               compSet(0xab, 0xac, 0xabcd),
				0xffffffffffffffab: compSet(0x11, 0x22, 0xffffffffffffff34),
			},
			res: []uint64{0x11, 0x22, 0xac},
		},
		{
			name:    "int16-valid-value-bitsize-12",
			in:      0x3ab,
			size:    2,
			bitsize: 12,
			comps: CompMap{
				0x3ab:              compSet(0x11, 0x1234, 0xfffffffffffffffe),
				0x13ab:             compSet(0xab, 0xffa),
				0xffffffffffffffab: compSet(0xfffffffffffffff1),
				0xfffffffffffff3ab: compSet(0xff1, 0x12),
			},
			res: []uint64{0x11, 0x3f1, 0xffe},
		},
		{
			name:    "int16-invalid-value-bitsize-12",
			in:      0x71ab,
			size:    2,
			bitsize: 12,
			comps: CompMap{
				0x1ab: compSet(0x11, 0x1234, 0xfffffffffffffffe),
			},
			res: []uint64{0x11, 0xffe},
		},
		{
			name:    "int16-negative-valid-value-bitsize-12",
			in:      0x8ab,
			size:    2,
			bitsize: 12,
			comps: CompMap{
				0x8ab:              compSet(0x11),
				0xffffffffffffffab: compSet(0x12, 0xffffffffffffff0a),
				0xfffffffffffff8ab: compSet(0x13, 0xffffffffffffff00),
			},
			res: []uint64{0x11, 0x13, 0x80a, 0x812, 0xf00},
		},
		{
			name:    "int16-negative-invalid-value-bitsize-12",
			in:      0x88ab,
			size:    2,
			bitsize: 12,
			comps: CompMap{
				0x8ab:              compSet(0x13),
				0xfffffffffffff8ab: compSet(0x11, 0xffffffffffffff11),
			},
			res: []uint64{0x11, 0x13, 0xf11},
		},
		{
			name: "int32-invalid-value",
			in:   0xaabaddcafe,
			size: 4,
			comps: CompMap{0xbaddcafe: compSet(0xab, 0xabcd, 0xbaddcafe,
				0xdeadbeef, 0xaabbccddeeff1122)},
			res: []uint64{0xab, 0xabcd, 0xdeadbeef},
		},
		{
			name:  "int64-valid-value",
			in:    0xdeadc0debaddcafe,
			size:  8,
			comps: CompMap{0xdeadc0debaddcafe: compSet(0xab, 0xabcd, 0xdeadbeef, 0xdeadbeefdeadbeef)},
			res:   []uint64{0xab, 0xabcd, 0xdeadbeef, 0xdeadbeefdeadbeef},
		},
	}
	meta := target.SyscallMap["test$hint_int"]
	structType := meta.Args[0].Type.(*PtrType).Elem.(*StructType)
	types := make(map[string]Type)
	for _, field := range structType.Fields {
		types[field.Name] = field.Type
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("%v", test.name), func(t *testing.T) {
			var res []uint64
			typ := types[fmt.Sprintf("int%v_%v", test.size, test.bitsize)]
			constArg := MakeConstArg(typ, DirIn, test.in)
			checkConstArg(constArg, test.comps, func() {
				res = append(res, constArg.Val)
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
	target := initTargetTest(t, "test", "64")
	// All inputs are in Little-Endian.
	var tests = []DataArgTest{
		{
			"one-replacer-test",
			"\xef\xbe\xad\xde",
			CompMap{
				0xdeadbeef: compSet(0xcafebabe, 0xdeadbeef),
				0xbeef:     compSet(0xbeef),
				0xef:       compSet(0xef),
			},
			map[string]bool{
				"\xbe\xba\xfe\xca": true,
			},
		},
		// Test for cases when there's multiple comparisons (op1, op2), (op1, op3), ...
		// Checks that for every such operand a program is generated.
		{
			"multiple-replacers-test",
			"\xcd\xab",
			CompMap{0xabcd: compSet(0x2, 0x3)},
			map[string]bool{
				"\x02\x00": true, "\x03\x00": true,
			},
		},
		// Checks that special ints are not used.
		{
			"special-ints-test",
			"\xcd\xab",
			CompMap{0xabcd: compSet(0x1, 0x2)},
			map[string]bool{
				"\x02\x00": true,
			},
		},
		// Checks that ints of various sizes are extracted.
		{
			"different-sizes-test",
			"\xef\xcd\xab\x90\x78\x56\x34\x12",
			CompMap{
				0xef:               compSet(0x11),
				0xcdef:             compSet(0x2222),
				0x90abcdef:         compSet(0x33333333),
				0x1234567890abcdef: compSet(0x4444444444444444),
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
			"different-offsets-test",
			"\xab\xab\xab\xab\xab\xab\xab\xab\xab",
			CompMap{
				0xab:               compSet(0x11),
				0xabab:             compSet(0x2222),
				0xabababab:         compSet(0x33333333),
				0xabababababababab: compSet(0x4444444444444444),
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
		{
			"replace-in-the-middle-of-a-larger-blob",
			"\xef\xcd\xab\x90\x78\x56\x34\x12",
			CompMap{0xffffffffffff90ab: compSet(0xffffffffffffaabb)},
			map[string]bool{
				"\xef\xcd\xbb\xaa\x78\x56\x34\x12": true,
			},
		},
		{

			"big-endian-replace",
			"\xef\xcd\xab\x90\x78\x56\x34\x12",
			CompMap{
				// 0xff07 is reversed special int.
				0xefcd:             compSet(0xaabb, 0xff07),
				0x3412:             compSet(0xaabb, 0xff07),
				0x9078:             compSet(0xaabb, 0x11223344, 0xff07),
				0x90785634:         compSet(0xaabbccdd, 0x11223344),
				0xefcdab9078563412: compSet(0x1122334455667788),
			},
			map[string]bool{
				"\xaa\xbb\xab\x90\x78\x56\x34\x12": true,
				"\xef\xcd\xab\x90\x78\x56\xaa\xbb": true,
				"\xef\xcd\xab\xaa\xbb\x56\x34\x12": true,
				"\xef\xcd\xab\xaa\xbb\xcc\xdd\x12": true,
				"\xef\xcd\xab\x11\x22\x33\x44\x12": true,
				"\x11\x22\x33\x44\x55\x66\x77\x88": true,
			},
		},
	}
	meta := target.SyscallMap["test$hint_data"]
	typ := meta.Args[0].Type.(*PtrType).Elem // array[int8]
	for _, test := range tests {
		t.Run(fmt.Sprintf("%v", test.name), func(t *testing.T) {
			res := make(map[string]bool)
			dataArg := MakeDataArg(typ, DirIn, []byte(test.in))
			checkDataArg(dataArg, test.comps, func() {
				res[string(dataArg.Data())] = true
			})
			if !reflect.DeepEqual(res, test.res) {
				s := "\ngot:  ["
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
	t.Parallel()
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
			name: "shrink-16-test",
			in:   0x1234,
			comps: CompMap{
				0x34:   compSet(0xab),
				0x1234: compSet(0xcdcd),
			},
			res: []uint64{0x12ab, 0xcdcd},
		},
		{
			// Models the following code:
			// void f(u32 dw) {
			//		u8 b = (u8) dw
			//		i16 w = (i16) dw
			//		if (b == 0xab) {...}
			//		if (w == 0xcdcd) {...}
			//		if (dw == 0xefefefef) {...}
			//  }; f(0x12345678);
			name: "shrink-32-test",
			in:   0x12345678,
			comps: CompMap{
				0x78:       compSet(0xab),
				0x5678:     compSet(0xcdcd),
				0x12345678: compSet(0xefefefef),
			},
			res: []uint64{0x123456ab, 0x1234cdcd, 0xefefefef},
		},
		{
			// Models the following code:
			// void f(u64 qw) {
			//		u8 b = (u8) qw
			//		u16 w = (u16) qw
			//		u32 dw = (u32) qw
			//		if (b == 0xab) {...}
			//		if (w == 0xcdcd) {...}
			//		if (dw == 0xefefefef) {...}
			//		if (qw == 0x0101010101010101) {...}
			//  }; f(0x1234567890abcdef);
			name: "shrink-64-test",
			in:   0x1234567890abcdef,
			comps: CompMap{
				0xef:               compSet(0xab, 0xef),
				0xcdef:             compSet(0xcdcd),
				0x90abcdef:         compSet(0xefefefef),
				0x1234567890abcdef: compSet(0x0101010101010101),
			},
			res: []uint64{
				0x0101010101010101,
				0x1234567890abcdab,
				0x1234567890abcdcd,
				0x12345678efefefef,
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
			name:  "shrink-with-a-wider-replacer-test1",
			in:    0x1234,
			comps: CompMap{0x34: compSet(0x1bab)},
			res:   nil,
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
			name:  "shrink-with-a-wider-replacer-test2",
			in:    0x1234,
			comps: CompMap{0x34: compSet(0xfffffffffffffffd)},
			res:   []uint64{0x12fd},
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
			name:  "extend-8-test",
			in:    0xff,
			comps: CompMap{0xffffffffffffffff: compSet(0xfffffffffffffffe)},
			res:   []uint64{0xfe},
		},
		{
			// Models the following code:
			// void f(i16 w) {
			//		i64 qw = (i64) w;
			//		if (qw == -2) {...};
			// }; f(-1);
			name:  "extend-16-test",
			in:    0xffff,
			comps: CompMap{0xffffffffffffffff: compSet(0xfffffffffffffffe)},
			res:   []uint64{0xfffe},
		},
		{
			// Models the following code:
			// void f(i32 dw) {
			//		i64 qw = (i32) dw;
			//		if (qw == -2) {...};
			// }; f(-1);
			name:  "extend-32-test",
			in:    0xffffffff,
			comps: CompMap{0xffffffffffffffff: compSet(0xfffffffffffffffe)},
			res:   []uint64{0xfffffffe},
		},
		{
			// Models the following code:
			// void f(i8 b) {
			//		i16 w = (i16) b;
			//		if (w == (i16) 0xfeff) {...};
			// }; f(-1);
			// There's no value for b that will make the comparison true,
			// so we don't generate hints.
			name:  "extend-with-a-wider-replacer-test",
			in:    0xff,
			comps: CompMap{0xffffffffffffffff: compSet(0xfffffffffffffeff)},
			res:   nil,
		},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("%v", test.name), func(t *testing.T) {
			res := shrinkExpand(test.in, test.comps, 64)
			if !reflect.DeepEqual(res, test.res) {
				t.Fatalf("\ngot : %v\nwant: %v", res, test.res)
			}
		})
	}
}

func TestHintsRandom(t *testing.T) {
	target, rs, iters := initTest(t)
	ct := target.DefaultChoiceTable()
	iters /= 10 // the test takes long
	r := newRand(target, rs)
	for i := 0; i < iters; i++ {
		p := target.Generate(rs, 5, ct)
		for i, c := range p.Calls {
			vals := extractValues(c)
			for j := 0; j < 5; j++ {
				vals[r.randInt64()] = true
			}
			comps := make(CompMap)
			for v := range vals {
				comps.AddComp(v, r.randInt64())
			}
			p.MutateWithHints(i, comps, func(p1 *Prog) {})
		}
	}
}

func extractValues(c *Call) map[uint64]bool {
	vals := make(map[uint64]bool)
	ForeachArg(c, func(arg Arg, _ *ArgCtx) {
		if arg.Dir() == DirOut {
			return
		}
		switch a := arg.(type) {
		case *ConstArg:
			vals[a.Val] = true
		case *DataArg:
			data := a.Data()
			for i := range data {
				vals[uint64(data[i])] = true
				if i < len(data)-1 {
					v := uint64(data[i]) | uint64(data[i+1])<<8
					vals[v] = true
				}
				if i < len(data)-3 {
					v := uint64(data[i]) | uint64(data[i+1])<<8 |
						uint64(data[i+2])<<16 | uint64(data[i+3])<<24
					vals[v] = true
				}
				if i < len(data)-7 {
					v := uint64(data[i]) | uint64(data[i+1])<<8 |
						uint64(data[i+2])<<16 | uint64(data[i+3])<<24 |
						uint64(data[i+4])<<32 | uint64(data[i+5])<<40 |
						uint64(data[i+6])<<48 | uint64(data[i+7])<<56
					vals[v] = true
				}
			}
		}
	})
	delete(vals, 0) // replacing 0 can yield too many condidates
	return vals
}

func TestHintsData(t *testing.T) {
	target := initTargetTest(t, "test", "64")
	type Test struct {
		in    string
		comps CompMap
		out   []string
	}
	tests := []Test{
		{
			in:    "0809101112131415",
			comps: CompMap{0x12111009: compSet(0x10)},
			out:   []string{"0810000000131415"},
		},
	}
	for _, test := range tests {
		p, err := target.Deserialize([]byte(fmt.Sprintf("test$hint_data(&AUTO=\"%v\")", test.in)), Strict)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		p.MutateWithHints(0, test.comps, func(newP *Prog) {
			got = append(got, hex.EncodeToString(
				newP.Calls[0].Args[0].(*PointerArg).Res.(*DataArg).Data()))
		})
		sort.Strings(test.out)
		sort.Strings(got)
		if !reflect.DeepEqual(got, test.out) {
			t.Fatalf("comps: %v\ninput: %v\ngot : %+v\nwant: %+v",
				test.comps, test.in, got, test.out)
		}
	}
}

func BenchmarkHints(b *testing.B) {
	target, cleanup := initBench(b)
	defer cleanup()
	rs := rand.NewSource(0)
	r := newRand(target, rs)
	ct := target.DefaultChoiceTable()
	p := target.Generate(rs, 30, ct)
	comps := make([]CompMap, len(p.Calls))
	for i, c := range p.Calls {
		vals := extractValues(c)
		for j := 0; j < 5; j++ {
			vals[r.randInt64()] = true
		}
		comps[i] = make(CompMap)
		for v := range vals {
			comps[i].AddComp(v, r.randInt64())
		}
	}
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			for i := range p.Calls {
				p.MutateWithHints(i, comps[i], func(p1 *Prog) {})
			}
		}
	})
}

func compSet(vals ...uint64) map[uint64]bool {
	m := make(map[uint64]bool)
	for _, v := range vals {
		m[v] = true
	}
	return m
}
