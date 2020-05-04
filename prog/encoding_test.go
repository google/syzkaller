// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"bytes"
	"fmt"
	"math/rand"
	"reflect"
	"sort"
	"testing"
)

func setToArray(s map[string]struct{}) []string {
	a := make([]string, 0, len(s))
	for c := range s {
		a = append(a, c)
	}
	sort.Strings(a)
	return a
}

func TestSerializeData(t *testing.T) {
	t.Parallel()
	r := rand.New(rand.NewSource(0))
	for _, readable := range []bool{false, true} {
		for i := 0; i < 1e3; i++ {
			data := make([]byte, r.Intn(4))
			for i := range data {
				data[i] = byte(r.Intn(256))
			}
			buf := new(bytes.Buffer)
			serializeData(buf, data, readable)
			p := newParser(nil, buf.Bytes(), true)
			if !p.Scan() {
				t.Fatalf("parser does not scan")
			}
			data1, err := p.deserializeData()
			if err != nil {
				t.Fatalf("failed to deserialize %q -> %s: %v", data, buf.Bytes(), err)
			}
			if !bytes.Equal(data, data1) {
				t.Fatalf("corrupted data %q -> %s -> %q", data, buf.Bytes(), data1)
			}
		}
	}
}

func TestCallSet(t *testing.T) {
	t.Parallel()
	tests := []struct {
		prog   string
		ok     bool
		calls  []string
		ncalls int
	}{
		{
			"",
			false,
			[]string{},
			0,
		},
		{
			"r0 =  (foo)",
			false,
			[]string{},
			0,
		},
		{
			"getpid()",
			true,
			[]string{"getpid"},
			1,
		},
		{
			"r11 =  getpid()",
			true,
			[]string{"getpid"},
			1,
		},
		{
			"getpid()\n" +
				"open(0x1, something that this package may not understand)\n" +
				"getpid()\n" +
				"#read()\n" +
				"\n" +
				"close$foo(&(0x0000) = {})\n",
			true,
			[]string{"getpid", "open", "close$foo"},
			4,
		},
	}
	for i, test := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			calls, ncalls, err := CallSet([]byte(test.prog))
			if err != nil && test.ok {
				t.Fatalf("parsing failed: %v", err)
			}
			if err == nil && !test.ok {
				t.Fatalf("parsing did not fail")
			}
			callArray := setToArray(calls)
			sort.Strings(test.calls)
			if !reflect.DeepEqual(callArray, test.calls) {
				t.Fatalf("got call set %+v, expect %+v", callArray, test.calls)
			}
			if ncalls != test.ncalls {
				t.Fatalf("got %v calls, expect %v", ncalls, test.ncalls)
			}
		})
	}
}

func TestCallSetRandom(t *testing.T) {
	target, rs, iters := initTest(t)
	ct := target.DefaultChoiceTable()
	for i := 0; i < iters; i++ {
		const ncalls = 10
		p := target.Generate(rs, ncalls, ct)
		calls0 := make(map[string]struct{})
		for _, c := range p.Calls {
			calls0[c.Meta.Name] = struct{}{}
		}
		calls1, ncalls1, err := CallSet(p.Serialize())
		if err != nil {
			t.Fatalf("CallSet failed: %v", err)
		}
		callArray0 := setToArray(calls0)
		callArray1 := setToArray(calls1)
		if !reflect.DeepEqual(callArray0, callArray1) {
			t.Fatalf("got call set:\n%+v\nexpect:\n%+v", callArray1, callArray0)
		}
		if ncalls1 != ncalls {
			t.Fatalf("got %v calls, expect %v", ncalls1, ncalls)
		}
	}
}

func TestDeserialize(t *testing.T) {
	TestDeserializeHelper(t, "test", "64", nil, []DeserializeTest{
		{
			In:  `test$struct(&(0x7f0000000000)={0x0, {0x0}})`,
			Out: `test$struct(&(0x7f0000000000))`,
		},
		{
			In:        `test$struct(&(0x7f0000000000)=0x0)`,
			Out:       `test$struct(&(0x7f0000000000))`,
			StrictErr: "wrong int arg",
		},
		{
			In:  `test$regression1(&(0x7f0000000000)=[{"000000"}, {"0000000000"}])`,
			Out: `test$regression1(&(0x7f0000000000)=[{}, {}])`,
		},
		{
			In:  `test$regression2(&(0x7f0000000000)=[0x1, 0x2, 0x3, 0x4, 0x5, 0x6])`,
			Out: `test$regression2(&(0x7f0000000000)=[0x1, 0x2, 0x3, 0x4])`,
		},
		{
			In:        `test_excessive_args1(0x0, 0x1, {0x1, &(0x7f0000000000)=[0x1, 0x2]})`,
			Out:       `test_excessive_args1()`,
			StrictErr: "excessive syscall arguments",
		},
		{
			In:        `test_excessive_args2(0x0, 0x1, {0x1, &(0x7f0000000000)={0x1, 0x2}})`,
			Out:       `test_excessive_args2(0x0)`,
			StrictErr: "excessive syscall arguments",
		},
		{
			In:        `test_excessive_args2(0x0, 0x1, {0x1, &(0x7f0000000000)=nil})`,
			Out:       `test_excessive_args2(0x0)`,
			StrictErr: "excessive syscall arguments",
		},
		{
			In:        `test_excessive_args2(0x0, &(0x7f0000000000), 0x0)`,
			Out:       `test_excessive_args2(0x0)`,
			StrictErr: "excessive syscall arguments",
		},
		{
			In:        `test$excessive_fields1(&(0x7f0000000000)={0x1, &(0x7f0000000000)=[{0x0}, 0x2]}, {0x1, 0x2, [0x1, 0x2]})`,
			Out:       `test$excessive_fields1(&(0x7f0000000000)={0x1})`,
			StrictErr: "excessive struct excessive_fields fields",
		},
		{
			In: `test$excessive_fields1(0x0)`,
		},
		{
			In:        `test$excessive_fields1(r0)`,
			Out:       `test$excessive_fields1(&(0x7f0000000000))`,
			StrictErr: "undeclared variable r0",
		},
		{
			In:        `test_excessive_args2(r1)`,
			Out:       `test_excessive_args2(0x0)`,
			StrictErr: "undeclared variable r1",
		},
		{
			In:        `test_excessive_args2({0x0, 0x1})`,
			Out:       `test_excessive_args2(0x0)`,
			StrictErr: "wrong struct arg",
		},
		{
			In:        `test_excessive_args2([0x0], 0x0)`,
			Out:       `test_excessive_args2(0x0)`,
			StrictErr: "wrong array arg",
		},
		{
			In:        `test_excessive_args2(@foo)`,
			Out:       `test_excessive_args2(0x0)`,
			StrictErr: "wrong union arg",
		},
		{
			In:        `test_excessive_args2('foo')`,
			Out:       `test_excessive_args2(0x0)`,
			StrictErr: "wrong string arg",
		},
		{
			In:        `test_excessive_args2(&(0x7f0000000000)={0x0, 0x1})`,
			Out:       `test_excessive_args2(0x0)`,
			StrictErr: "wrong addr arg",
		},
		{
			In:  `test_excessive_args2(nil)`,
			Out: `test_excessive_args2(0x0)`,
		},
		{
			In:        `test$type_confusion1(&(0x7f0000000000)=@unknown)`,
			Out:       `test$type_confusion1(&(0x7f0000000000))`,
			StrictErr: "wrong union option",
		},
		{
			In:        `test$type_confusion1(&(0x7f0000000000)=@unknown={0x0, 'abc'}, 0x0)`,
			Out:       `test$type_confusion1(&(0x7f0000000000))`,
			StrictErr: "wrong union option",
		},
		{
			In:        `test$excessive_fields1(&(0x7f0000000000)=0x0)`,
			Out:       `test$excessive_fields1(&(0x7f0000000000))`,
			StrictErr: "wrong int arg",
		},
		{
			In: `test$excessive_fields1(0xffffffffffffffff)`,
		},
		{
			In: `test$excessive_fields1(0xfffffffffffffffe)`,
		},
		{
			In:  `test$excessive_fields1(0xfffffffffffffffd)`,
			Out: `test$excessive_fields1(0x0)`,
		},
		{
			In:  `test$excessive_fields1(0xfffffffffffffffc)`,
			Out: `test$excessive_fields1(0xffffffffffffffff)`,
		},
		{
			In:  `test$auto0(AUTO, &AUTO={AUTO, AUTO, 0x1}, AUTO, 0x0)`,
			Out: `test$auto0(0x42, &(0x7f0000000040)={0xc, 0x43, 0x1}, 0xc, 0x0)`,
		},
		{
			In:  `test$auto0(AUTO, &AUTO={AUTO, AUTO, AUTO}, AUTO, 0x0)`,
			Err: `wrong type *prog.IntType for AUTO`,
		},
		{
			In:  `test$str0(&AUTO="303100090a0d7022273a")`,
			Out: `test$str0(&(0x7f0000000040)='01\x00\t\n\rp\"\':')`,
		},
		{
			In:  `test$blob0(&AUTO="303100090a0d7022273a")`,
			Out: `test$blob0(&(0x7f0000000040)='01\x00\t\n\rp\"\':')`,
		},
		{
			In:  `test$blob0(&AUTO="3031000a0d7022273a01")`,
			Out: `test$blob0(&(0x7f0000000040)="3031000a0d7022273a01")`,
		},
		{
			In:        `test$out_const(&(0x7f0000000000)=0x2)`,
			Out:       `test$out_const(&(0x7f0000000000))`,
			StrictErr: `out arg const[1, const] has non-default value: 2`,
		},
		{
			In: `test$str1(&(0x7f0000000000)='foo\x00')`,
		},
		{
			In:        `test$str1(&(0x7f0000000000)='bar\x00')`,
			Out:       `test$str1(&(0x7f0000000000)='foo\x00')`,
			StrictErr: `bad string value "bar\x00", expect ["foo\x00"]`,
		},
		{
			In: `test$str2(&(0x7f0000000000)='bar\x00')`,
		},
		{
			In:        `test$str2(&(0x7f0000000000)='baz\x00')`,
			Out:       `test$str2(&(0x7f0000000000)='foo\x00')`,
			StrictErr: `bad string value "baz\x00", expect ["foo\x00" "bar\x00"]`,
		},
		{
			In:  `test$opt2(&(0x7f0000000000))`,
			Out: `test$opt2(0x0)`,
		},
		{
			In:        `test$opt2(&(0x7f0000000001))`,
			Out:       `test$opt2(0x0)`,
			StrictErr: `unaligned vma address 0x1`,
		},
		{
			In:  `test$opt2(&(0x7f0000000000)=nil)`,
			Out: `test$opt2(0x0)`,
		},
		{
			In:        `test$opt2(&(0x7f0000000000)='foo')`,
			Out:       `test$opt2(0x0)`,
			StrictErr: `non-nil argument for nil type`,
		},
	})
}

func TestSerializeDeserialize(t *testing.T) {
	TestDeserializeHelper(t, "test", "64", nil, []DeserializeTest{
		{
			In:  `serialize0(&(0x7f0000408000)={"6861736800000000000000000000", "48490000"})`,
			Out: `serialize0(&(0x7f0000408000)={'hash\x00', 'HI\x00'})`,
		},
		{
			In:  `serialize1(&(0x7f0000000000)="0000000000000000", 0x8)`,
			Out: `serialize1(&(0x7f0000000000)=""/8, 0x8)`,
		},
	})
}

func TestSerializeDeserializeRandom(t *testing.T) {
	testEachTargetRandom(t, func(t *testing.T, target *Target, rs rand.Source, iters int) {
		ct := target.DefaultChoiceTable()
		data0 := make([]byte, ExecBufferSize)
		data1 := make([]byte, ExecBufferSize)
		for i := 0; i < iters; i++ {
			p0 := target.Generate(rs, 10, ct)
			if ok, _, _ := testSerializeDeserialize(t, p0, data0, data1); ok {
				continue
			}
			p0, _ = Minimize(p0, -1, false, func(p1 *Prog, _ int) bool {
				ok, _, _ := testSerializeDeserialize(t, p1, data0, data1)
				return !ok
			})
			ok, n0, n1 := testSerializeDeserialize(t, p0, data0, data1)
			if ok {
				t.Log("flaky?")
			}
			decoded0, err := target.DeserializeExec(data0[:n0])
			if err != nil {
				t.Fatal(err)
			}
			decoded1, err := target.DeserializeExec(data1[:n1])
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("decoded0: %+v", decoded0)
			t.Logf("decoded1: %+v", decoded1)
			t.Fatalf("was: %q\ngot: %q\nprogram:\n%s",
				data0[:n0], data1[:n1], p0.Serialize())
		}
	})
}

func testSerializeDeserialize(t *testing.T, p0 *Prog, data0, data1 []byte) (bool, int, int) {
	n0, err := p0.SerializeForExec(data0)
	if err != nil {
		t.Fatal(err)
	}
	serialized := p0.Serialize()
	p1, err := p0.Target.Deserialize(serialized, NonStrict)
	if err != nil {
		t.Fatal(err)
	}
	n1, err := p1.SerializeForExec(data1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data0[:n0], data1[:n1]) {
		t.Logf("PROG0:\n%s\n", p0.Serialize())
		t.Logf("PROG1:\n%s\n", p1.Serialize())
		return false, n0, n1
	}
	return true, 0, 0
}

func TestDeserializeComments(t *testing.T) {
	target := initTargetTest(t, "test", "64")
	p, err := target.Deserialize([]byte(`
# comment1
# comment2
serialize0(0x0)
serialize0(0x0)
# comment3
serialize0(0x0)
# comment4
serialize0(0x0)	#  comment5
#comment6

serialize0(0x0)
#comment7
`), Strict)
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []string{
		"comment2",
		"",
		"comment3",
		"comment5",
		"",
	} {
		if got := p.Calls[i].Comment; got != want {
			t.Errorf("bad call %v comment: %q, want %q", i, got, want)
		}
	}
	wantComments := []string{
		"comment1",
		"comment4",
		"comment6",
		"comment7",
	}
	if !reflect.DeepEqual(p.Comments, wantComments) {
		t.Errorf("bad program comments %q\nwant: %q", p.Comments, wantComments)
	}
}
