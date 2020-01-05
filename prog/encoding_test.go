// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"bytes"
	"fmt"
	"math/rand"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
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
		prog  string
		ok    bool
		calls []string
	}{
		{
			"",
			false,
			[]string{},
		},
		{
			"r0 =  (foo)",
			false,
			[]string{},
		},
		{
			"getpid()",
			true,
			[]string{"getpid"},
		},
		{
			"r11 =  getpid()",
			true,
			[]string{"getpid"},
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
		},
	}
	for i, test := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			calls, err := CallSet([]byte(test.prog))
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
		})
	}
}

func TestCallSetRandom(t *testing.T) {
	target, rs, iters := initTest(t)
	for i := 0; i < iters; i++ {
		p := target.Generate(rs, 10, nil)
		calls0 := make(map[string]struct{})
		for _, c := range p.Calls {
			calls0[c.Meta.Name] = struct{}{}
		}
		calls1, err := CallSet(p.Serialize())
		if err != nil {
			t.Fatalf("CallSet failed: %v", err)
		}
		callArray0 := setToArray(calls0)
		callArray1 := setToArray(calls1)
		if !reflect.DeepEqual(callArray0, callArray1) {
			t.Fatalf("got call set:\n%+v\nexpect:\n%+v", callArray1, callArray0)
		}
	}
}

func TestDeserialize(t *testing.T) {
	target := initTargetTest(t, "test", "64")
	tests := []struct {
		input     string
		output    string
		err       string
		strictErr string
	}{
		{
			input: `test$struct(&(0x7f0000000000)={0x0, {0x0}})`,
		},
		{
			input:     `test$struct(&(0x7f0000000000)=0x0)`,
			output:    `test$struct(&(0x7f0000000000))`,
			strictErr: "wrong int arg",
		},
		{
			input: `test$regression1(&(0x7f0000000000)=[{"000000"}, {"0000000000"}])`,
		},
		{
			input: `test$regression2(&(0x7f0000000000)=[0x1, 0x2, 0x3, 0x4, 0x5, 0x6])`,
		},
		{
			input:     `test$excessive_args1(0x0, 0x1, {0x1, &(0x7f0000000000)=[0x1, 0x2]})`,
			strictErr: "excessive syscall arguments",
		},
		{
			input:     `test$excessive_args2(0x0, 0x1, {0x1, &(0x7f0000000000)={0x1, 0x2}})`,
			strictErr: "excessive syscall arguments",
		},
		{
			input:     `test$excessive_args2(0x0, 0x1, {0x1, &(0x7f0000000000)=nil})`,
			strictErr: "excessive syscall arguments",
		},
		{
			input:     `test$excessive_args2(0x0, &(0x7f0000000000), 0x0)`,
			strictErr: "excessive syscall arguments",
		},
		{
			input:     `test$excessive_fields1(&(0x7f0000000000)={0x1, &(0x7f0000000000)=[{0x0}, 0x2]}, {0x1, 0x2, [0x1, 0x2]})`,
			strictErr: "excessive struct excessive_fields fields",
		},
		{
			input:  `test$excessive_fields1(0x0)`,
			output: `test$excessive_fields1(0x0)`,
		},
		{
			input:     `test$excessive_fields1(r0)`,
			output:    `test$excessive_fields1(&(0x7f0000000000))`,
			strictErr: "undeclared variable r0",
		},
		{
			input:     `test$excessive_args2(r1)`,
			output:    `test$excessive_args2(0x0)`,
			strictErr: "undeclared variable r1",
		},
		{
			input:     `test$excessive_args2({0x0, 0x1})`,
			output:    `test$excessive_args2(0x0)`,
			strictErr: "wrong struct arg",
		},
		{
			input:     `test$excessive_args2([0x0], 0x0)`,
			output:    `test$excessive_args2(0x0)`,
			strictErr: "wrong array arg",
		},
		{
			input:     `test$excessive_args2(@foo)`,
			output:    `test$excessive_args2(0x0)`,
			strictErr: "wrong union arg",
		},
		{
			input:     `test$excessive_args2('foo')`,
			output:    `test$excessive_args2(0x0)`,
			strictErr: "wrong string arg",
		},
		{
			input:     `test$excessive_args2(&(0x7f0000000000)={0x0, 0x1})`,
			output:    `test$excessive_args2(0x0)`,
			strictErr: "wrong addr arg",
		},
		{
			input:  `test$excessive_args2(nil)`,
			output: `test$excessive_args2(0x0)`,
		},
		{
			input:     `test$type_confusion1(&(0x7f0000000000)=@unknown)`,
			output:    `test$type_confusion1(&(0x7f0000000000))`,
			strictErr: "wrong union option",
		},
		{
			input:     `test$type_confusion1(&(0x7f0000000000)=@unknown={0x0, 'abc'}, 0x0)`,
			output:    `test$type_confusion1(&(0x7f0000000000))`,
			strictErr: "wrong union option",
		},
		{
			input:     `test$excessive_fields1(&(0x7f0000000000)=0x0)`,
			output:    `test$excessive_fields1(&(0x7f0000000000))`,
			strictErr: "wrong int arg",
		},
		{
			input:  `test$excessive_fields1(0x0)`,
			output: `test$excessive_fields1(0x0)`,
		},
		{
			input:  `test$excessive_fields1(0xffffffffffffffff)`,
			output: `test$excessive_fields1(0xffffffffffffffff)`,
		},
		{
			input:  `test$excessive_fields1(0xfffffffffffffffe)`,
			output: `test$excessive_fields1(0xfffffffffffffffe)`,
		},
		{
			input:  `test$excessive_fields1(0xfffffffffffffffd)`,
			output: `test$excessive_fields1(0x0)`,
		},
		{
			input:  `test$excessive_fields1(0xfffffffffffffffc)`,
			output: `test$excessive_fields1(0xffffffffffffffff)`,
		},
		{
			input:  `test$auto0(AUTO, &AUTO={AUTO, AUTO, 0x1}, AUTO, 0x0)`,
			output: `test$auto0(0x42, &(0x7f0000000040)={0xc, 0x43, 0x1}, 0xc, 0x0)`,
		},
		{
			input: `test$auto0(AUTO, &AUTO={AUTO, AUTO, AUTO}, AUTO, 0x0)`,
			err:   `wrong type *prog.IntType for AUTO`,
		},
		{
			input:  `test$str0(&AUTO="303100090a0d7022273a")`,
			output: `test$str0(&(0x7f0000000040)='01\x00\t\n\rp\"\':')`,
		},
		{
			input:  `test$blob0(&AUTO="303100090a0d7022273a")`,
			output: `test$blob0(&(0x7f0000000040)='01\x00\t\n\rp\"\':')`,
		},
		{
			input:  `test$blob0(&AUTO="3031000a0d7022273a01")`,
			output: `test$blob0(&(0x7f0000000040)="3031000a0d7022273a01")`,
		},
		{
			input:     `test$out_const(&(0x7f0000000000)=0x2)`,
			output:    `test$out_const(&(0x7f0000000000))`,
			strictErr: `out arg const[1, const] has non-default value: 2`,
		},
		{
			input:  `test$str1(&(0x7f0000000000)='foo\x00')`,
			output: `test$str1(&(0x7f0000000000)='foo\x00')`,
		},
		{
			input:     `test$str1(&(0x7f0000000000)='bar\x00')`,
			output:    `test$str1(&(0x7f0000000000)='foo\x00')`,
			strictErr: `bad string value "bar\x00", expect ["foo\x00"]`,
		},
		{
			input:  `test$str2(&(0x7f0000000000)='bar\x00')`,
			output: `test$str2(&(0x7f0000000000)='bar\x00')`,
		},
		{
			input:     `test$str2(&(0x7f0000000000)='baz\x00')`,
			output:    `test$str2(&(0x7f0000000000)='foo\x00')`,
			strictErr: `bad string value "baz\x00", expect ["foo\x00" "bar\x00"]`,
		},
	}
	buf := make([]byte, ExecBufferSize)
	for _, test := range tests {
		if test.strictErr == "" {
			test.strictErr = test.err
		}
		if test.err != "" && test.output != "" {
			t.Errorf("both err and output are set")
			continue
		}
		for _, mode := range []DeserializeMode{NonStrict, Strict} {
			p, err := target.Deserialize([]byte(test.input), mode)
			wantErr := test.err
			if mode == Strict {
				wantErr = test.strictErr
			}
			if err != nil {
				if wantErr == "" {
					t.Errorf("deserialization failed with\n%s\ndata:\n%s\n",
						err, test.input)
					continue
				}
				if !strings.Contains(err.Error(), wantErr) {
					t.Errorf("deserialization failed with\n%s\nwhich doesn't match\n%s\ndata:\n%s",
						err, wantErr, test.input)
					continue
				}
			} else {
				if wantErr != "" {
					t.Errorf("deserialization should have failed with:\n%s\ndata:\n%s\n",
						wantErr, test.input)
					continue
				}
				output := strings.TrimSpace(string(p.Serialize()))
				if test.output != "" && test.output != output {
					t.Errorf("wrong serialized data:\n%s\nexpect:\n%s\n",
						output, test.output)
					continue
				}
				p.SerializeForExec(buf)
			}
		}
	}
}

func TestSerializeDeserialize(t *testing.T) {
	target := initTargetTest(t, "test", "64")
	tests := [][2]string{
		{
			`serialize0(&(0x7f0000408000)={"6861736800000000000000000000", "48490000"})`,
			`serialize0(&(0x7f0000408000)={'hash\x00', 'HI\x00'})`,
		},
		{
			`serialize1(&(0x7f0000000000)="0000000000000000", 0x8)`,
			`serialize1(&(0x7f0000000000)=""/8, 0x8)`,
		},
	}
	for _, test := range tests {
		p, err := target.Deserialize([]byte(test[0]), Strict)
		if err != nil {
			t.Fatal(err)
		}
		data := p.Serialize()
		test[1] += "\n"
		if string(data) != test[1] {
			t.Fatalf("\ngot : %s\nwant: %s", data, test[1])
		}
	}
}

func TestSerializeDeserializeRandom(t *testing.T) {
	testEachTargetRandom(t, func(t *testing.T, target *Target, rs rand.Source, iters int) {
		data0 := make([]byte, ExecBufferSize)
		data1 := make([]byte, ExecBufferSize)
		for i := 0; i < iters; i++ {
			p0 := target.Generate(rs, 10, nil)
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
			diff := cmp.Diff(decoded0, decoded1)
			t.Logf("decoded diff: %v", diff)
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
