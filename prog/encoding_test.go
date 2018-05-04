// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"bytes"
	"fmt"
	"math/rand"
	"reflect"
	"regexp"
	"sort"
	"strings"
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
	for i := 0; i < 1e4; i++ {
		data := make([]byte, r.Intn(4))
		for i := range data {
			data[i] = byte(r.Intn(256))
		}
		buf := new(bytes.Buffer)
		serializeData(buf, data)
		p := newParser(buf.Bytes())
		if !p.Scan() {
			t.Fatalf("parser does not scan")
		}
		data1, err := deserializeData(p)
		if err != nil {
			t.Fatalf("failed to deserialize %q -> %s: %v", data, buf.Bytes(), err)
		}
		if !bytes.Equal(data, data1) {
			t.Fatalf("corrupted data %q -> %s -> %q", data, buf.Bytes(), data1)
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
		input  string
		output string
		err    *regexp.Regexp
	}{
		{
			input: `syz_test$struct(&(0x7f0000000000)={0x0, {0x0}})`,
		},
		{
			input:  `syz_test$struct(&(0x7f0000000000)=0x0)`,
			output: `syz_test$struct(&(0x7f0000000000))`,
		},
		{
			input: `syz_test$regression1(&(0x7f0000000000)=[{"000000"}, {"0000000000"}])`,
		},
		{
			input: `syz_test$regression2(&(0x7f0000000000)=[0x1, 0x2, 0x3, 0x4, 0x5, 0x6])`,
		},
		{
			input: `syz_test$excessive_args1(0x0, 0x1, {0x1, &(0x7f0000000000)=[0x1, 0x2]})`,
		},
		{
			input: `syz_test$excessive_args2(0x0, 0x1, {0x1, &(0x7f0000000000)={0x1, 0x2}})`,
		},
		{
			input: `syz_test$excessive_args2(0x0, 0x1, {0x1, &(0x7f0000000000)=nil})`,
		},
		{
			input: `syz_test$excessive_args2(0x0, &(0x7f0000000000), 0x0)`,
		},
		{
			input: `syz_test$excessive_fields1(&(0x7f0000000000)={0x1, &(0x7f0000000000)=[{0x0}, 0x2]}, {0x1, 0x2, [0x1, 0x2]})`,
		},
		{
			input:  `syz_test$excessive_fields1(0x0)`,
			output: `syz_test$excessive_fields1(&(0x7f0000000000))`,
		},
		{
			input:  `syz_test$excessive_fields1(r0)`,
			output: `syz_test$excessive_fields1(&(0x7f0000000000))`,
		},
		{
			input:  `syz_test$excessive_args2(r1)`,
			output: `syz_test$excessive_args2(0x0)`,
		},
		{
			input:  `syz_test$excessive_args2({0x0, 0x1})`,
			output: `syz_test$excessive_args2(0x0)`,
		},
		{
			input:  `syz_test$excessive_args2([0x0], 0x0)`,
			output: `syz_test$excessive_args2(0x0)`,
		},
		{
			input:  `syz_test$excessive_args2(@foo)`,
			output: `syz_test$excessive_args2(0x0)`,
		},
		{
			input:  `syz_test$excessive_args2('foo')`,
			output: `syz_test$excessive_args2(0x0)`,
		},
		{
			input:  `syz_test$excessive_args2(&(0x7f0000000000)={0x0, 0x1})`,
			output: `syz_test$excessive_args2(0x0)`,
		},
		{
			input:  `syz_test$excessive_args2(nil)`,
			output: `syz_test$excessive_args2(0x0)`,
		},
		{
			input:  `syz_test$type_confusion1(&(0x7f0000000000)=@unknown)`,
			output: `syz_test$type_confusion1(&(0x7f0000000000))`,
		},
		{
			input:  `syz_test$type_confusion1(&(0x7f0000000000)=@unknown={0x0, 'abc'}, 0x0)`,
			output: `syz_test$type_confusion1(&(0x7f0000000000))`,
		},
		{
			input:  `syz_test$excessive_fields1(&(0x7f0000000000)=0x0)`,
			output: `syz_test$excessive_fields1(&(0x7f0000000000))`,
		},
	}
	buf := make([]byte, ExecBufferSize)
	for _, test := range tests {
		p, err := target.Deserialize([]byte(test.input))
		if err != nil {
			if test.err == nil {
				t.Fatalf("deserialization failed with\n%s\ndata:\n%s\n", err, test.input)
			}
			if !test.err.MatchString(err.Error()) {
				t.Fatalf("deserialization failed with\n%s\nwhich doesn't match\n%s\ndata:\n%s",
					err, test.err, test.input)
			}
			if test.output != "" {
				t.Fatalf("both err and output are set")
			}
		} else {
			if test.err != nil {
				t.Fatalf("deserialization should have failed with:\n%s\ndata:\n%s\n",
					test.err, test.input)
			}
			output := strings.TrimSpace(string(p.Serialize()))
			if test.output != "" && test.output != output {
				t.Fatalf("wrong serialized data:\n%s\nexpect:\n%s\n",
					output, test.output)
			}
			p.SerializeForExec(buf)
		}
	}
}

func TestSerializeDeserialize(t *testing.T) {
	target := initTargetTest(t, "test", "64")
	tests := [][2]string{
		{
			`serialize0(&(0x7f0000408000)={"6861736800000000000000000000", "4849000000"})`,
			`serialize0(&(0x7f0000408000)={'hash\x00', 'HI\x00'})`,
		},
		{
			`serialize1(&(0x7f0000000000)="0000000000000000", 0x8)`,
			`serialize1(&(0x7f0000000000)=""/8, 0x8)`,
		},
	}
	for _, test := range tests {
		p, err := target.Deserialize([]byte(test[0]))
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
				t.Fatal("flaky?")
			}
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
	p1, err := p0.Target.Deserialize(serialized)
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
