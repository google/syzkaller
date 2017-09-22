// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
	"reflect"
	"regexp"
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

func TestCallSet(t *testing.T) {
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
	target, _, _ := initTest(t)
	tests := []struct {
		data string
		err  *regexp.Regexp
	}{
		{
			"syz_test$struct(&(0x7f0000000000)={0x0, {0x0}})",
			nil,
		},
		{
			"syz_test$struct(&(0x7f0000000000)=0x0)",
			regexp.MustCompile(`bad const type.*`),
		},
	}
	for _, test := range tests {
		_, err := target.Deserialize([]byte(test.data))
		if err != nil {
			if test.err == nil {
				t.Fatalf("deserialization failed with\n%s\ndata:\n%s\n", err, test.data)
			}
			if !test.err.MatchString(err.Error()) {
				t.Fatalf("deserialization failed with\n%s\nwhich doesn't match\n%s\ndata:\n%s\n", err, test.err, test.data)
			}
		} else if test.err != nil {
			t.Fatalf("deserialization should have failed with:\n%s\ndata:\n%s\n", test.err, test.data)
		}
	}
}
