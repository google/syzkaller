// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package tool

import (
	"flag"
	"fmt"
	"io/ioutil"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestParseFlags(t *testing.T) {
	type Values struct {
		Foo bool
		Bar int
		Baz string
	}
	type Test struct {
		args string
		vals *Values
	}
	tests := []Test{
		{"", &Values{false, 1, "baz"}},
		{"-foo -bar=2", &Values{true, 2, "baz"}},
		{"-foo -bar=2 -qux", nil},
		{"-foo -bar=2 " + OptionalFlags([]Flag{{"qux", ""}}), &Values{true, 2, "baz"}},
	}
	for i, test := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			vals := new(Values)
			flags := flag.NewFlagSet("", flag.ContinueOnError)
			flags.SetOutput(ioutil.Discard)
			flags.BoolVar(&vals.Foo, "foo", false, "")
			flags.IntVar(&vals.Bar, "bar", 1, "")
			flags.StringVar(&vals.Baz, "baz", "baz", "")
			args := append(strings.Split(test.args, " "), "arg0", "arg1")
			if args[0] == "" {
				args = args[1:]
			}
			err := ParseFlags(flags, args)
			if test.vals == nil {
				if err == nil {
					t.Fatalf("parsing did not fail")
				}
				return
			}
			if err != nil {
				t.Fatalf("parsing failed: %v", err)
			}
			if diff := cmp.Diff(test.vals, vals); diff != "" {
				t.Fatal(diff)
			}
			if flags.NArg() != 2 || flags.Arg(0) != "arg0" || flags.Arg(1) != "arg1" {
				t.Fatalf("bad args: %q", flags.Args())
			}
		})
	}
}

func TestCfgsFlagString(t *testing.T) {
	cfgs := &CfgsFlag{"a", "b", "c"}
	if got, want := cfgs.String(), "[a b c]"; got != want {
		t.Errorf("cfgs.String got: %s, want: %s", got, want)
	}
}

func TestCfgsFlagSet(t *testing.T) {
	cfgs := &CfgsFlag{}
	if err := cfgs.Set("a, b, c"); err != nil {
		t.Fatalf("cfgs.Set got: %v, want: nil", err)
	}
	if diff := cmp.Diff(*cfgs, CfgsFlag{"a", "b", "c"}); diff != "" {
		t.Errorf("*cfgs mismatch (-want +got):\n%s", diff)
	}
}

func TestCfgsFlagAlreadySet(t *testing.T) {
	cfgs := &CfgsFlag{"a", "b", "c"}
	if err := cfgs.Set("a, b, c"); err == nil {
		t.Errorf("cfgs.Set got: nil, want: error")
	}
}
