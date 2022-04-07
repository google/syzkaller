// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package serializer

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestSerializer(t *testing.T) {
	x := &X{
		Y: Y{1},
		P: &Y{2},
		A: []Y{{3}, {4}},
		B: true,
		S: "a\x09b",
		T: T1,
		I: []interface{}{
			nil,
			Y{V: 42},
			new(Y),
			(*Y)(nil),
			0,
			42,
			T(0),
			T(42),
			U(96),
			false,
			B(false),
			"",
			"foo",
			S(""),
			S("foo"),
		},
		F: nil,
	}
	want := `&X{Y{1},&Y{2},[]Y{
{3},
{4},
},true,"a\tb",1,[]{
nil,
Y{},
&Y{},
nil,
0,
42,
T(0),
T(42),
U(96),
false,
B(false),
"",
"foo",
S(""),
S("foo"),
},nil}`
	buf := new(bytes.Buffer)
	Write(buf, x)
	if diff := cmp.Diff(want, buf.String()); diff != "" {
		t.Fatal(diff)
	}
}

type X struct {
	Y Y
	P *Y
	A []Y
	B bool
	S string
	T T
	I []interface{}
	F func()
}

type Y struct {
	V int
}

type (
	S string
	B bool
	T int
	U uint16
)

const (
	_ T = iota
	T1
)
