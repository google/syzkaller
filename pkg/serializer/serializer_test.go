// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package serializer

import (
	"bytes"
	"testing"
)

func TestSerializer(t *testing.T) {
	x := &X{
		Y: Y{1},
		P: &Y{2},
		A: []Y{{3}, {4}},
		F: true,
		S: "a\x09b",
		T: T1,
	}
	buf := new(bytes.Buffer)
	Write(buf, x)
	t.Logf("\n%s", buf.String())
	t.Logf("\n%#v", x)
}

type X struct {
	Y Y
	P *Y
	A []Y
	F bool
	S string
	T T
}

type Y struct {
	V int
}

type T int

const (
	_ T = iota
	T1
)
