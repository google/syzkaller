// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build gofuzz

package compiler

import (
	"github.com/google/syzkaller/pkg/ast"
)

func Fuzz(data []byte) int {
	eh := func(pos ast.Pos, msg string) {}
	desc := ast.Parse(data, "", eh)
	if desc == nil {
		return 0
	}
	prog := Compile(desc, fuzzConsts, eh)
	if prog == nil {
		return 0
	}
	return 1
}

var fuzzConsts = map[string]uint64{"A": 1, "B": 2, "C": 3, "SYS_C": 4}
