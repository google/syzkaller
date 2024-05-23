// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLastExecutingEmpty(t *testing.T) {
	last := MakeLastExecuting(10, 10)
	assert.Empty(t, last.Collect())
}

func TestLastExecuting(t *testing.T) {
	last := MakeLastExecuting(10, 3)
	last.Note(0, []byte("prog1"), 1)

	last.Note(1, []byte("prog2"), 2)
	last.Note(1, []byte("prog3"), 3)

	last.Note(3, []byte("prog4"), 4)
	last.Note(3, []byte("prog5"), 5)
	last.Note(3, []byte("prog6"), 6)

	last.Note(7, []byte("prog7"), 7)
	last.Note(7, []byte("prog8"), 8)
	last.Note(7, []byte("prog9"), 9)
	last.Note(7, []byte("prog10"), 10)
	last.Note(7, []byte("prog11"), 11)

	last.Note(9, []byte("prog12"), 12)

	last.Note(8, []byte("prog13"), 13)

	assert.Equal(t, last.Collect(), []ExecRecord{
		{Proc: 0, Prog: []byte("prog1"), Time: 12},

		{Proc: 1, Prog: []byte("prog2"), Time: 11},
		{Proc: 1, Prog: []byte("prog3"), Time: 10},

		{Proc: 3, Prog: []byte("prog4"), Time: 9},
		{Proc: 3, Prog: []byte("prog5"), Time: 8},
		{Proc: 3, Prog: []byte("prog6"), Time: 7},

		{Proc: 7, Prog: []byte("prog9"), Time: 4},
		{Proc: 7, Prog: []byte("prog10"), Time: 3},
		{Proc: 7, Prog: []byte("prog11"), Time: 2},

		{Proc: 9, Prog: []byte("prog12"), Time: 1},

		{Proc: 8, Prog: []byte("prog13"), Time: 0},
	})
}
