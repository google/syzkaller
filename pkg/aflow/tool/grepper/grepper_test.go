// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package grepper

import (
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/stretchr/testify/assert"
)

func TestGrepper(t *testing.T) {
	repo := vcs.MakeTestRepo(t, t.TempDir())
	repo.CommitChangeset("description",
		vcs.FileContent{
			File: "foo.c",
			Content: `
int some_func(void)
{
	line;
	foobar;
	line;
}
			`,
		},
		vcs.FileContent{
			File: "bar.c",
			Content: `
int another_func(int) {
	foobar;
}
			`,
		},
		vcs.FileContent{
			File: "overflow.c",
			Content: strings.Repeat(`
int some_func(int) {
	barfoo;
}
			`, 1000),
		},
	)

	aflow.TestTool(t, Tool,
		state{KernelSrc: repo.Dir},
		args{Expression: "foobar"},
		results{Output: `bar.c=2=int another_func(int) {
bar.c:3:	foobar;
bar.c-4-}
--
foo.c=2=int some_func(void)
--
foo.c-4-	line;
foo.c:5:	foobar;
foo.c-6-	line;
`},
		"")

	aflow.TestTool(t, Tool,
		state{KernelSrc: repo.Dir},
		args{Expression: "barfoo"},
		func(got results) {
			assert.True(t, strings.Contains(got.Output,
				"Full output is too long, showing 500 out of 3999 lines."),
				"%v", got)
			assert.Equal(t, 505, strings.Count(got.Output, "\n"))
		},
		"")

	aflow.TestTool(t, Tool,
		state{KernelSrc: repo.Dir},
		args{Expression: "something that never appears"},
		results{},
		"no matches")

	aflow.TestTool(t, Tool,
		state{KernelSrc: repo.Dir},
		args{Expression: "bad expression ("},
		results{},
		`bad expression: fatal: command line, 'bad expression (': Unmatched ( or \(`)
	aflow.TestTool(t, Tool,
		state{KernelSrc: repo.Dir},
		args{Expression: "->root"},
		results{},
		"no matches")
	aflow.TestTool(t, Tool,
		state{KernelSrc: repo.Dir},
		args{Expression: `-\>root`},
		results{},
		"no matches")
}
