// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Some of these error messages and grep responses are linux-specific.
//go:build linux

package grepper

import (
	"fmt"
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
			File: "longline.c",
			Content: `
int long_func(void)
{
	` + strings.Repeat("a", 300) + `;
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
		args{Expression: "aaaaa"},
		func(got results) {
			expectedLine := "longline.c:4:	" + strings.Repeat("a", 186) + "..."
			assert.True(t, strings.Contains(got.Output, expectedLine),
				"output does not contain expected truncated line: %q", got.Output)
		},
		"")

	aflow.TestTool(t, Tool,
		state{KernelSrc: repo.Dir},
		args{Expression: "barfoo"},
		func(got results) {
			assert.True(t, strings.Contains(got.Output,
				"Full output is too long, showing 200 out of 3999 lines."),
				"%v", got)
			assert.True(t, strings.Contains(got.Output, `
Number of matching lines per file (1 files in total):
overflow.c:1000
`), "%v", got)
			assert.Equal(t, 208, strings.Count(got.Output, "\n"))
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
		`bad expression: fatal: -e option, 'bad expression (': Unmatched ( or \(`)

	aflow.TestTool(t, Tool,
		state{KernelSrc: repo.Dir},
		args{Expression: "foobar", PathPrefixes: []string{"", "foo.c"}},
		results{Output: `foo.c=2=int some_func(void)
--
foo.c-4-	line;
foo.c:5:	foobar;
foo.c-6-	line;
`},
		"")

	aflow.TestTool(t, Tool,
		state{KernelSrc: repo.Dir},
		args{Expression: "foobar", PathPrefixes: []string{""}},
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
		args{Expression: "foobar|aaaaa", PathPrefixes: []string{"bar.c", "foo.c"}},
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
		args{Expression: "->root"},
		results{},
		"no matches")
	aflow.TestTool(t, Tool,
		state{KernelSrc: repo.Dir},
		args{Expression: `-\>root`},
		results{},
		"no matches")
}

func TestGrepperManyFiles(t *testing.T) {
	repo := vcs.MakeTestRepo(t, t.TempDir())
	var files []vcs.FileContent
	for i := range 150 {
		files = append(files, vcs.FileContent{
			File:    fmt.Sprintf("file%03d.c", i),
			Content: strings.Repeat("match;\n\n\n", 5),
		})
	}
	repo.CommitChangeset("description", files...)

	aflow.TestTool(t, Tool,
		state{KernelSrc: repo.Dir},
		args{Expression: "match"},
		func(got results) {
			assert.True(t, strings.Contains(got.Output, `
Number of matching lines per file (150 files in total):
file000.c:5
file001.c:5
`), "%v", got)
			assert.True(t, strings.Contains(got.Output, `
file049.c:5
... and 100 more files
`), "%v", got)
			assert.False(t, strings.Contains(got.Output, "file050.c:5"), "%v", got)
		},
		"")
}
