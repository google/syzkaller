// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package html

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testRepo   = "https://github.com/google/syzkaller"
	testCommit = "111222"
)

func TestLinkifyHTMLFile(t *testing.T) {
	testGoldenFile(t, "crash_report.txt", "crash_report.html", func(input string) (string, error) {
		res, err := LinkifyHTML(input, testRepo, testCommit)
		return string(res), err
	})
}

// nolint: lll
func TestLinkifyHTMLCases(t *testing.T) {
	// Backticks can't be used in raw string literals, so we use single quotes instead.
	tests := []struct {
		name   string
		repo   string
		input  string
		output string
	}{
		{
			name:   "backticks",
			input:  `at 'fs/configfs/dir.c:734'.`,
			output: `at '<a href="https://github.com/google/syzkaller/blob/111222/fs/configfs/dir.c#L734">fs/configfs/dir.c:734</a>'.`,
		},
		{
			name:   "no line",
			input:  `in fs/ext4/mmp.c, and ('drivers/block/loop.c')`,
			output: `in <a href="https://github.com/google/syzkaller/blob/111222/fs/ext4/mmp.c#L0">fs/ext4/mmp.c</a>, and ('<a href="https://github.com/google/syzkaller/blob/111222/drivers/block/loop.c#L0">drivers/block/loop.c</a>')`,
		},
		{
			name:   "quotes",
			input:  `"fs/ext4/mmp.c" and **fs/ext4/mmp.c**`,
			output: `&#34;<a href="https://github.com/google/syzkaller/blob/111222/fs/ext4/mmp.c#L0">fs/ext4/mmp.c</a>&#34; and **<a href="https://github.com/google/syzkaller/blob/111222/fs/ext4/mmp.c#L0">fs/ext4/mmp.c</a>**`,
		},
		{
			name:   "longer extension",
			input:  `tools/foo.cc:10 and tools/foo.cpp`,
			output: `<a href="https://github.com/google/syzkaller/blob/111222/tools/foo.cc#L10">tools/foo.cc:10</a> and <a href="https://github.com/google/syzkaller/blob/111222/tools/foo.cpp#L0">tools/foo.cpp</a>`,
		},
		{
			name:   "line range",
			input:  `see fs/ext4/xattr.c:2978-3006.`,
			output: `see <a href="https://github.com/google/syzkaller/blob/111222/fs/ext4/xattr.c#L2978">fs/ext4/xattr.c:2978-3006</a>.`,
		},
		{
			name:   "large line number",
			input:  `fs/ext4/mmp.c:12345678901234567890 and fs/ext4/mmp.c:123456789`,
			output: `fs/ext4/mmp.c:12345678901234567890 and <a href="https://github.com/google/syzkaller/blob/111222/fs/ext4/mmp.c#L123456789">fs/ext4/mmp.c:123456789</a>`,
		},
		{
			name:   "no directory",
			input:  `in mmp.c:51 and mmp.c`,
			output: `in mmp.c:51 and mmp.c`,
		},
		{
			name:   "absolute path",
			input:  `/usr/src/linux/fs/ext4/mmp.c:51`,
			output: `/usr/src/linux/fs/ext4/mmp.c:51`,
		},
		{
			name:   "url",
			input:  `https://github.com/torvalds/linux/blob/master/fs/ext4/mmp.c`,
			output: `https://github.com/torvalds/linux/blob/master/fs/ext4/mmp.c`,
		},
		{
			name:   "unknown extension",
			input:  `fs/ext4/mmp.cfg and fs/ext4/mmp.c-foo`,
			output: `fs/ext4/mmp.cfg and fs/ext4/mmp.c-foo`,
		},
		{
			name:   "not a source file",
			input:  `/dev/loop2 and kworker/u8:1`,
			output: `/dev/loop2 and kworker/u8:1`,
		},
		{
			name:   "unknown repo",
			repo:   "repo1",
			input:  `at fs/dcache.c:2693 <b>`,
			output: `at fs/dcache.c:2693 &lt;b&gt;`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repo := test.repo
			if repo == "" {
				repo = testRepo
			}
			got, err := LinkifyHTML(strings.ReplaceAll(test.input, "'", "`"), repo, testCommit)
			require.NoError(t, err)
			assert.Equal(t, strings.ReplaceAll(test.output, "'", "`"), string(got))
		})
	}
}

func TestLinkifyMarkdownFile(t *testing.T) {
	testGoldenFile(t, "root_cause.md", "root_cause.linkified.md", func(input string) (string, error) {
		return LinkifyMarkdown(input, testRepo, testCommit)
	})
}

var flagUpdate = flag.Bool("update", false, "update test files accordingly to current results")

// testGoldenFile checks that fn produces the contents of testdata/goldenFile for testdata/inputFile.
func testGoldenFile(t *testing.T, inputFile, goldenFile string, fn func(string) (string, error)) {
	input, err := os.ReadFile(filepath.Join("testdata", inputFile))
	require.NoError(t, err)
	got, err := fn(string(input))
	require.NoError(t, err)
	goldenFile = filepath.Join("testdata", goldenFile)
	if *flagUpdate {
		require.NoError(t, os.WriteFile(goldenFile, []byte(got), 0644))
	}
	want, err := os.ReadFile(goldenFile)
	require.NoError(t, err)
	assert.Equal(t, string(want), got)
}

// nolint: lll
func TestLinkifyMarkdown(t *testing.T) {
	// Backticks can't be used in raw string literals, so we use single quotes instead.
	tests := []struct {
		name   string
		repo   string
		input  string
		output string
	}{
		{
			name: "text",
			input: `See fs/ext4/mmp.c:51 and **net/ipv4/tcp_input.c**.
- in (drivers/block/loop.c)`,
			output: `See [fs/ext4/mmp.c:51](https://github.com/google/syzkaller/blob/111222/fs/ext4/mmp.c#L51) and **[net/ipv4/tcp_input.c](https://github.com/google/syzkaller/blob/111222/net/ipv4/tcp_input.c#L0)**.
- in ([drivers/block/loop.c](https://github.com/google/syzkaller/blob/111222/drivers/block/loop.c#L0))`,
		},
		{
			name:   "code span",
			input:  `In 'fs/ext4/mmp.c:51', 'fs/ext4/inode.c' and 'foo() in fs/ext4/mmp.c'`,
			output: `In ['fs/ext4/mmp.c:51'](https://github.com/google/syzkaller/blob/111222/fs/ext4/mmp.c#L51), ['fs/ext4/inode.c'](https://github.com/google/syzkaller/blob/111222/fs/ext4/inode.c#L0) and 'foo() in fs/ext4/mmp.c'`,
		},
		{
			name:   "line range",
			input:  `In 'fs/ext4/xattr.c:2978-3006' and fs/ext4/xattr.c:10-20`,
			output: `In ['fs/ext4/xattr.c:2978-3006'](https://github.com/google/syzkaller/blob/111222/fs/ext4/xattr.c#L2978) and [fs/ext4/xattr.c:10-20](https://github.com/google/syzkaller/blob/111222/fs/ext4/xattr.c#L10)`,
		},
		{
			name:   "code span with line",
			input:  `In 'foo() at fs/ext4/mmp.c:51'`,
			output: `In 'foo() at fs/ext4/mmp.c:51'`,
		},
		{
			name:   "unbalanced backticks",
			input:  `'fs/a.c'fs/b.c:1'`,
			output: `['fs/a.c'](https://github.com/google/syzkaller/blob/111222/fs/a.c#L0)[fs/b.c:1](https://github.com/google/syzkaller/blob/111222/fs/b.c#L1)'`,
		},
		{
			name:   "between code spans",
			input:  `'foo'fs/a.c'bar'`,
			output: `'foo'[fs/a.c](https://github.com/google/syzkaller/blob/111222/fs/a.c#L0)'bar'`,
		},
		{
			name: "code block",
			input: `  '''c
kmmpd+0x2fc/0x938 fs/ext4/mmp.c:173
  '''
`,
			output: `  '''c
kmmpd+0x2fc/0x938 fs/ext4/mmp.c:173
  '''
`,
		},
		{
			name:   "existing links",
			input:  `[fs/ext4/mmp.c](https://example.com), ['fs/ext4/mmp.c'](https://example.com), [mmp](fs/ext4/mmp.c), https://example.com/fs/ext4/mmp.c`,
			output: `[fs/ext4/mmp.c](https://example.com), ['fs/ext4/mmp.c'](https://example.com), [mmp](fs/ext4/mmp.c), https://example.com/fs/ext4/mmp.c`,
		},
		{
			name:   "unknown repo",
			repo:   "repo1",
			input:  `See 'fs/ext4/mmp.c:51' and fs/ext4/mmp.c`,
			output: `See 'fs/ext4/mmp.c:51' and fs/ext4/mmp.c`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repo := test.repo
			if repo == "" {
				repo = testRepo
			}
			got, err := LinkifyMarkdown(strings.ReplaceAll(test.input, "'", "`"), repo, testCommit)
			require.NoError(t, err)
			assert.Equal(t, strings.ReplaceAll(test.output, "'", "`"), got)
		})
	}
}
