// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package executor

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func TestExecutorMistakes(t *testing.T) {
	checks := []*struct {
		pattern     string
		suppression string
		message     string
		tests       []string
		commonOnly  bool
	}{
		{
			pattern:    `\)\n\t*(debug|debug_dump_data)\(`,
			message:    "debug() calls are stripped from C reproducers, this code will break. Use {} around debug() to fix",
			commonOnly: true,
			tests: []string{
				`
if (foo)
	debug("foo failed");
`, `
	if (x + y)
		debug_dump_data(data, len);
`,
			},
		},
		{
			pattern:     `\) {\n[^\n}]+?\n\t*}\n`,
			suppression: "debug|__except",
			message:     "Don't use single-line compound statements (remove {})",
			tests: []string{
				`
if (foo) {
	bar();
}
`, `
	while (x + y) {
		foo(a, y);
	}
`,
			},
		},
		{
			// These are also not properly stripped by pkg/csource.
			pattern: `/\*[^{]`,
			message: "Don't use /* */ block comments. Use // line comments instead",
			tests: []string{
				`/* C++ comment */`,
			},
		},
		{
			pattern: `#define __NR_`,
			message: "Don't define syscall __NR_foo constants.\n" +
				"These should be guarded by #ifndef __NR_foo, but this is dependent on the host " +
				"and may break on other machines (after pkg/csource processing).\n" +
				"Define sys_foo constants instead.",
			commonOnly: true,
			tests: []string{
				`
#ifndef __NR_io_uring_setup
#ifdef __alpha__
#define __NR_io_uring_setup 535
#else // !__alpha__
#define __NR_io_uring_setup 425
#endif
#endif // __NR_io_uring_setup
`,
			},
		},
		{
			pattern:     `//[^\s]`,
			suppression: `https?://|//%`,
			message:     "Add a space after //",
			tests: []string{
				`//foo`,
			},
		},
		{
			// This detects C89-style variable declarations in the beginning of block in a best-effort manner.
			// Struct fields look exactly as C89 variable declarations, to filter them out we look for "{"
			// at the beginning of the line.
			pattern: `
{[^{]*
\s+((unsigned )?[a-zA-Z][a-zA-Z0-9_]+\s*\*?|(struct )?[a-zA-Z][a-zA-Z0-9_]+\*)\s+([a-zA-Z][a-zA-Z0-9_]*(,\s*)?)+;
`,
			suppression: `return |goto |va_list |pthread_|zx_`,
			message:     "Don't use C89 var declarations. Declare vars where they are needed and combine with initialization",
			tests: []string{
				`
{
	int i;
`,
				`
{
	socklen_t optlen;
`,
				`
{
	int fd, rv;
`,
				`
{
	int fd, rv;
`,
				`
{
	struct nlattr* attr;
`,
				`
{
	int* i;
`,
				`
{
	DIR* dp;
`,
			},
		},
		{
			pattern: `(fail|exitf)\(".*\\n`,
			message: "Don't use \\n in fail/exitf messages",
			tests: []string{
				`fail("some message with new line\n");`,
			},
		},
		{
			pattern: `fail(msg)?\("[^"]*%`,
			message: "DON'T",
			tests: []string{
				`fail("format %s string")`,
				`failmsg("format %s string", "format")`,
			},
		},
		{
			pattern: `ifn?def\s+SYZ_`,
			message: "SYZ_* are always defined, use #if instead of #ifdef",
			tests: []string{
				`#ifndef SYZ_EXECUTOR_USES_FORK_SERVER`,
				`#ifdef SYZ_EXECUTOR_USES_FORK_SERVER`,
			},
		},
	}
	for _, check := range checks {
		re := regexp.MustCompile(check.pattern)
		for _, test := range check.tests {
			if !re.MatchString(test) {
				t.Fatalf("patter %q does not match test %q", check.pattern, test)
			}
		}
	}
	for _, file := range executorFiles(t) {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, check := range checks {
			if check.commonOnly && !strings.Contains(file, "common") {
				continue
			}
			re := regexp.MustCompile(check.pattern)
			supp := regexp.MustCompile(check.suppression)
			for _, match := range re.FindAllIndex(data, -1) {
				end := match[1] - 1
				for end != len(data) && data[end] != '\n' {
					end++
				}
				// Match suppressions against all lines of the match.
				start := match[0] - 1
				for start != 0 && data[start-1] != '\n' {
					start--
				}
				if check.suppression != "" && supp.Match(data[start:end]) {
					continue
				}
				// Locate the last line of the match, that's where we assume the error is.
				start = end - 1
				for start != 0 && data[start-1] != '\n' {
					start--
				}

				line := bytes.Count(data[:start], []byte{'\n'}) + 1
				t.Errorf("\nexecutor/%v:%v: %v\n%s\n", file, line, check.message, data[start:end])
			}
		}
	}
}

func executorFiles(t *testing.T) []string {
	cc, err := filepath.Glob("*.cc")
	if err != nil {
		t.Fatal(err)
	}
	h, err := filepath.Glob("*.h")
	if err != nil {
		t.Fatal(err)
	}
	if len(cc) == 0 || len(h) == 0 {
		t.Fatal("found no executor files")
	}
	res := append(cc, h...)
	sort.Strings(res)
	return res
}
