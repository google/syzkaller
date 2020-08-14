// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package executor

import (
	"bytes"
	"io/ioutil"
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
			// These are also not properly stripped by pkg/csource.
			pattern: `/\*[^{]`,
			message: "Don't use /* */ block comments. Use // line comments instead",
			tests: []string{
				`/* C++ comment */`,
			},
		},
		{
			pattern:     `//[^\s]`,
			suppression: `https?://`,
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
		data, err := ioutil.ReadFile(file)
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
				// Locate the last line of the match, that's where we assume the error is.
				end := match[1] - 1
				for end != len(data) && data[end] != '\n' {
					end++
				}
				start := end - 1
				for start != 0 && data[start-1] != '\n' {
					start--
				}
				if check.suppression != "" && supp.Match(data[start:end]) {
					continue
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
