// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package email

import (
	"bufio"
	"fmt"
	"regexp"
	"strings"
)

func ParsePatch(text string) (title, diff string, err error) {
	s := bufio.NewScanner(strings.NewReader(text))
	lastLine := ""
	diffStarted := false
	for s.Scan() {
		ln := s.Text()
		if lineMatchesDiffStart(ln) {
			diffStarted = true
			diff += ln + "\n"
			if title == "" {
				title = lastLine
			}
			continue
		}
		if diffStarted {
			if ln == "" || ln == "--" || ln == "-- " || ln[0] == '>' {
				diffStarted = false
				continue
			}
			if strings.HasPrefix(ln, " ") || strings.HasPrefix(ln, "+") ||
				strings.HasPrefix(ln, "-") || strings.HasPrefix(ln, "@") ||
				strings.HasPrefix(ln, "================") {
				diff += ln + "\n"
				continue
			}
		}
		if strings.HasPrefix(ln, "Subject: ") {
			title = ln[len("Subject: "):]
			continue
		}
		if ln == "" || title != "" || diffStarted {
			continue
		}
		lastLine = ln
		if strings.HasPrefix(ln, "    ") {
			title = ln[4:]
		}
	}
	if err = s.Err(); err != nil {
		return
	}
	if strings.Contains(strings.ToLower(title), "[patch") {
		pos := strings.IndexByte(title, ']')
		if pos == -1 {
			err = fmt.Errorf("title contains '[patch' but not ']'")
			return
		}
		title = title[pos+1:]
	}
	title = strings.TrimSpace(title)
	if title == "" {
		err = fmt.Errorf("failed to extract title")
		return
	}
	if diff == "" {
		err = fmt.Errorf("failed to extract diff")
		return
	}
	return
}

func lineMatchesDiffStart(ln string) bool {
	diffRegexps := []*regexp.Regexp{
		regexp.MustCompile(`^(---|\+\+\+) [^\s]`),
		regexp.MustCompile(`^diff --git`),
		regexp.MustCompile(`^index [0-9a-f]+\.\.[0-9a-f]+`),
		regexp.MustCompile(`^new file mode [0-9]+`),
		regexp.MustCompile(`^Index: [^\s]`),
	}
	for _, re := range diffRegexps {
		if re.MatchString(ln) {
			return true
		}
	}
	return false
}
