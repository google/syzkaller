// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package email

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"
)

func ParsePatch(message []byte) (diff string) {
	s := bufio.NewScanner(bytes.NewReader(message))
	diffStarted := false
	for s.Scan() {
		ln := s.Text()
		if lineMatchesDiffStart(ln) {
			diffStarted = true
			diff += ln + "\n"
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
	}
	if err := s.Err(); err != nil {
		panic("error while scanning from memory: " + err.Error())
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
