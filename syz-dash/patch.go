// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package dash

import (
	"bufio"
	"fmt"
	"strings"
)

func parsePatch(text string) (title string, diff string, err error) {
	s := bufio.NewScanner(strings.NewReader(text))
	parsingDiff := false
	diffStarted := false
	lastLine := ""
	for s.Scan() {
		ln := s.Text()
		if strings.HasPrefix(ln, "--- a/") || strings.HasPrefix(ln, "--- /dev/null") {
			parsingDiff = true
			if title == "" {
				title = lastLine
			}
		}
		if parsingDiff {
			if ln == "--" || ln == "-- " {
				break
			}
			diff += ln + "\n"
			continue
		}
		if strings.HasPrefix(ln, "diff --git") {
			diffStarted = true
			continue
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
