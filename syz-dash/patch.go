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
		if strings.HasPrefix(ln, "--- a/") {
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
			ln = ln[len("Subject: "):]
			if strings.Contains(strings.ToLower(ln), "[patch") {
				pos := strings.IndexByte(ln, ']')
				if pos == -1 {
					err = fmt.Errorf("subject line does not contain ']'")
					return
				}
				ln = ln[pos+1:]
			}
			title = ln
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
