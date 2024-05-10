// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package covermerger

import (
	"strings"

	dmp "github.com/sergi/go-diff/diffmatchpatch"
)

func makeLineToLineMatcher(textFrom, textTo string) *LineToLineMatcher {
	diffMatcher := dmp.New()
	diffs := diffMatcher.DiffMain(textFrom, textTo, false)
	curToLinePos := 0
	textDestPosToLine := map[int]int{}
	for iLine, line := range strings.Split(textTo, "\n") {
		textDestPosToLine[curToLinePos] = iLine
		curToLinePos += len(line) + len("\n")
	}

	toLines := strings.Split(textTo, "\n")
	curFromLinePos := 0
	lineToLine := []int{}
	for _, line := range strings.Split(textFrom, "\n") {
		toLinePos := diffMatcher.DiffXIndex(diffs, curFromLinePos)
		toLine := -1
		if bestMatchDestLine, ok := textDestPosToLine[toLinePos]; ok {
			if toLines[bestMatchDestLine] == line {
				toLine = bestMatchDestLine
			}
		}
		lineToLine = append(lineToLine, toLine)
		curFromLinePos += len(line) + len("\n")
	}
	return &LineToLineMatcher{
		lineToLine: lineToLine,
	}
}

type LineToLineMatcher struct {
	lineToLine []int
}

func (lm *LineToLineMatcher) SameLinePos(line int) int {
	return lm.lineToLine[line]
}
