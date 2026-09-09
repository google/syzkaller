// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"fmt"
	"strings"
)

// TruncateText truncates text to maxLines, appending a notice with the total line count if truncated.
func TruncateText(text string, maxLines int) string {
	pos := 0
	for range maxLines {
		idx := strings.IndexByte(text[pos:], '\n')
		if idx < 0 {
			return text
		}
		pos += idx + 1
	}
	if pos >= len(text) {
		return text
	}
	total := maxLines + strings.Count(text[pos:], "\n")
	if !strings.HasSuffix(text, "\n") {
		total++
	}
	return fmt.Sprintf("%s\n[Output truncated: showing %d of %d lines]",
		strings.TrimRight(text[:pos], "\n"), maxLines, total)
}
