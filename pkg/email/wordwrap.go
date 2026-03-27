// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package email

import (
	"strings"
	"unicode"
)

// WordWrap wraps the given text so that no line exceeds the specified width.
// It returns the newly formatted string.
//
// It adheres to the following formatting rules:
//   - Preserves all existing newlines.
//   - Preserves the leading indentation of each line.
//   - When a line wraps, applies the same leading indentation to the newly wrapped lines.
//   - Prevents single words that exceed the maximum width from being split.
//   - Preserves original spacing separating words.
//   - Calculates line length visually (e.g. a '\t' character advances to the next 8-character stop).
func WordWrap(text string, width int) string {
	width = max(1, width)

	var result strings.Builder
	lineLen := 0

	for i, line := range strings.Split(text, "\n") {
		trimmedLine := strings.TrimLeftFunc(line, unicode.IsSpace)
		indentStr := line[:len(line)-len(trimmedLine)]
		isEmpty := trimmedLine == ""

		if i > 0 {
			result.WriteByte('\n')
		}
		result.WriteString(indentStr)
		lineLen = visualLength(0, indentStr)

		if isEmpty {
			continue
		}

		for trimmedLine != "" {
			// Find index of first non-space character.
			wordOffset := strings.IndexFunc(trimmedLine, func(r rune) bool {
				return !unicode.IsSpace(r)
			})

			if wordOffset == -1 {
				// Only trailing spaces left on this line.
				break
			}

			space := trimmedLine[:wordOffset]
			trimmedLine = trimmedLine[wordOffset:]

			// Find end of the current word.
			spaceOffset := strings.IndexFunc(trimmedLine, unicode.IsSpace)
			var word string
			if spaceOffset == -1 {
				word = trimmedLine
				trimmedLine = ""
			} else {
				word = trimmedLine[:spaceOffset]
				trimmedLine = trimmedLine[spaceOffset:]
			}

			if space == "" {
				// First word.
				result.WriteString(word)
				lineLen = visualLength(lineLen, word)
			} else {
				nextLen := visualLength(visualLength(lineLen, space), word)
				if nextLen > width {
					// Overflow occurred, wrap and drop the space.
					result.WriteByte('\n')
					result.WriteString(indentStr)
					result.WriteString(word)
					lineLen = visualLength(visualLength(0, indentStr), word)
				} else {
					result.WriteString(space)
					result.WriteString(word)
					lineLen = nextLen
				}
			}
		}
	}

	return result.String()
}

// visualLength calculates the visual horizontal column position after
// appending string s to an existing visual position p, correctly handling
// multi-byte runes and expanding tabs to the nearest 8-character stop.
func visualLength(p int, s string) int {
	for _, r := range s {
		if r == '\t' {
			p += 8 - (p % 8)
		} else {
			p++
		}
	}
	return p
}
