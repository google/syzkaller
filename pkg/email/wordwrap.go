// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package email

import (
	"strings"
	"unicode"
)

// WordWrap reflows the given text so that no line exceeds the specified width.
// It returns the newly formatted string.
//
// It adheres to the following formatting rules:
//   - Preserves all existing newlines that designate new paragraphs or different block elements.
//   - Reflows and seamlessly merges lines of the same paragraph spanning multiple lines.
//   - Preserves the leading indentation of each line.
//   - When a line wraps, applies the same leading indentation to the newly wrapped lines.
//   - Prevents single words that exceed the maximum width from being split.
//   - Preserves original spacing separating words.
//   - Calculates line length visually (e.g. a '\t' character advances to the next 8-character stop).
func WordWrap(text string, width int) string {
	width = max(1, width)

	var result strings.Builder

	var lastIndent string
	lastEmpty := true
	lineLen := 0

	for i, line := range strings.Split(text, "\n") {
		trimmedLine := strings.TrimLeftFunc(line, unicode.IsSpace)
		indentStr := line[:len(line)-len(trimmedLine)]
		isEmpty := trimmedLine == ""
		isList := isListMarker(trimmedLine)

		// We merge this line with the previous one (effectively treating the newline as a space) if:
		// 1. We are not on the very first line.
		// 2. Neither the current nor previous line are completely blank (blank lines mean paragraph breaks).
		// 3. The indentation of this line exactly aligns with the previous line.
		// 4. This line doesn't definitively start a new block element (like a bulleted list).
		merge := i > 0 && !isEmpty && !lastEmpty && indentStr == lastIndent && !isList

		lastIndent = indentStr
		lastEmpty = isEmpty

		if merge {
			trimmedLine = " " + trimmedLine
		} else {
			if i > 0 {
				result.WriteByte('\n')
			}
			result.WriteString(indentStr)
			lineLen = visualLength(0, indentStr)
		}

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

func isListMarker(s string) bool {
	if strings.HasPrefix(s, "- ") || strings.HasPrefix(s, "* ") ||
		strings.HasPrefix(s, "+ ") || strings.HasPrefix(s, "> ") {
		return true
	}
	for i, r := range s {
		if r >= '0' && r <= '9' {
			continue
		}
		if r == '.' && i > 0 && len(s) > i+1 && s[i+1] == ' ' {
			return true
		}
		break
	}
	return false
}
