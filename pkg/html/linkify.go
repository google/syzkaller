// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package html

import (
	"fmt"
	"html/template"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/syzkaller/pkg/vcs"
)

// LinkifyHTML HTML-escapes the plain text and turns references to source files
// (e.g. "fs/ext4/inode.c:2753" or "fs/ext4/inode.c") into links to the given kernel revision.
func LinkifyHTML(text, repo, commit string) (template.HTML, error) {
	refs, err := findSourceRefs(text, repo, commit)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	pos := 0
	for _, ref := range refs {
		b.WriteString(template.HTMLEscapeString(text[pos:ref.start]))
		fmt.Fprintf(&b, `<a href="%v">%v</a>`, template.HTMLEscapeString(ref.url),
			template.HTMLEscapeString(text[ref.start:ref.end]))
		pos = ref.end
	}
	b.WriteString(template.HTMLEscapeString(text[pos:]))
	return template.HTML(b.String()), nil
}

// LinkifyMarkdown turns references to source files in Markdown text (see LinkifyHTML)
// into Markdown links to the given kernel revision.
// It's a simple line-based heuristic that is good enough for AI-generated text:
// fenced code blocks are left intact (Markdown does not support links there), and code spans
// are linked only if they consist of just a reference (e.g. `fs/ext4/inode.c`).
func LinkifyMarkdown(md, repo, commit string) (string, error) {
	var b strings.Builder
	inCodeBlock := false
	for line := range strings.Lines(md) {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			inCodeBlock = !inCodeBlock
		}
		if inCodeBlock {
			b.WriteString(line)
			continue
		}
		pos := 0
		for _, span := range codeSpanRe.FindAllStringIndex(line, -1) {
			if err := linkifyMarkdownText(&b, line[pos:span[0]], repo, commit); err != nil {
				return "", err
			}
			code := line[span[0]:span[1]]
			url, err := codeSpanLink(code, repo, commit)
			if err != nil {
				return "", err
			}
			if url != "" && !strings.HasPrefix(line[span[1]:], "](") {
				code = "[" + code + "](" + url + ")"
			}
			b.WriteString(code)
			pos = span[1]
		}
		if err := linkifyMarkdownText(&b, line[pos:], repo, commit); err != nil {
			return "", err
		}
	}
	return b.String(), nil
}

// codeSpanRe matches Markdown code spans (only the common form with single backticks).
var codeSpanRe = regexp.MustCompile("`[^`]+`")

// linkifyMarkdownText writes Markdown text without code spans with source references turned into links.
func linkifyMarkdownText(b *strings.Builder, text, repo, commit string) error {
	refs, err := findSourceRefs(text, repo, commit)
	if err != nil {
		return err
	}
	pos := 0
	for _, ref := range refs {
		if strings.HasSuffix(text[:ref.start], "](") || strings.HasPrefix(text[ref.end:], "](") {
			continue // already a link
		}
		b.WriteString(text[pos:ref.start] + "[" + text[ref.start:ref.end] + "](" + ref.url + ")")
		pos = ref.end
	}
	b.WriteString(text[pos:])
	return nil
}

// codeSpanLink returns the link for the code span, if it consists of just a source reference.
func codeSpanLink(code, repo, commit string) (string, error) {
	content := code[1 : len(code)-1]
	refs, err := findSourceRefs(content, repo, commit)
	if err != nil || len(refs) != 1 || refs[0].start != 0 || refs[0].end != len(content) {
		return "", err
	}
	return refs[0].url, nil
}

type sourceRef struct {
	start int
	end   int
	url   string
}

// findSourceRefs returns the locations of the source file references in text
// (along with the links to them), for which a link to the given kernel revision can be generated.
func findSourceRefs(text, repo, commit string) ([]sourceRef, error) {
	if vcs.FileLink(repo, commit, "", 0) == "" {
		// Links can't be generated for this repo, no need to match anything.
		return nil, nil
	}
	var refs []sourceRef
	for _, m := range sourceRefRe.FindAllStringSubmatchIndex(text, -1) {
		start, end := m[0], m[1]
		if start > 0 && !strings.ContainsRune(sourceRefPrefixes, rune(text[start-1])) ||
			end < len(text) && !strings.ContainsRune(sourceRefSuffixes, rune(text[end])) {
			continue
		}
		file := text[m[2]:m[3]]
		line := 0
		if m[4] != -1 {
			var err error
			if line, err = strconv.Atoi(text[m[4]:m[5]]); err != nil {
				return nil, fmt.Errorf("failed to parse line number in %q: %w", text[start:end], err)
			}
		}
		url := vcs.FileLink(repo, commit, file, line)
		if url == "" {
			continue
		}
		refs = append(refs, sourceRef{start: start, end: end, url: url})
	}
	return refs, nil
}

// sourceRefRe matches file:line, file:line-line and file references in crash reports and in AI-generated text.
// Line ranges are linked to the first line of the range.
// To limit false positives, the file must have a known extension and at least one directory.
// The surrounding characters are checked separately (see sourceRefPrefixes/sourceRefSuffixes)
// to e.g. not match parts of URLs or absolute paths.
// Line numbers are limited to 9 digits, so that they always fit into int.
var sourceRefRe = regexp.MustCompile(`((?:[a-zA-Z0-9_.-]+/)+[a-zA-Z0-9_.-]+\.(?:cpp|cc|c|h|S|s|go|rs))\b` +
	`(?::([0-9]{1,9})(?:-[0-9]{1,9})?)?`)

const (
	// AI-generated text frequently puts references into backticks, braces, quotes or bold markers.
	sourceRefPrefixes = " \t\r\n([{`'\"*"
	// The references may also be followed by punctuation or a column number.
	sourceRefSuffixes = " \t\r\n)]}`'\"*,.:;!?"
)
