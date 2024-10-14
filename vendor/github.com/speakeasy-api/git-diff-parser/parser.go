package git_diff_parser

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var ErrUnhandled = errors.New("unhandled git diff syntax")

type ContentChangeType string

const (
	ContentChangeTypeAdd    ContentChangeType = "add"
	ContentChangeTypeDelete ContentChangeType = "delete"
	ContentChangeTypeModify ContentChangeType = "modify"
	ContentChangeTypeNOOP   ContentChangeType = ""
)

// ContentChange is a part of the line that starts with ` `, `-`, `+`
// Consecutive ContentChange build a line.
// A `~` is a special case of ContentChange that is used to indicate a new line.
type ContentChange struct {
	Type ContentChangeType `json:"type"`
	From string            `json:"from"`
	To   string            `json:"to"`
}

type ChangeList []ContentChange

// Hunk is a line that starts with @@.
// Each hunk shows one area where the files differ
// Unified format hunks look like this:
// @@ from-file-line-numbers to-file-line-numbers @@
//
//	line-from-either-file
//	line-from-either-file…
//
// If a hunk contains just one line, only its start line number appears. Otherwise its line numbers look like ‘start,count’. An empty hunk is considered to start at the line that follows the hunk.
type Hunk struct {
	ChangeList         ChangeList `json:"change_list"`
	StartLineNumberOld int        `json:"start_line_number_old"`
	CountOld           int        `json:"count_old"`
	StartLineNumberNew int        `json:"start_line_number_new"`
	CountNew           int        `json:"count_new"`
}

func (changes *ChangeList) IsSignificant() bool {
	for _, change := range *changes {
		if change.Type != ContentChangeTypeNOOP {
			return true
		}
	}
	return false
}

func NewHunk(line string) (Hunk, error) {
	namedHunkRegex := regexp.MustCompile(`(?m)^@@ -(?P<start_old>\d+),?(?P<count_old>\d+)? \+(?P<start_new>\d+),?(?P<count_new>\d+)? @@`)
	match := namedHunkRegex.FindStringSubmatch(line)
	result := make(map[string]string)
	for i, name := range namedHunkRegex.SubexpNames() {
		if i != 0 && name != "" {
			result[name] = match[i]
		}
	}
	startLineNumberOld, err := strconv.Atoi(result["start_old"])
	if err != nil {
		return Hunk{}, fmt.Errorf("failed to parse start line number old: %w", err)
	}
	countOld, err := strconv.Atoi(result["count_old"])
	if err != nil {
		countOld = 1
	}
	startLineNumberNew, err := strconv.Atoi(result["start_new"])
	if err != nil {
		return Hunk{}, fmt.Errorf("failed to parse start line number new: %w", err)
	}
	countNew, err := strconv.Atoi(result["count_new"])
	if err != nil {
		countNew = 1
	}
	return Hunk{
		StartLineNumberOld: startLineNumberOld,
		CountOld:           countOld,
		StartLineNumberNew: startLineNumberNew,
		CountNew:           countNew,
	}, nil
}

type FileDiffType string

const (
	FileDiffTypeAdded    FileDiffType = "add"
	FileDiffTypeDeleted  FileDiffType = "delete"
	FileDiffTypeModified FileDiffType = "modify"
)

type BinaryDeltaType string

const (
	BinaryDeltaTypeLiteral BinaryDeltaType = "literal"
	BinaryDeltaTypeDelta   BinaryDeltaType = "delta"
)

type BinaryPatch struct {
	Type    BinaryDeltaType `json:"type"`
	Count   int
	Content string
}

// FileDiff Source of truth: https://github.com/git/git/blob/master/diffcore.h#L106
// Implemented in https://github.com/git/git/blob/master/diff.c#L3496
type FileDiff struct {
	FromFile    string        `json:"from_file"`
	ToFile      string        `json:"to_file"`
	Type        FileDiffType  `json:"type"`
	IsBinary    bool          `json:"is_binary"`
	NewMode     string        `json:"new_mode"`
	Hunks       []Hunk        `json:"hunks"`
	BinaryPatch []BinaryPatch `json:"binary_patch"`
}

type Diff struct {
	FileDiff []FileDiff `json:"file_diff"`
}

type ParserMode int

const (
	modeHeader ParserMode = iota
	modeHunk
	modeBinary
)

type parser struct {
	diff Diff
	err  []error
	mode ParserMode
}

func (p *parser) VisitLine(diff string) {
	if p.tryVisitHeader(diff) {
		return
	}
	if p.tryVisitBinary(diff) {
		return
	}
	if p.tryVisitHunkHeader(diff) {
		return
	}
	fileHEAD := len(p.diff.FileDiff) - 1
	hunkHEAD := len(p.diff.FileDiff[fileHEAD].Hunks) - 1
	if hunkHEAD < 0 {
		p.err = append(p.err, fmt.Errorf("%w: %s", ErrUnhandled, diff))
		return
	}
	changeHead := len(p.diff.FileDiff[fileHEAD].Hunks[hunkHEAD].ChangeList) - 1
	// swallow extra, unused lines from start
	if strings.HasPrefix(diff, "~") &&
		!p.diff.FileDiff[fileHEAD].Hunks[hunkHEAD].ChangeList.IsSignificant() {
		p.diff.FileDiff[fileHEAD].Hunks[hunkHEAD].StartLineNumberOld += 1
		p.diff.FileDiff[fileHEAD].Hunks[hunkHEAD].StartLineNumberNew += 1
		p.diff.FileDiff[fileHEAD].Hunks[hunkHEAD].CountOld -= 1
		p.diff.FileDiff[fileHEAD].Hunks[hunkHEAD].CountNew -= 1
		p.diff.FileDiff[fileHEAD].Hunks[hunkHEAD].ChangeList = []ContentChange{}
	}
	if strings.HasPrefix(diff, "+") {
		if changeHead > 0 && p.diff.FileDiff[fileHEAD].Hunks[hunkHEAD].ChangeList[changeHead].Type == ContentChangeTypeDelete {
			p.diff.FileDiff[fileHEAD].Hunks[hunkHEAD].ChangeList[changeHead].Type = ContentChangeTypeModify
			p.diff.FileDiff[fileHEAD].Hunks[hunkHEAD].ChangeList[changeHead].To = strings.TrimPrefix(diff, "+")
			return
		}
		p.diff.FileDiff[fileHEAD].Hunks[hunkHEAD].ChangeList = append(p.diff.FileDiff[fileHEAD].Hunks[hunkHEAD].ChangeList, ContentChange{
			Type: ContentChangeTypeAdd,
			From: "",
			To:   strings.TrimPrefix(diff, "+"),
		})
		return
	}
	if strings.HasPrefix(diff, "-") {
		p.diff.FileDiff[fileHEAD].Hunks[hunkHEAD].ChangeList = append(p.diff.FileDiff[fileHEAD].Hunks[hunkHEAD].ChangeList, ContentChange{
			Type: ContentChangeTypeDelete,
			From: strings.TrimPrefix(diff, "-"),
			To:   "",
		})
		return
	}
	if diff == "~" {
		p.diff.FileDiff[fileHEAD].Hunks[hunkHEAD].ChangeList = append(p.diff.FileDiff[fileHEAD].Hunks[hunkHEAD].ChangeList, ContentChange{
			Type: ContentChangeTypeNOOP,
			From: "\n",
			To:   "\n",
		})
	}
	p.diff.FileDiff[fileHEAD].Hunks[hunkHEAD].ChangeList = append(p.diff.FileDiff[fileHEAD].Hunks[hunkHEAD].ChangeList, ContentChange{
		Type: ContentChangeTypeNOOP,
		From: diff,
		To:   diff,
	})
}

func (p *parser) tryVisitHeader(diff string) bool {
	// format: "diff --git a/README.md b/README.md"
	if strings.HasPrefix(diff, "diff ") {
		strings.Split(diff, " ")
		p.diff.FileDiff = append(p.diff.FileDiff, p.parseDiffLine(diff))
		p.mode = modeHeader
		return true
	}
	fileHEAD := len(p.diff.FileDiff) - 1
	if len(diff) == 0 && p.mode == modeHeader {
		return true
	}
	if fileHEAD < 0 {
		p.err = append(p.err, fmt.Errorf("%w: %s", ErrUnhandled, diff))
		return true
	}
	if p.mode != modeHeader {
		return false
	}
	if strings.HasPrefix(diff, "+++ ") || strings.HasPrefix(diff, "--- ") {
		// ignore -- we're still in the FileDiff and we've already captured the file names
		return true
	}
	if strings.HasPrefix(diff, "index ") {
		return true
	}
	if done := p.visitFileModeHeader(diff, fileHEAD); done {
		return done
	}

	if strings.HasPrefix(diff, "rename from ") || strings.HasPrefix(diff, "rename to ") {
		p.diff.FileDiff[fileHEAD].Type = FileDiffTypeModified
		return true
	}

	if strings.HasPrefix(diff, "GIT binary patch") {
		p.diff.FileDiff[fileHEAD].Type = FileDiffTypeModified
		p.diff.FileDiff[fileHEAD].IsBinary = true
		p.mode = modeBinary
		return true
	}

	// binary files ... differ
	if strings.HasPrefix(strings.ToLower(diff), "binary files ") {
		return true
	}

	if strings.HasPrefix(diff, "similarity") {
		return true
	}
	// continue to parse if fileHEAD > 0
	return fileHEAD < 0
}

func (p *parser) visitFileModeHeader(diff string, fileHEAD int) bool {
	if strings.HasPrefix(diff, "new file mode ") {
		p.diff.FileDiff[fileHEAD].Type = FileDiffTypeModified
		p.diff.FileDiff[fileHEAD].NewMode = strings.TrimPrefix(diff, "new file mode ")
		return true
	}
	if strings.HasPrefix(diff, "new mode ") {
		p.diff.FileDiff[fileHEAD].Type = FileDiffTypeModified
		p.diff.FileDiff[fileHEAD].NewMode = strings.TrimPrefix(diff, "new mode ")
		return true
	}

	if strings.HasPrefix(diff, "deleted file mode ") {
		p.diff.FileDiff[fileHEAD].Type = FileDiffTypeDeleted
		return true
	}
	if strings.HasPrefix(diff, "old mode ") {
		p.diff.FileDiff[fileHEAD].Type = FileDiffTypeModified
		return true
	}
	return false
}

func (p *parser) tryVisitBinary(diff string) bool {
	if p.mode != modeBinary {
		return false
	}
	fileHEAD := len(p.diff.FileDiff) - 1
	if fileHEAD < 0 {
		return true
	}
	if strings.HasPrefix(diff, "delta ") {
		p.diff.FileDiff[fileHEAD].Type = FileDiffTypeModified
		startByteCount, err := strconv.Atoi(strings.Split(diff, " ")[1])
		if err != nil {
			return true
		}

		p.diff.FileDiff[fileHEAD].BinaryPatch = append(p.diff.FileDiff[fileHEAD].BinaryPatch, BinaryPatch{
			Type:    BinaryDeltaTypeDelta,
			Count:   startByteCount,
			Content: "",
		})
		return true
	}
	if strings.HasPrefix(diff, "literal ") {
		p.diff.FileDiff[fileHEAD].Type = FileDiffTypeModified
		startByteCount, err := strconv.Atoi(strings.Split(diff, " ")[1])
		if err != nil {
			return true
		}
		p.diff.FileDiff[fileHEAD].BinaryPatch = append(p.diff.FileDiff[fileHEAD].BinaryPatch, BinaryPatch{
			Type:    BinaryDeltaTypeLiteral,
			Count:   startByteCount,
			Content: "",
		})
		return true
	}

	if len(p.diff.FileDiff[fileHEAD].BinaryPatch) > 0 {
		p.diff.FileDiff[fileHEAD].BinaryPatch[len(p.diff.FileDiff[fileHEAD].BinaryPatch)-1].Content += diff
		return true
	}
	return true
}

func (p *parser) tryVisitHunkHeader(diff string) bool {
	fileHEAD := len(p.diff.FileDiff) - 1
	if fileHEAD < 0 {
		return false
	}
	if strings.HasPrefix(diff, "@@") {
		hunk, err := NewHunk(diff)
		if err != nil {
			p.err = append(p.err, err)
		}
		p.diff.FileDiff[fileHEAD].Hunks = append(p.diff.FileDiff[fileHEAD].Hunks, hunk)
		p.mode = modeHunk
		return true
	}
	return false
}

func (p *parser) parseDiffLine(line string) FileDiff {
	filesStr := line[11:]
	var oldPath, newPath string

	quoteIndex := strings.Index(filesStr, "\"")
	switch quoteIndex {
	case -1:
		segs := strings.Split(filesStr, " ")
		oldPath = segs[0][2:]
		newPath = segs[1][2:]

	case 0:
		const indexDelta = 2
		nextQuoteIndex := strings.Index(filesStr[indexDelta:], "\"") + indexDelta
		oldPath = filesStr[3:nextQuoteIndex]
		newQuoteIndex := strings.Index(filesStr[nextQuoteIndex+1:], "\"") + nextQuoteIndex + 1
		if newQuoteIndex < 0 {
			newPath = filesStr[nextQuoteIndex+4:]
		} else {
			newPath = filesStr[newQuoteIndex+3 : len(filesStr)-1]
		}

	default:
		segs := strings.Split(filesStr, " ")
		oldPath = segs[0][2:]
		newPath = segs[1][3 : len(segs[1])-1]
	}

	return FileDiff{
		FromFile: oldPath,
		ToFile:   newPath,
	}
}

// Converts git diff --word-diff=porcelain output to a Diff object.
func Parse(diff string) (Diff, []error) {
	p := parser{}
	lines := strings.Split(diff, "\n")
	for i := 0; i < len(lines); i++ {
		p.VisitLine(lines[i])
	}
	return p.diff, p.err
}

// SignificantChange Allows a structured diff to be passed into the `isSignificant` function to determine significance. That function can return a message, which is optionally passed as the final argument
// Returns the first significant change found, or false if non found.
func SignificantChange(diff string, isSignificant func(*FileDiff, *ContentChange) (bool, string)) (bool, string, error) {
	parsed, err := Parse(diff)
	if len(err) > 0 {
		return true, "", fmt.Errorf("failed to parse diff: %w", err[0])
	}
	for _, fileDiff := range parsed.FileDiff {
		if significant, msg := isSignificant(&fileDiff, &ContentChange{}); significant {
			return true, msg, nil
		}

		for _, hunk := range fileDiff.Hunks {
			for _, change := range hunk.ChangeList {
				if significant, msg := isSignificant(&fileDiff, &change); significant {
					return true, msg, nil
				}
			}
		}
	}

	return false, "", nil
}
