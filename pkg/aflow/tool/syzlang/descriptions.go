// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzlang

import (
	"bufio"
	"fmt"
	"io"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/sys/targets"
)

func DescriptionFiles(osTarget string) []string {
	entries, err := sys.Files.ReadDir(osTarget)
	if err != nil {
		panic(err)
	}
	var files []string
	for _, ent := range entries {
		if ent.Name() == "auto.txt" || ent.Name() == "auto.txt.const" {
			continue
		}
		files = append(files, ent.Name())
	}
	slices.Sort(files)
	return files
}

// DescriptionFilesPrompt returns a formatted section for the prompt listing description files,
// excluding ".const" files, and appending a note about where constant values are defined.
func DescriptionFilesPrompt(osTarget string) string {
	files := DescriptionFiles(osTarget)
	var filtered []string
	for _, f := range files {
		if !strings.HasSuffix(f, ".const") {
			filtered = append(filtered, f)
		}
	}
	sb := new(strings.Builder)
	sb.WriteString("Available Syscall Description Files:\n")
	for _, f := range filtered {
		sb.WriteString(f)
		sb.WriteByte('\n')
	}
	sb.WriteString("\nNote that the constant values for the descriptions are defined " +
		"in the file suffixed with .const (e.g. sys.txt.const for sys.txt).\n")
	return sb.String()
}

var ReadDescription = aflow.NewFuncTool("read-description", readDescription, fmt.Sprintf(`
The tool reads the content of a syzlang description file (e.g. sys.txt, socket.txt, etc).
Description files contain syscall definitions and related types.

You can read a specific file sequentially by providing File and FirstLine (it will return a window of %d lines).
You can also grep across a specific File or all description files by providing a regular expression in Expression. 
If Expression is provided, FirstLine is ignored. The grep results will automatically
include up to %d surrounding context lines for each match to help you understand the definition.
You can read and grep both .txt and .const files.
`, paginateLinesWindow, grepContextLines))

const (
	maxGrepLines          = 500
	maxLineLen            = 500
	paginateLinesWindow   = 200
	maxOutputBytes        = 256 * 1024
	defaultScanBufferSize = 64 * 1024
	maxScanBufferSize     = 10 * 1024 * 1024
	grepContextLines      = 10
)

// nolint: lll
type readDescArgs struct {
	File       string `jsonschema:"the name of the syzlang description file to read, e.g. sys.txt or socket.txt. Can be empty if Expression is provided to search all files." json:",omitempty"`
	FirstLine  int    `jsonschema:"First source line to return, 1-based." json:",omitempty"`
	Expression string `jsonschema:"Regular expression to search in the description file(s)." json:",omitempty"`
}

type readDescResults struct {
	Output string `jsonschema:"Content of the description file."`
}

type readDescState struct {
	TargetOS string
}

func readDescription(ctx *aflow.Context, state readDescState, args readDescArgs) (readDescResults, error) {
	if args.Expression != "" && args.FirstLine != 0 {
		return readDescResults{}, aflow.BadCallError("Expression cannot be used together with FirstLine")
	}
	osTarget := strings.ToLower(state.TargetOS)
	if osTarget == "" {
		osTarget = targets.Linux
	}
	if _, err := sys.Files.ReadDir(osTarget); err != nil {
		return readDescResults{}, aflow.BadCallError("invalid OS %q: %v", osTarget, err)
	}
	if args.Expression != "" {
		return grepDescriptions(osTarget, args.Expression, args.File)
	}
	return paginateDescription(osTarget, args.File, args.FirstLine)
}

func validateFilePath(file string) error {
	if file != "" {
		cleaned := strings.TrimPrefix(file, "test/")
		if strings.Contains(cleaned, "/") || strings.Contains(cleaned, "\\") || strings.HasPrefix(cleaned, ".") {
			return aflow.BadCallError("invalid file path %q", file)
		}
		if cleaned == "auto.txt" || cleaned == "auto.txt.const" {
			return aflow.BadCallError("access to auto.txt or auto.txt.const is disallowed")
		}
	}
	return nil
}

func newScanner(f io.Reader) *bufio.Scanner {
	scanner := bufio.NewScanner(f)
	buf := make([]byte, 0, defaultScanBufferSize)
	scanner.Buffer(buf, maxScanBufferSize)
	return scanner
}

func grepDescriptions(osTarget, expression, file string) (readDescResults, error) {
	if err := validateFilePath(file); err != nil {
		return readDescResults{}, err
	}

	re, err := regexp.Compile(expression)
	if err != nil {
		return readDescResults{}, aflow.BadCallError("bad expression: %v", err)
	}
	var targetFiles []string
	if file != "" {
		targetFiles = []string{file}
	} else {
		targetFiles = DescriptionFiles(osTarget)
	}

	state := grepState{
		b:           new(strings.Builder),
		targetFiles: targetFiles,
	}

	for _, fname := range targetFiles {
		f, err := sys.Files.Open(path.Join(osTarget, fname))
		if err != nil {
			return readDescResults{}, aflow.BadCallError("failed to read file %q: %v", fname, err)
		}

		scanner := newScanner(f)
		state.fname = fname
		state.beforeBuf = nil
		state.remainingAfterCtxLines = 0
		state.lastPrintedLineNum = 0
		lineNum := 1

		for scanner.Scan() {
			line := scanner.Text()
			matched := re.MatchString(line)
			state.processLine(line, lineNum, matched)
			if state.truncated {
				break
			}
			lineNum++
		}
		f.Close()
		if err := scanner.Err(); err != nil {
			return readDescResults{}, aflow.BadCallError("failed to scan file %q: %v", fname, err)
		}
		if state.truncated {
			break
		}
	}

	if state.linesCount == 0 {
		return readDescResults{Output: "No matches found."}, nil
	}

	res := state.b.String()
	if state.truncated {
		res = fmt.Sprintf("%s\n... (Output truncated because it reached the maximum "+
			"line count limit. Use a stricter Expression.)", res)
	}
	return readDescResults{limitOutputBytes(res)}, nil
}

type ctxLine struct {
	num  int
	text string
}

type grepState struct {
	// File-local state (reset for every target file).
	beforeBuf              []ctxLine
	remainingAfterCtxLines int
	lastPrintedLineNum     int

	// Global state (retained across all files).
	linesCount  int
	truncated   bool
	b           *strings.Builder
	fname       string
	targetFiles []string
}

func (s *grepState) appendLine(num int, text, sep string) {
	if s.truncated {
		return
	}
	var prefix string
	if len(s.targetFiles) == 1 {
		prefix = fmt.Sprintf("%4d%s\t", num, sep)
	} else {
		prefix = fmt.Sprintf("%s:%d%s\t", s.fname, num, sep)
	}
	truncatedLine := truncateLine(text)
	s.b.WriteString(prefix)
	s.b.WriteString(truncatedLine)
	s.b.WriteByte('\n')
}

func (s *grepState) appendSeparator(lineNum int) {
	if s.lastPrintedLineNum <= 0 || s.lastPrintedLineNum >= lineNum-len(s.beforeBuf)-1 {
		return
	}
	if s.b.Len() == 0 || s.truncated {
		return
	}
	s.b.WriteString("--\n")
}

func (s *grepState) processMatched(line string, lineNum int) {
	s.appendSeparator(lineNum)

	for _, cl := range s.beforeBuf {
		s.appendLine(cl.num, cl.text, "-")
	}
	s.beforeBuf = nil

	s.appendLine(lineNum, line, ":")
	s.lastPrintedLineNum = lineNum

	s.linesCount++
	if s.linesCount >= maxGrepLines {
		s.truncated = true
	}
	s.remainingAfterCtxLines = grepContextLines
}

func (s *grepState) processUnmatched(line string, lineNum int) {
	if s.remainingAfterCtxLines > 0 {
		s.appendLine(lineNum, line, "-")
		s.remainingAfterCtxLines--
		s.lastPrintedLineNum = lineNum
		return
	}
	s.beforeBuf = append(s.beforeBuf, ctxLine{num: lineNum, text: line})
	if len(s.beforeBuf) > grepContextLines {
		s.beforeBuf = s.beforeBuf[1:]
	}
}

func (s *grepState) processLine(line string, lineNum int, matched bool) {
	if matched {
		s.processMatched(line, lineNum)
	} else {
		s.processUnmatched(line, lineNum)
	}
}

func paginateDescription(osTarget, file string, firstLine int) (readDescResults, error) {
	if file == "" {
		return readDescResults{}, aflow.BadCallError("File must be provided when not using Expression")
	}
	if err := validateFilePath(file); err != nil {
		return readDescResults{}, err
	}

	f, err := sys.Files.Open(path.Join(osTarget, file))
	if err != nil {
		return readDescResults{}, aflow.BadCallError("failed to read file %q: %v", file, err)
	}
	defer f.Close()

	firstLine = max(1, firstLine)

	scanner := newScanner(f)
	lineNum := 1

	// Skip until firstLine.
	for lineNum < firstLine && scanner.Scan() {
		lineNum++
	}
	if err := scanner.Err(); err != nil {
		return readDescResults{}, aflow.BadCallError("failed to scan file %q: %v", file, err)
	}
	// If EOF reached before firstLine.
	if lineNum < firstLine {
		return readDescResults{}, aflow.BadCallError("file %s does not have line %d, it has only %d lines",
			file, firstLine, lineNum-1)
	}

	b := new(strings.Builder)
	count := 0

	for count < paginateLinesWindow && scanner.Scan() {
		line := scanner.Text()
		truncatedLine := truncateLine(line)

		lineStr := fmt.Sprintf("%4d:\t%s\n", lineNum, truncatedLine)
		b.WriteString(lineStr)
		lineNum++
		count++
	}
	if err := scanner.Err(); err != nil {
		return readDescResults{}, aflow.BadCallError("failed to scan file %q: %v", file, err)
	}

	res := b.String()
	return readDescResults{limitOutputBytes(res)}, nil
}

func limitOutputBytes(res string) string {
	if len(res) > maxOutputBytes {
		return res[:maxOutputBytes] + "\nWARNING: Output truncated as it exceeded the 256KB limit."
	}
	return res
}

func truncateLine(line string) string {
	if len(line) <= maxLineLen {
		return line
	}
	count := 0
	for i := range line {
		if count == maxLineLen {
			return line[:i] + "... <truncated>"
		}
		count++
	}
	return line
}
