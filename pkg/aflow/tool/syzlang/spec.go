// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzlang

import (
	"bufio"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/syzlang"
)

const autoTxt = "auto.txt"

var ReadSyzSpec = aflow.NewFuncTool("read-syz-spec", readSyzSpec, fmt.Sprintf(`
The tool reads the content of a syzlang description file (e.g. sys.txt), 
a test seed file (e.g. test/syz_mount_xxxx_0.txt),
or specification/header files from the repository (executor/ and docs/ directories).

CRITICAL INSTRUCTION: Do NOT use this tool for Linux kernel files, standard POSIX headers (like
sys/socket.h), or runtime filesystem paths (like /sys/class/gpio/export). This tool is ONLY
for syzkaller specification/metadata/code files (descriptions, seeds, or executor headers).

Description files contain syscall definitions. Test seeds contain working examples of 
syzkaller programs. These seeds (e.g., test/vusb_cdc_ecm) often serve as a starting point 
for a program that sets up some devices, like USB. You DO NOT need to understand exactly 
every field of the lines in the test seed files.
You can also read executor headers like executor/common_usb_linux.h. This is highly useful
for understanding syz_* pseudo-syscalls (e.g. syz_usb_connect or syz_mount_image). Since
these pseudo-syscalls do not exist in the Linux kernel, their actual C/C++ implementations are
defined in the syzkaller executor. Reading these headers allows you to see exactly how
complex arguments or opaque pointers are parsed and mapped to real kernel interactions.
Kernel docs from the docs/ directory can also be read.

CRITICAL INSTRUCTION: When querying a file in the sys/<os> or sys/<os>/test directory, you MUST
provide ONLY the base filename or the test/ prefix (e.g. use "vusb.txt", NOT "sys/linux/vusb.txt" 
or "/path/to/sys/linux/vusb.txt").

You can read a specific file sequentially by providing File and FirstLine. The tool returns at most %d lines at a time.
If you need more, you need to call the tool several times.

Note: Individual lines exceeding %d characters will be horizontally truncated and appended
with "... <line truncated>". This usually happens with massive arrays or descriptors. You do NOT 
need to understand or reconstruct the truncated parts. Crucially, this does NOT mean the file 
itself was truncated; subsequent lines are still printed normally. Do not attempt to paginate 
further just because a line was truncated.
`, paginateLinesWindow, maxLineLen))

var SyzGrepper = aflow.NewFuncTool("syz-grepper", syzGrepper, fmt.Sprintf(`
The tool greps across syzlang description files (e.g. sys.txt), test seed files (e.g. test/syz_mount_image_btrfs_0),
or specification/header files (executor/ and docs/ directories).

CRITICAL INSTRUCTION: Do NOT use this tool to search Linux kernel source code, POSIX headers, or virtual
filesystem paths (like sys/class/ or /sys/class/). This tool is ONLY for syzkaller specification/metadata/code files.

CRITICAL INSTRUCTION: The 'Expression' parameter is a regular expression matched against the *text content*
inside the files. It is NOT matched against the filenames. Do NOT use it to search for filenames or paths
(e.g. do NOT set 'Expression' to "test/.*tun").

CRITICAL INSTRUCTION: When querying a file in the sys/<os> or sys/<os>/test directory, you MUST provide
ONLY the base filename or the test/ prefix (e.g. use "vusb.txt", NOT "sys/linux/vusb.txt" 
or "/path/to/sys/linux/vusb.txt").

If you want to search inside test seeds (the test/ directory) for relevant syscalls or device names,
you MUST set 'PathPrefix' to "test". Otherwise, 'syz-grepper' will search across all description files
excluding tests.

The grep results will automatically include up to %d surrounding context lines for each match
to help you understand the definition.
You can grep both .txt, .const, and test seed files.

Note: Individual lines exceeding %d characters will be horizontally truncated and appended with "... <line truncated>".
`, grepContextLines, maxLineLen))

const (
	maxGrepLines          = 300
	maxLineLen            = 500
	paginateLinesWindow   = 100
	maxOutputBytes        = 32 * 1024
	defaultScanBufferSize = 32 * 1024
	maxScanBufferSize     = 10 * 1024 * 1024
	grepContextLines      = 10
)

type readSyzSpecArgs struct {
	File      string `jsonschema:"Source file path to read, e.g. sys.txt."`
	FirstLine int    `jsonschema:"First source line to return, 1-based."`
	LineCount int    `jsonschema:"Number of lines to return, capped at 150." json:",omitempty"`
}

type syzGrepperArgs struct {
	Expression string `jsonschema:"Regular expression to search in the description file(s)."`
	PathPrefix string `jsonschema:"Optional path prefix or file to restrict the scope of the grep." json:",omitempty"`
}

type readSyzSpecResults struct {
	Output string `jsonschema:"Content of the description file."`
}

type syzGrepperResults struct {
	Output string `jsonschema:"Grep results from the description file(s)."`
}

type specToolsState struct {
	TargetOS  string
	Syzkaller string
}

func readSyzSpec(ctx *aflow.Context, state specToolsState, args readSyzSpecArgs) (readSyzSpecResults, error) {
	sysFS := syzlang.NewSyzFS(state.Syzkaller, state.TargetOS)
	cleanedFile := sysFS.CleanPath(args.File)
	res, err := paginateSyzSpec(sysFS, sysFS.OSTarget(), cleanedFile, args.FirstLine, args.LineCount)
	return readSyzSpecResults{Output: res}, err
}

func syzGrepper(ctx *aflow.Context, state specToolsState, args syzGrepperArgs) (syzGrepperResults, error) {
	sysFS := syzlang.NewSyzFS(state.Syzkaller, state.TargetOS)
	cleanedFile := sysFS.CleanPath(args.PathPrefix)
	res, err := grepSyzSpec(sysFS, sysFS.OSTarget(), args.Expression, cleanedFile)
	return syzGrepperResults{Output: res}, err
}

func validateFilePath(file string) error {
	if file != "" {
		cleaned := file
		if suffix, ok := strings.CutPrefix(cleaned, "test/"); ok {
			cleaned = suffix
		} else if suffix, ok := strings.CutPrefix(cleaned, "executor/"); ok {
			cleaned = suffix
		} else if suffix, ok := strings.CutPrefix(cleaned, "docs/"); ok {
			cleaned = suffix
		}
		if strings.Contains(cleaned, "..") || filepath.IsAbs(cleaned) {
			return aflow.BadCallError("invalid file path %q", file)
		}
		if !strings.HasPrefix(file, "executor/") && !strings.HasPrefix(file, "docs/") && !strings.HasPrefix(file, "test/") {
			if strings.Contains(cleaned, "/") || strings.Contains(cleaned, "\\") {
				return aflow.BadCallError("invalid file path %q", file)
			}
		}
		if cleaned == autoTxt || cleaned == autoTxt+".const" {
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

func resolveTargetFiles(fileSystem fs.FS, osTarget, file string) ([]string, error) {
	if file == "" {
		// When file is empty, syz-grepper searches across all description files.
		// These are files under osTarget/ directory, excluding test/ subdirectory.
		return DescriptionFiles(osTarget), nil
	}

	fileInfo, err := fs.Stat(fileSystem, file)
	if err == nil && fileInfo.IsDir() {
		var targetFiles []string
		err = fs.WalkDir(fileSystem, file, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() {
				targetFiles = append(targetFiles, p)
			}
			return nil
		})
		if err != nil {
			return nil, aflow.BadCallError("failed to walk directory %q: %v", file, err)
		}
		return targetFiles, nil
	}
	return []string{file}, nil
}

func grepSyzSpec(fileSystem fs.FS, osTarget, expression, file string) (string, error) {
	if err := validateFilePath(file); err != nil {
		return "", err
	}

	re, err := regexp.Compile(expression)
	if err != nil {
		return "", aflow.BadCallError("bad expression: %v", err)
	}
	targetFiles, err := resolveTargetFiles(fileSystem, osTarget, file)
	if err != nil {
		return "", err
	}

	state := grepState{
		b:           new(strings.Builder),
		targetFiles: targetFiles,
	}

	for _, fname := range targetFiles {
		f, err := fileSystem.Open(fname)
		if err != nil {
			return "", aflow.BadCallError("failed to read file %q: %v", fname, err)
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
			return "", aflow.BadCallError("failed to scan file %q: %v", fname, err)
		}
		if state.truncated {
			break
		}
	}

	if state.linesCount == 0 {
		return "No matches found.", nil
	}

	res := state.b.String()
	if state.truncated {
		res = fmt.Sprintf("%s\n... (Output truncated because it reached the maximum "+
			"line count limit. Use a stricter Expression.)", res)
	}
	return limitOutputBytes(res), nil
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
	linesCount        int
	truncated         bool
	b                 *strings.Builder
	fname             string
	targetFiles       []string
	firstMatchPrinted bool
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
	if s.firstMatchPrinted && s.lastPrintedLineNum <= 0 {
		s.b.WriteString("--\n")
	} else {
		s.appendSeparator(lineNum)
	}
	s.firstMatchPrinted = true

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

func paginateSyzSpec(fileSystem fs.FS, osTarget, file string, firstLine,
	lineCount int) (string, error) {
	if file == "" {
		return "", aflow.BadCallError("File must be provided")
	}
	if err := validateFilePath(file); err != nil {
		return "", err
	}

	f, err := fileSystem.Open(file)
	if err != nil {
		return "", aflow.BadCallError("failed to read file %q: %v", file, err)
	}
	defer f.Close()

	firstLine = max(1, firstLine)
	if lineCount <= 0 || lineCount > paginateLinesWindow {
		lineCount = paginateLinesWindow
	}

	scanner := newScanner(f)
	lineNum := 1

	// Skip until firstLine.
	for lineNum < firstLine && scanner.Scan() {
		lineNum++
	}
	if err := scanner.Err(); err != nil {
		return "", aflow.BadCallError("failed to scan file %q: %v", file, err)
	}
	// If EOF reached before firstLine.
	if lineNum < firstLine {
		return "", aflow.BadCallError("file %s does not have line %d, it has only %d lines",
			file, firstLine, lineNum-1)
	}

	b := new(strings.Builder)
	count := 0

	for count < lineCount && scanner.Scan() {
		line := scanner.Text()
		truncatedLine := truncateLine(line)

		lineStr := fmt.Sprintf("%4d:\t%s\n", lineNum, truncatedLine)
		b.WriteString(lineStr)
		lineNum++
		count++
	}
	if err := scanner.Err(); err != nil {
		return "", aflow.BadCallError("failed to scan file %q: %v", file, err)
	}
	if count < lineCount {
		b.WriteString("(EOF)\n")
	}

	res := b.String()
	return limitOutputBytes(res), nil
}

func limitOutputBytes(res string) string {
	if len(res) > maxOutputBytes {
		msg := fmt.Sprintf("\nWARNING: Output truncated as it exceeded the %dKB limit.", maxOutputBytes/1024)
		return res[:maxOutputBytes] + msg
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
			return line[:i] + "... <line truncated>"
		}
		count++
	}
	return line
}
