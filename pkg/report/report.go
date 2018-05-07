// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package report contains functions that process kernel output,
// detect/extract crash messages, symbolize them, etc.
package report

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/syzkaller/pkg/symbolizer"
)

type Reporter interface {
	// ContainsCrash searches kernel console output for oops messages.
	ContainsCrash(output []byte) bool

	// Parse extracts information about oops from console output.
	// Returns nil if no oops found.
	Parse(output []byte) *Report

	// Symbolize symbolizes rep.Report and fills in Maintainers.
	Symbolize(rep *Report) error
}

type Report struct {
	// Title contains a representative description of the first oops.
	Title string
	// Report contains whole oops text.
	Report []byte
	// Output contains whole raw console output as passed to Reporter.Parse.
	Output []byte
	// StartPos/EndPos denote region of output with oops message(s).
	StartPos int
	EndPos   int
	// Corrupted indicates whether the report is truncated of corrupted in some other way.
	Corrupted bool
	// corruptedReason contains reason why the report is marked as corrupted.
	corruptedReason string
	// Maintainers is list of maintainer emails.
	Maintainers []string
}

// NewReporter creates reporter for the specified OS:
// kernelSrc: path to kernel sources directory
// kernelObj: path to kernel build directory (can be empty for in-tree build)
// symbols: kernel symbols (result of pkg/symbolizer.ReadSymbols on kernel object file)
// ignores: optional list of regexps to ignore (must match first line of crash message)
func NewReporter(os, kernelSrc, kernelObj string, symbols map[string][]symbolizer.Symbol,
	ignores []*regexp.Regexp) (Reporter, error) {
	ctor := ctors[os]
	if ctor == nil {
		return nil, fmt.Errorf("unknown os: %v", os)
	}
	if kernelObj == "" {
		kernelObj = kernelSrc // assume in-tree build
	}
	rep, err := ctor(kernelSrc, kernelObj, symbols, ignores)
	if err != nil {
		return nil, err
	}
	return reporterWrapper{rep}, nil
}

var ctors = map[string]fn{
	"akaros":  ctorStub,
	"linux":   ctorLinux,
	"freebsd": ctorFreebsd,
	"netbsd":  ctorNetbsd,
	"fuchsia": ctorStub,
	"windows": ctorStub,
}

type fn func(string, string, map[string][]symbolizer.Symbol, []*regexp.Regexp) (Reporter, error)

type reporterWrapper struct {
	Reporter
}

func (wrap reporterWrapper) Parse(output []byte) *Report {
	rep := wrap.Reporter.Parse(output)
	if rep == nil {
		return nil
	}
	rep.Title = sanitizeTitle(rep.Title)
	return rep
}

func sanitizeTitle(title string) string {
	const maxTitleLen = 120 // Corrupted/intermixed lines can be very long.
	res := make([]byte, 0, len(title))
	prev := byte(' ')
	for i := 0; i < len(title) && i < maxTitleLen; i++ {
		ch := title[i]
		switch {
		case ch == '\t':
			ch = ' '
		case ch < 0x20 || ch >= 0x7f:
			continue
		}
		if ch == ' ' && prev == ' ' {
			continue
		}
		res = append(res, ch)
		prev = ch
	}
	return strings.TrimSpace(string(res))
}

type guilter interface {
	extractGuiltyFile([]byte) string
}

func (wrap reporterWrapper) extractGuiltyFile(report []byte) string {
	if g, ok := wrap.Reporter.(guilter); ok {
		return g.extractGuiltyFile(report)
	}
	panic("not implemented")
}

type oops struct {
	header       []byte
	formats      []oopsFormat
	suppressions []*regexp.Regexp
}

type oopsFormat struct {
	title *regexp.Regexp
	// If title is matched but report is not, the report is considered corrupted.
	report *regexp.Regexp
	// Format string to create report title.
	// Strings captured by title (or by report if present) are passed as input.
	// If stack is not nil, extracted function name is passed as an additional last argument.
	fmt string
	// If not nil, a function name is extracted from the report and passed to fmt.
	// If not nil but frame extraction fails, the report is considered corrupted.
	stack        *stackFmt
	noStackTrace bool
	corrupted    bool
}

type stackFmt struct {
	// parts describe how guilty stack frame must be extracted from the report.
	// parts are matched consecutively potentially capturing frames.
	// parts can be of 3 types:
	//  - non-capturing regexp, matched against report and advances current position
	//  - capturing regexp, same as above, but also yields a frame
	//  - special value parseStackTrace means that a stack trace must be parsed
	//    starting from current position
	parts []*regexp.Regexp
	// If parts2 is present it is tried when parts matching fails.
	parts2 []*regexp.Regexp
	// Skip these functions in stack traces (matched as substring).
	skip []string
}

var parseStackTrace *regexp.Regexp

func compile(re string) *regexp.Regexp {
	re = strings.Replace(re, "{{ADDR}}", "0x[0-9a-f]+", -1)
	re = strings.Replace(re, "{{PC}}", "\\[\\<[0-9a-f]+\\>\\]", -1)
	re = strings.Replace(re, "{{FUNC}}", "([a-zA-Z0-9_]+)(?:\\.|\\+)", -1)
	re = strings.Replace(re, "{{SRC}}", "([a-zA-Z0-9-_/.]+\\.[a-z]+:[0-9]+)", -1)
	return regexp.MustCompile(re)
}

func containsCrash(output []byte, oopses []*oops, ignores []*regexp.Regexp) bool {
	for pos := 0; pos < len(output); {
		next := bytes.IndexByte(output[pos:], '\n')
		if next != -1 {
			next += pos
		} else {
			next = len(output)
		}
		for _, oops := range oopses {
			match := matchOops(output[pos:next], oops, ignores)
			if match == -1 {
				continue
			}
			return true
		}
		pos = next + 1
	}
	return false
}

func matchOops(line []byte, oops *oops, ignores []*regexp.Regexp) int {
	match := bytes.Index(line, oops.header)
	if match == -1 {
		return -1
	}
	if matchesAny(line, oops.suppressions) {
		return -1
	}
	if matchesAny(line, ignores) {
		return -1
	}
	return match
}

func extractDescription(output []byte, oops *oops, params *stackParams) (
	desc string, corrupted string, format oopsFormat) {
	startPos := len(output)
	matchedTitle := false
	for _, f := range oops.formats {
		match := f.title.FindSubmatchIndex(output)
		if match == nil || match[0] > startPos {
			continue
		}
		if match[0] == startPos && desc != "" {
			continue
		}
		if match[0] < startPos {
			desc = ""
			format = oopsFormat{}
			startPos = match[0]
		}
		matchedTitle = true
		if f.report != nil {
			match = f.report.FindSubmatchIndex(output)
			if match == nil {
				continue
			}
		}
		var args []interface{}
		for i := 2; i < len(match); i += 2 {
			args = append(args, string(output[match[i]:match[i+1]]))
		}
		corrupted = ""
		if f.stack != nil {
			frame := ""
			frame, corrupted = extractStackFrame(params, f.stack, output[match[0]:])
			if frame == "" {
				frame = "corrupted"
				if corrupted == "" {
					corrupted = "extracted no stack frame"
				}
			}
			args = append(args, frame)
		}
		desc = fmt.Sprintf(f.fmt, args...)
		format = f
	}
	if len(desc) == 0 {
		// If we are here and matchedTitle is set, it means that we've matched
		// a title of an oops but not full report regexp or stack trace,
		// which means the report was corrupted.
		if matchedTitle {
			corrupted = "matched title but not report regexp"
		}
		pos := bytes.Index(output, oops.header)
		if pos == -1 {
			return
		}
		end := bytes.IndexByte(output[pos:], '\n')
		if end == -1 {
			end = len(output)
		} else {
			end += pos
		}
		desc = string(output[pos:end])
	}
	return
}

type stackParams struct {
	// stackStartRes matches start of stack traces.
	stackStartRes []*regexp.Regexp
	// frameRes match different formats of lines containing kernel frames (capture function name).
	frameRes []*regexp.Regexp
	// skipPatterns match functions that must be unconditionally skipped.
	skipPatterns []string
	// If we looked at any lines that match corruptedLines during report analysis,
	// then the report is marked as corrupted.
	corruptedLines []*regexp.Regexp
}

func extractStackFrame(params *stackParams, stack *stackFmt, output []byte) (string, string) {
	skip := append([]string{}, params.skipPatterns...)
	skip = append(skip, stack.skip...)
	var skipRe *regexp.Regexp
	if len(skip) != 0 {
		skipRe = regexp.MustCompile(strings.Join(skip, "|"))
	}
	frame, corrupted := extractStackFrameImpl(params, output, skipRe, stack.parts)
	if frame != "" || len(stack.parts2) == 0 {
		return frame, corrupted
	}
	return extractStackFrameImpl(params, output, skipRe, stack.parts2)
}

func extractStackFrameImpl(params *stackParams, output []byte, skipRe *regexp.Regexp,
	parts []*regexp.Regexp) (string, string) {
	corrupted := ""
	s := bufio.NewScanner(bytes.NewReader(output))
nextPart:
	for _, part := range parts {
		if part == parseStackTrace {
			for s.Scan() {
				ln := s.Bytes()
				if corrupted == "" && matchesAny(ln, params.corruptedLines) {
					corrupted = "corrupted line in report (1)"
				}
				if matchesAny(ln, params.stackStartRes) {
					continue nextPart
				}
				var match []int
				for _, re := range params.frameRes {
					match = re.FindSubmatchIndex(ln)
					if match != nil {
						break
					}
				}
				if match == nil {
					continue
				}
				frame := ln[match[2]:match[3]]
				if skipRe == nil || !skipRe.Match(frame) {
					return string(frame), corrupted
				}
			}
		} else {
			for s.Scan() {
				ln := s.Bytes()
				if corrupted == "" && matchesAny(ln, params.corruptedLines) {
					corrupted = "corrupted line in report (2)"
				}
				match := part.FindSubmatchIndex(ln)
				if match == nil {
					continue
				}
				if len(match) == 4 && match[2] != -1 {
					frame := ln[match[2]:match[3]]
					if skipRe == nil || !skipRe.Match(frame) {
						return string(frame), corrupted
					}
				}
				break
			}
		}
	}
	return "", corrupted
}

func matchesAny(line []byte, res []*regexp.Regexp) bool {
	for _, re := range res {
		if re.Match(line) {
			return true
		}
	}
	return false
}

// replace replaces [start:end] in where with what, inplace.
func replace(where []byte, start, end int, what []byte) []byte {
	if len(what) >= end-start {
		where = append(where, what[end-start:]...)
		copy(where[start+len(what):], where[end:])
		copy(where[start:], what)
	} else {
		copy(where[start+len(what):], where[end:])
		where = where[:len(where)-(end-start-len(what))]
		copy(where[start:], what)
	}
	return where
}
