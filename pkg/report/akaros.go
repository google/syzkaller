// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"bufio"
	"bytes"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/syzkaller/pkg/symbolizer"
)

type akaros struct {
	*config
	objfile string
}

func ctorAkaros(cfg *config) (Reporter, []string, error) {
	ctx := &akaros{
		config: cfg,
	}
	if ctx.kernelObj != "" {
		ctx.objfile = filepath.Join(ctx.kernelObj, ctx.target.KernelObject)
	}
	return ctx, nil, nil
}

func (ctx *akaros) ContainsCrash(output []byte) bool {
	return containsCrash(output, akarosOopses, ctx.ignores)
}

func (ctx *akaros) Parse(output []byte) *Report {
	rep := simpleLineParser(output, akarosOopses, akarosStackParams, ctx.ignores)
	if rep == nil {
		return nil
	}
	if report := ctx.minimizeReport(rep.Report); len(report) != 0 {
		rep.Report = report
	}
	return rep
}

func (ctx *akaros) Symbolize(rep *Report) error {
	if ctx.objfile == "" {
		return nil
	}
	symb := symbolizer.NewSymbolizer(ctx.config.target)
	defer symb.Close()
	var symbolized []byte
	s := bufio.NewScanner(bytes.NewReader(rep.Report))
	for s.Scan() {
		line := bytes.Trim(s.Bytes(), "\r")
		line = ctx.symbolizeLine(symb.Symbolize, ctx.objfile, line)
		symbolized = append(symbolized, line...)
		symbolized = append(symbolized, '\n')
	}
	rep.Report = symbolized
	return nil
}

func (ctx *akaros) symbolizeLine(symbFunc func(bin string, pc uint64) ([]symbolizer.Frame, error),
	objfile string, line []byte) []byte {
	match := akarosSymbolizeRe.FindSubmatchIndex(line)
	if match == nil {
		return line
	}
	addr, err := strconv.ParseUint(string(line[match[2]:match[3]]), 0, 64)
	if err != nil {
		return line
	}
	frames, err := symbFunc(objfile, addr-1)
	if err != nil || len(frames) == 0 {
		return line
	}
	var symbolized []byte
	for i, frame := range frames {
		if i != 0 {
			symbolized = append(symbolized, '\n')
		}
		file := frame.File
		if pos := strings.LastIndex(file, "/kern/"); pos != -1 {
			file = file[pos+6:]
		}
		modified := append([]byte{}, line...)
		modified = append(modified, fmt.Sprintf(" at %v:%v", file, frame.Line)...)
		if frame.Inline {
			modified = replace(modified, match[4], match[5], []byte(frame.Func))
			modified = replace(modified, match[2], match[3], []byte("     [inline]     "))
		}
		symbolized = append(symbolized, modified...)
	}
	return symbolized
}

func (ctx *akaros) minimizeReport(report []byte) []byte {
	out := new(bytes.Buffer)
	for s := bufio.NewScanner(bytes.NewReader(report)); s.Scan(); {
		line := bytes.Trim(s.Bytes(), "\r")
		if len(line) == 0 ||
			bytes.Contains(line, []byte("Entering Nanwan's Dungeon")) ||
			bytes.Contains(line, []byte("Type 'help' for a list of commands")) {
			continue
		}
		out.Write(line)
		out.WriteByte('\n')
	}
	return out.Bytes()
}

var (
	akarosSymbolizeRe = compile(`^#[0-9]+ \[\<(0x[0-9a-f]+)\>\] in ([a-zA-Z0-9_]+)`)
	akarosBacktraceRe = compile(`(?:Stack Backtrace|Backtrace of kernel context) on Core [0-9]+:`)
)

var akarosStackParams = &stackParams{
	stackStartRes: []*regexp.Regexp{
		akarosBacktraceRe,
	},
	frameRes: []*regexp.Regexp{
		compile(`^#[0-9]+ {{PC}} in ([a-zA-Z0-9_]+)`),
	},
	skipPatterns: []string{
		"backtrace",
		"mon_backtrace",
		"monitor",
		"_panic",
		"_warn",
	},
}

var akarosOopses = append([]*oops{
	{
		[]byte("kernel panic"),
		[]oopsFormat{
			{
				title: compile("kernel panic at {{SRC}}, from core [0-9]+: assertion failed: (.*)"),
				fmt:   "assertion failed: %[2]v",
				stack: &stackFmt{
					parts: []*regexp.Regexp{
						akarosBacktraceRe,
						parseStackTrace,
					},
				},
			},
			{
				title: compile("kernel panic at {{SRC}}, from core [0-9]+: (.*)"),
				fmt:   "kernel panic: %[2]v",
				stack: &stackFmt{
					parts: []*regexp.Regexp{
						akarosBacktraceRe,
						parseStackTrace,
					},
				},
			},
			{
				title:        compile("kernel panic"),
				fmt:          "kernel panic",
				noStackTrace: true,
				corrupted:    true,
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte("kernel warning"),
		[]oopsFormat{
			{
				title: compile("kernel warning at {{SRC}}, from core [0-9]+"),
				fmt:   "kernel warning in %[2]v",
				stack: &stackFmt{
					parts: []*regexp.Regexp{
						akarosBacktraceRe,
						parseStackTrace,
					},
				},
			},
			{
				title:        compile("kernel warning"),
				fmt:          "kernel warning",
				noStackTrace: true,
				corrupted:    true,
			},
		},
		[]*regexp.Regexp{},
	},
}, commonOopses...)
