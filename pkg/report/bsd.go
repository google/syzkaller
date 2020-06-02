// Copyright 2017 syzkaller project authors. All rights reserved.
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

type bsd struct {
	*config
	oopses       []*oops
	symbolizeRes []*regexp.Regexp
	kernelObject string
	symbols      map[string][]symbolizer.Symbol
}

func ctorBSD(cfg *config, oopses []*oops, symbolizeRes []*regexp.Regexp) (Reporter, error) {
	var symbols map[string][]symbolizer.Symbol
	kernelObject := ""
	if cfg.kernelObj != "" {
		kernelObject = filepath.Join(cfg.kernelObj, cfg.target.KernelObject)
		var err error
		symb := symbolizer.NewSymbolizer(cfg.target)
		symbols, err = symb.ReadTextSymbols(kernelObject)
		if err != nil {
			return nil, err
		}
	}
	ctx := &bsd{
		config:       cfg,
		oopses:       oopses,
		symbolizeRes: symbolizeRes,
		kernelObject: kernelObject,
		symbols:      symbols,
	}
	return ctx, nil
}

func (ctx *bsd) ContainsCrash(output []byte) bool {
	return containsCrash(output, ctx.oopses, ctx.ignores)
}

func (ctx *bsd) Parse(output []byte) *Report {
	stripped := bytes.Replace(output, []byte{'\r', '\n'}, []byte{'\n'}, -1)
	stripped = bytes.Replace(stripped, []byte{'\n', '\r'}, []byte{'\n'}, -1)
	for len(stripped) != 0 && stripped[0] == '\r' {
		stripped = stripped[1:]
	}
	rep := simpleLineParser(stripped, ctx.oopses, nil, ctx.ignores)
	if rep == nil {
		return nil
	}
	rep.Output = output
	return rep
}

func (ctx *bsd) Symbolize(rep *Report) error {
	symb := symbolizer.NewSymbolizer(ctx.config.target)
	defer symb.Close()
	var symbolized []byte
	s := bufio.NewScanner(bytes.NewReader(rep.Report))
	prefix := rep.reportPrefixLen
	for s.Scan() {
		line := append([]byte{}, s.Bytes()...)
		line = append(line, '\n')
		newLine := ctx.symbolizeLine(symb.Symbolize, line)
		if prefix > len(symbolized) {
			prefix += len(newLine) - len(line)
		}
		symbolized = append(symbolized, newLine...)
	}
	rep.Report = symbolized
	rep.reportPrefixLen = prefix
	return nil
}

func (ctx *bsd) symbolizeLine(symbFunc func(bin string, pc uint64) ([]symbolizer.Frame, error),
	line []byte) []byte {
	var match []int
	// Check whether the line corresponds to the any of the parts that require symbolization.
	for _, re := range ctx.symbolizeRes {
		match = re.FindSubmatchIndex(line)
		if match != nil {
			break
		}
	}
	if match == nil {
		return line
	}
	// First part of the matched regex contains the function name.
	// Second part contains the offset.
	fn := line[match[2]:match[3]]
	off, err := strconv.ParseUint(string(line[match[4]:match[5]]), 16, 64)
	if err != nil {
		return line
	}

	// Get the symbol from the list of symbols generated using the kernel object and addr2line.
	symb := ctx.symbols[string(fn)]
	if len(symb) == 0 {
		return line
	}
	fnStart := (0xffffffff << 32) | symb[0].Addr

	// Retrieve the frames for the corresponding offset of the function.
	frames, err := symbFunc(ctx.kernelObject, fnStart+off)
	if err != nil || len(frames) == 0 {
		return line
	}
	var symbolized []byte
	// Go through each of the frames and add the corresponding file names and line numbers.
	for _, frame := range frames {
		file := frame.File
		file = strings.TrimPrefix(file, ctx.kernelBuildSrc)
		file = strings.TrimPrefix(file, "/")
		info := fmt.Sprintf(" %v:%v", file, frame.Line)
		modified := append([]byte{}, line...)
		modified = replace(modified, match[5], match[5], []byte(info))
		if frame.Inline {
			// If frames are marked inline then show that in the report also.
			end := match[5] + len(info)
			modified = replace(modified, end, end, []byte(" [inline]"))
			modified = replace(modified, match[5], match[5], []byte(" "+frame.Func))
		}
		symbolized = append(symbolized, modified...)
	}
	return symbolized
}
