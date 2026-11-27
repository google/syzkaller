// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"bytes"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/google/syzkaller/pkg/symbolizer"
	"github.com/google/syzkaller/sys/targets"
)

type bsd struct {
	*config
	oopses          []*oops
	symbolizeRes    []*regexp.Regexp
	kernelObject    string
	symbols         map[string][]symbolizer.Symbol
	symbolizerCache symbolizer.Cache
}

func ctorBSD(cfg *config, oopses []*oops, symbolizeRes []*regexp.Regexp) (reporterImpl, error) {
	kernelObject, symbols, err := loadKernelSymbols(cfg)
	if err != nil {
		return nil, err
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

func loadKernelSymbols(cfg *config) (string, map[string][]symbolizer.Symbol, error) {
	if cfg.kernelDirs.Obj == "" {
		return "", nil, nil
	}
	kernelObject := filepath.Join(cfg.kernelDirs.Obj, cfg.target.KernelObject)
	symbols, err := symbolizer.ReadTextSymbols(kernelObject)
	if err != nil {
		return "", nil, err
	}
	return kernelObject, symbols, nil
}

func (ctx *bsd) ContainsCrash(output []byte) bool {
	return containsCrash(output, ctx.oopses, ctx.ignores)
}

func (ctx *bsd) Parse(output []byte) *Report {
	return simpleLineParser(output, ctx.oopses, nil, ctx.ignores)
}

func (ctx *bsd) Symbolize(rep *Report) error {
	return runSymbolizer(rep, ctx.target, ctx.kernelObject, &ctx.symbolizerCache, ctx.symbolizeLine)
}

type bsdSymbFunc = func(string, ...uint64) ([]symbolizer.Frame, error)

func runSymbolizer(rep *Report, target *targets.Target, kernelObject string, cache *symbolizer.Cache,
	symbLine func(bsdSymbFunc, []byte) []byte) error {
	if kernelObject == "" {
		return nil
	}
	symb := symbolizer.Make(target)
	defer symb.Close()
	symbFunc := symb.Symbolize
	if cache != nil {
		symbFunc = func(bin string, pcs ...uint64) ([]symbolizer.Frame, error) {
			if len(pcs) == 1 {
				return cache.Symbolize(symb.Symbolize, bin, pcs[0])
			}
			return symb.Symbolize(bin, pcs...)
		}
	}
	symbolizeReportLines(rep, symbFunc, symbLine)
	return nil
}

func symbolizeReportLines(rep *Report, symbFunc bsdSymbFunc, symbLine func(bsdSymbFunc, []byte) []byte) {
	var symbolized []byte
	prefix := rep.reportPrefixLen
	for line := range bytes.SplitAfterSeq(rep.Report, []byte("\n")) {
		newLine := symbLine(symbFunc, line)
		if prefix > len(symbolized) {
			prefix += len(newLine) - len(line)
		}
		symbolized = append(symbolized, newLine...)
	}
	rep.Report = symbolized
	rep.reportPrefixLen = prefix
}

func (ctx *bsd) symbolizeLine(symbFunc func(string, ...uint64) ([]symbolizer.Frame, error),
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
		file = strings.TrimPrefix(file, ctx.kernelDirs.BuildSrc)
		file = strings.TrimPrefix(file, "/")
		info := fmt.Sprintf(" %v:%v", file, frame.Line)
		modified := slices.Clone(line)
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
