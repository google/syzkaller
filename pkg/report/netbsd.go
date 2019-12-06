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

type netbsd struct {
	*config
	kernelObject string
	symbols      map[string][]symbolizer.Symbol
}

var (
	netbsdSymbolizeRe = []*regexp.Regexp{
		// stack
		regexp.MustCompile(` at netbsd:([A-Za-z0-9_]+)\+0x([0-9a-f]+)`),
		// witness
		regexp.MustCompile(`#[0-9]+ +([A-Za-z0-9_]+)\+0x([0-9a-f]+)`),
	}
)

func ctorNetbsd(cfg *config) (Reporter, []string, error) {
	var symbols map[string][]symbolizer.Symbol
	cfg.ignores = append(cfg.ignores, regexp.MustCompile("event_init: unable to initialize")) // postfix output
	kernelObject := ""
	if cfg.kernelObj != "" {
		kernelObject = filepath.Join(cfg.kernelObj, cfg.target.KernelObject)
		var err error
		symbols, err = symbolizer.ReadSymbols(kernelObject)
		if err != nil {
			return nil, nil, err
		}
	}
	ctx := &netbsd{
		config:       cfg,
		kernelObject: kernelObject,
		symbols:      symbols,
	}
	return ctx, nil, nil
}

func (ctx *netbsd) ContainsCrash(output []byte) bool {
	return containsCrash(output, netbsdOopses, ctx.ignores)
}

func (ctx *netbsd) Parse(output []byte) *Report {
	stripped := bytes.Replace(output, []byte{'\r', '\n'}, []byte{'\n'}, -1)
	stripped = bytes.Replace(stripped, []byte{'\n', '\r'}, []byte{'\n'}, -1)
	for len(stripped) != 0 && stripped[0] == '\r' {
		stripped = stripped[1:]
	}
	rep := simpleLineParser(stripped, netbsdOopses, nil, ctx.ignores)
	if rep == nil {
		return nil
	}
	rep.Output = output
	return rep
}

func (ctx *netbsd) Symbolize(rep *Report) error {
	symb := symbolizer.NewSymbolizer()
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

func (ctx *netbsd) symbolizeLine(symbFunc func(bin string, pc uint64) ([]symbolizer.Frame, error),
	line []byte) []byte {
	var match []int
	// Check whether the line corresponds to the any of the parts that
	// require symbolization.
	for _, re := range netbsdSymbolizeRe {
		match = re.FindSubmatchIndex(line)
		if match != nil {
			break
		}
	}
	if match == nil {
		return line
	}
	// First part of the matched regex contains the function name
	// Second part contains the offset
	fn := line[match[2]:match[3]]
	off, err := strconv.ParseUint(string(line[match[4]:match[5]]), 16, 64)
	if err != nil {
		return line
	}

	// Get the symbol from the list of symbols generated using
	// the kernel object and addr2line
	symb := ctx.symbols[string(fn)]
	if len(symb) == 0 {
		return line
	}
	fnStart := (0xffffffff << 32) | symb[0].Addr

	// Retrieve the frames for the corresponding offset of the function
	frames, err := symbFunc(ctx.kernelObject, fnStart+off)
	if err != nil || len(frames) == 0 {
		return line
	}
	var symbolized []byte
	// Go through each of the frames and add the corresponding file names
	// and line numbers.
	for _, frame := range frames {
		file := frame.File
		file = strings.TrimPrefix(file, ctx.kernelBuildSrc)
		file = strings.TrimPrefix(file, "/")
		info := fmt.Sprintf(" %v:%v", file, frame.Line)
		modified := append([]byte{}, line...)
		modified = replace(modified, match[5], match[5], []byte(info))
		if frame.Inline {
			// If frames are marked inline then show that in the report also
			end := match[5] + len(info)
			modified = replace(modified, end, end, []byte(" [inline]"))
			modified = replace(modified, match[5], match[5], []byte(" "+frame.Func))
		}
		symbolized = append(symbolized, modified...)
	}
	return symbolized
}

// nolint: lll
var netbsdOopses = append([]*oops{
	{
		[]byte("fault in supervisor mode"),
		[]oopsFormat{
			{
				title:  compile("fatal (page|protection|integer divide) fault in supervisor mode"),
				report: compile(`fatal (page|protection|integer divide) fault in supervisor mode(?:.*\n)+?.*Stopped in.*netbsd:([^\\+]+)`),
				fmt:    "%[1]v fault in %[2]v",
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte("panic: "),
		[]oopsFormat{
			{
				title:  compile("panic: kernel diagnostic assertion"),
				report: compile(`panic: kernel diagnostic assertion "(.*?)"`),
				fmt:    "assert failed: %[1]v",
			},
			{
				title:  compile("panic: lock error"),
				report: compile(`panic: lock error:(?:.*\n)+?.*?Begin traceback.*?\n(?:.*(?:panic|printf|lockdebug|abort|mutex).*\n)*.*?\](.*?)\(`),
				fmt:    "lock error in %[1]v",
			},
			{
				title:  compile("ASan: Unauthorized Access"),
				report: compile(`ASan: Unauthorized Access (?:.*\n)+(?:kasan|__asan).*\n(.*)\(`),
				fmt:    "ASan: Unauthorized Access in %[1]v",
			},
			{
				title:  compile("MSan: Uninitialized"),
				report: compile(`MSan: Uninitialized (?:.*\n)+(?:kmsan|__msan).*\n(.*)\(`),
				fmt:    "MSan: Uninitialized Memory in %[1]v",
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte("UBSan:"),
		[]oopsFormat{
			{
				title: compile("UBSan:"),
				fmt:   "UBSan: Undefined behavior",
			},
		},
		[]*regexp.Regexp{},
	},
}, commonOopses...)
