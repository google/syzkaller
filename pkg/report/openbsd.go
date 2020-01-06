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

type openbsd struct {
	*config
	kernelObject string
	symbols      map[string][]symbolizer.Symbol
}

var (
	openbsdSymbolizeRe = []*regexp.Regexp{
		// stack
		regexp.MustCompile(` at ([A-Za-z0-9_]+)\+0x([0-9a-f]+)`),
		// witness
		regexp.MustCompile(`#[0-9]+ +([A-Za-z0-9_]+)\+0x([0-9a-f]+)`),
	}
)

func ctorOpenbsd(cfg *config) (Reporter, []string, error) {
	var symbols map[string][]symbolizer.Symbol
	kernelObject := ""
	if cfg.kernelObj != "" {
		kernelObject = filepath.Join(cfg.kernelObj, cfg.target.KernelObject)
		var err error
		symbols, err = symbolizer.ReadSymbols(kernelObject)
		if err != nil {
			return nil, nil, err
		}
	}
	ctx := &openbsd{
		config:       cfg,
		kernelObject: kernelObject,
		symbols:      symbols,
	}
	suppressions := []string{
		"panic: fifo_badop called",
	}
	return ctx, suppressions, nil
}

func (ctx *openbsd) ContainsCrash(output []byte) bool {
	return containsCrash(output, openbsdOopses, ctx.ignores)
}

func (ctx *openbsd) Parse(output []byte) *Report {
	stripped := bytes.Replace(output, []byte{'\r', '\n'}, []byte{'\n'}, -1)
	stripped = bytes.Replace(stripped, []byte{'\n', '\r'}, []byte{'\n'}, -1)
	for len(stripped) != 0 && stripped[0] == '\r' {
		stripped = stripped[1:]
	}
	rep := simpleLineParser(stripped, openbsdOopses, nil, ctx.ignores)
	if rep == nil {
		return nil
	}
	rep.Output = output
	return rep
}

func (ctx *openbsd) Symbolize(rep *Report) error {
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

func (ctx *openbsd) symbolizeLine(symbFunc func(bin string, pc uint64) ([]symbolizer.Frame, error),
	line []byte) []byte {
	var match []int
	for _, re := range openbsdSymbolizeRe {
		match = re.FindSubmatchIndex(line)
		if match != nil {
			break
		}
	}
	if match == nil {
		return line
	}
	fn := line[match[2]:match[3]]
	off, err := strconv.ParseUint(string(line[match[4]:match[5]]), 16, 64)
	if err != nil {
		return line
	}

	symb := ctx.symbols[string(fn)]
	if len(symb) == 0 {
		return line
	}
	fnStart := (0xffffffff << 32) | symb[0].Addr

	frames, err := symbFunc(ctx.kernelObject, fnStart+off)
	if err != nil || len(frames) == 0 {
		return line
	}
	var symbolized []byte
	for _, frame := range frames {
		file := frame.File
		file = strings.TrimPrefix(file, ctx.kernelBuildSrc)
		file = strings.TrimPrefix(file, "/")
		info := fmt.Sprintf(" %v:%v", file, frame.Line)
		modified := append([]byte{}, line...)
		modified = replace(modified, match[5], match[5], []byte(info))
		if frame.Inline {
			end := match[5] + len(info)
			modified = replace(modified, end, end, []byte(" [inline]"))
			modified = replace(modified, match[5], match[5], []byte(" "+frame.Func))
		}
		symbolized = append(symbolized, modified...)
	}
	return symbolized
}

var openbsdOopses = append([]*oops{
	{
		[]byte("cleaned vnode"),
		[]oopsFormat{
			{
				title: compile("cleaned vnode: "),
				fmt:   "panic: cleaned vnode isn't",
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte("panic"),
		[]oopsFormat{
			{
				title: compile("panic: kernel diagnostic assertion (.+) failed: file \".*/([^\"]+)"),
				fmt:   "assert %[1]v failed in %[2]v",
			},
			{
				title: compile("panic: Data modified on freelist: .* previous type ([^ ]+)"),
				fmt:   "malloc: free list modified: %[1]v",
			},
			{
				title: compile("panic: pool_cache_item_magic_check: ([^ ]+) cpu free list modified"),
				fmt:   "pool: cpu free list modified: %[1]v",
			},
			{
				title: compile("panic: pool_do_put: ([^:]+): double pool_put"),
				fmt:   "pool: double put: %[1]v",
			},
			{
				title: compile("panic: pool_do_get: ([^:]+) free list modified"),
				fmt:   "pool: free list modified: %[1]v",
			},
			{
				title: compile("panic: pool_p_free: ([^:]+) free list modified"),
				fmt:   "pool: free list modified: %[1]v",
			},
			{
				title: compile("panic: timeout_add: to_ticks \\(.+\\) < 0"),
				fmt:   "panic: timeout_add: to_ticks < 0",
			},
			{
				title: compile("panic: attempt to execute user address {{ADDR}} in supervisor mode"),
				fmt:   "panic: attempt to execute user address",
			},
			{
				title: compile("panic: unhandled af"),
				fmt:   "panic: unhandled af",
			},
			{
				title: compile("panic: (kqueue|knote).* ([a-z]+ .*)"),
				fmt:   "kqueue: %[2]v",
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte("lock order reversal:"),
		[]oopsFormat{
			{
				title: compile("lock order reversal:\\n+.*1st {{ADDR}} ([^\\ ]+).*\\n.*2nd {{ADDR}} ([^\\ ]+)"),
				fmt:   "witness: reversal: %[1]v %[2]v",
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte("witness:"),
		[]oopsFormat{
			{
				title: compile("witness: thread {{ADDR}} exiting with the following locks held:"),
				fmt:   "witness: thread exiting with locks held",
			},
			{
				title: compile("witness: userret: returning with the following locks held:(.*\\n)+?.*sys_([a-z0-9_]+)\\+"),
				fmt:   "witness: userret: %[2]v",
			},
			{
				title: compile("(witness: .*)"),
				fmt:   "%[1]v",
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte("uvm_fault"),
		[]oopsFormat{
			{
				title: compile("uvm_fault\\((?:.*\\n)+?.*Stopped at[ ]+{{ADDR}}"),
				fmt:   "uvm_fault",
			},
			{
				title: compile("uvm_fault\\((?:.*\\n)+?.*Stopped at[ ]+([^\\+]+)"),
				fmt:   "uvm_fault: %[1]v",
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte("kernel:"),
		[]oopsFormat{
			{
				title: compile("kernel: page fault trap, code=0.*\\nStopped at[ ]+([^\\+]+)"),
				fmt:   "uvm_fault: %[1]v",
			},
		},
		[]*regexp.Regexp{
			compile("reorder_kernel"),
		},
	},
}, commonOopses...)
