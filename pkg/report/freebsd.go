// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/google/syzkaller/pkg/cover/backend"
	"github.com/google/syzkaller/pkg/symbolizer"
)

type freebsd struct {
	*config
	kernelObject    string
	symbols         map[string][]symbolizer.Symbol
	symbolizerCache symbolizer.Cache
}

var (
	// Exact faulting PC from trap header, e.g. "instruction pointer = 0x20:0xffffffff8202f244".
	freebsdRipRe = regexp.MustCompile(`instruction pointer\s*=\s*0x[0-9a-fA-F]+:(0x[0-9a-fA-F]+)`)
	// KDB stack_print frame with explicit PC, e.g. "#6 0xffffffff8039e2f1 at xpt_release_ccb+0x91".
	freebsdStackPCRe = regexp.MustCompile(`#[0-9]+\s+(0x[0-9a-fA-F]+) at [A-Za-z0-9_.]+\+0x[0-9a-fA-F]+`)
	// DDB Stopped at line (exact PC), e.g. "Stopped at kdb_enter+0x6a: movq ...".
	freebsdStoppedAtRe = regexp.MustCompile(`Stopped at\s+([A-Za-z0-9_.]+)\+0x([0-9a-fA-F]+)`)
	// DDB db_trace_self_wrapper frame without PC, e.g. "func() at func+0x167c/frame 0x...".
	freebsdDDBStackRe = regexp.MustCompile(
		`\([^\n]*\)\s+at\s+([A-Za-z0-9_.]+)\+0x([0-9a-fA-F]+)(?:/frame\s+0x[0-9a-fA-F]+)?`)
)

func ctorFreebsd(cfg *config) (reporterImpl, []string, error) {
	kernelObject, symbols, err := loadKernelSymbols(cfg)
	if err != nil {
		return nil, nil, err
	}
	ctx := &freebsd{
		config:       cfg,
		kernelObject: kernelObject,
		symbols:      symbols,
	}
	return ctx, nil, nil
}

func (ctx *freebsd) ContainsCrash(output []byte) bool {
	return containsCrash(output, freebsdOopses, ctx.ignores)
}

func (ctx *freebsd) Parse(output []byte) *Report {
	return simpleLineParser(output, freebsdOopses, freebsdStackParams, ctx.ignores)
}

func (ctx *freebsd) Symbolize(rep *Report) error {
	return runSymbolizer(rep, ctx.target, ctx.kernelObject, &ctx.symbolizerCache, ctx.symbolizeLine)
}

func (ctx *freebsd) symbolizeLine(symbFunc bsdSymbFunc, line []byte) []byte {
	pc, insertPos, includeFunc, ok := ctx.parseSymbolizeLine(line)
	if !ok {
		return line
	}

	frames, err := symbFunc(ctx.kernelObject, pc)
	if err != nil || len(frames) == 0 {
		return line
	}
	var symbolized []byte
	for _, frame := range frames {
		file, _ := backend.CleanPath(frame.File, &ctx.kernelDirs, nil)
		file = strings.TrimPrefix(file, "usr/src/")
		file = strings.TrimPrefix(file, "build/src/")
		var info string
		if includeFunc || frame.Inline {
			info = fmt.Sprintf(" %v %v:%v", frame.Func, file, frame.Line)
		} else {
			info = fmt.Sprintf(" %v:%v", file, frame.Line)
		}
		if frame.Inline {
			info += " [inline]"
		}
		modified := slices.Clone(line)
		modified = replace(modified, insertPos, insertPos, []byte(info))
		symbolized = append(symbolized, modified...)
	}
	return symbolized
}

func (ctx *freebsd) parseSymbolizeLine(line []byte) (pc uint64, insertPos int, includeFunc, ok bool) {
	if match := freebsdRipRe.FindSubmatchIndex(line); match != nil {
		pc, err := strconv.ParseUint(string(line[match[2]:match[3]]), 0, 64)
		if err != nil || pc == 0 {
			return 0, 0, false, false
		}
		return pc, match[1], true, true
	}
	if match := freebsdStackPCRe.FindSubmatchIndex(line); match != nil {
		pc, err := strconv.ParseUint(string(line[match[2]:match[3]]), 0, 64)
		if err != nil || pc == 0 {
			return 0, 0, false, false
		}
		// Stack frames contain return addresses; look up the call instruction.
		return pc - 1, match[1], false, true
	}
	if match := freebsdStoppedAtRe.FindSubmatchIndex(line); match != nil {
		pc, found := ctx.lookupSymOffset(line, match, false)
		return pc, match[5], false, found
	}
	if match := freebsdDDBStackRe.FindSubmatchIndex(line); match != nil {
		pc, found := ctx.lookupSymOffset(line, match, true)
		return pc, match[1], false, found
	}
	return 0, 0, false, false
}

func (ctx *freebsd) lookupSymOffset(line []byte, match []int, returnPC bool) (uint64, bool) {
	fn := string(line[match[2]:match[3]])
	off, err := strconv.ParseUint(string(line[match[4]:match[5]]), 16, 64)
	if err != nil || returnPC && off == 0 {
		return 0, false
	}
	var matched *symbolizer.Symbol
	for i := range ctx.symbols[fn] {
		s := &ctx.symbols[fn][i]
		if s.Size <= 0 {
			continue
		}
		size := uint64(s.Size)
		if returnPC && off <= size || !returnPC && off < size {
			if matched != nil && matched.Addr != s.Addr {
				return 0, false
			}
			matched = s
		}
	}
	if matched == nil {
		return 0, false
	}
	pc := matched.Addr + off
	if returnPC {
		pc--
	}
	return pc, true
}

var freebsdStackParams = &stackParams{}

var freebsdOopses = append([]*oops{
	{
		[]byte("Fatal trap"),
		[]oopsFormat{
			{
				title: compile("Fatal trap (.+?)\\n(?:.*\\n)+?" +
					"KDB: stack backtrace:\\n" +
					"(?:#[0-9]+ {{ADDR}} at (?:kdb_backtrace|vpanic|panic|trap_fatal|" +
					"trap_pfault|trap|calltrap|m_copydata|__rw_wlock_hard)" +
					"\\+{{ADDR}}\\n)*#[0-9]+ {{ADDR}} at {{FUNC}}{{ADDR}}"),
				fmt: "Fatal trap %[1]v in %[2]v",
			},
			{
				title: compile("(Fatal trap [0-9]+:.*) while in (?:user|kernel) mode\\n(?:.*\\n)+?" +
					"KDB: stack backtrace:\\n" +
					"(?:[a-zA-Z0-9_]+\\(\\) at [a-zA-Z0-9_]+\\+0x.*\\n)*" +
					"--- trap 0x[0-9a-fA-F]+.* ---\\n" +
					"([a-zA-Z0-9_]+)\\(\\) at [a-zA-Z0-9_]+\\+0x.*\\n"),
				fmt: "%[1]v in %[2]v",
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte("panic:"),
		[]oopsFormat{
			{
				title: compile("panic: ffs_write: type {{ADDR}} [0-9]+ \\([0-9]+,[0-9]+\\)"),
				fmt:   "panic: ffs_write: type ADDR X (Y,Z)",
			},
			{
				title: compile("panic: ([a-zA-Z]+[a-zA-Z0-9_]*\\(\\)) of destroyed (mutex|rmlock|rwlock|sx) @ " +
					"/.*/(sys/.*:[0-9]+)"),
				fmt: "panic: %[1]v of destroyed %[2]v at %[3]v",
			},
			{
				title: compile("panic: No chunks on the queues for sid [0-9]+\\.\\n"),
				fmt:   "panic: sctp: no chunks on the queues",
			},
			{
				title: compile("panic: size_on_all_streams = [0-9]+ smaller than control length [0-9]+\\n"),
				fmt:   "panic: size_on_all_streams smaller than control length",
			},
			{
				title: compile("panic: sbflush_internal: ccc [0-9]+ mb [0-9]+ mbcnt [0-9]+\\n"),
				fmt:   "panic: sbflush_internal: residual data",
			},
			{
				title: compile("(panic: sx lock still held)\\n(?:.*\\n)+?" +
					"KDB: stack backtrace:\\n" +
					"(?:[a-zA-Z0-9_]+\\(\\) at [a-zA-Z0-9_]+\\+0x.*\\n)*" +
					"sx_destroy\\(\\) at [a-zA-Z0-9_+/ ]+\\n" +
					"([a-zA-Z0-9_]+)\\(\\) at [a-zA-Z0-9_+/ ]+\\+0x.*\\n"),
				fmt: "%[1]v in %[2]v",
			},
			{
				title: compile("panic: pfi_dynaddr_setup: dyn is 0x[0-9a-f]+\\n"),
				fmt:   "panic: pfi_dynaddr_setup: non-NULL dyn",
			},
			{
				title: compile("(panic: ASan: Invalid access, [0-9]+-byte (?:read|write)) at {{ADDR}},.*\\n(?:.*\\n)+?" +
					"KDB: stack backtrace:\\n" +
					"(?:[a-zA-Z0-9_]+\\(\\) at [a-zA-Z0-9_]+\\+0x.*\\n)*" +
					"__asan_.*\\(\\) at [a-zA-Z0-9_+/ ]+\\n" +
					"([a-zA-Z0-9_]+)\\(\\) at [a-zA-Z0-9_+/ ]+\\+0x.*\\n"),
				fmt: "%[1]v in %[2]v",
			},
		},
		[]*regexp.Regexp{},
	},
	&groupGoRuntimeErrors,
}, commonOopses...)
