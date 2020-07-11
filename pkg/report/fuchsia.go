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
	"github.com/ianlancetaylor/demangle"
)

type fuchsia struct {
	*config
	obj string
}

var (
	zirconRIP          = regexp.MustCompile(` RIP: (0x[0-9a-f]+) `)
	zirconBT           = regexp.MustCompile(`^bt#[0-9]+: (0x[0-9a-f]+)`)
	zirconReportEnd    = []byte("Halted")
	zirconAssertFailed = []byte("ASSERT FAILED at")
	zirconLinePrefix   = regexp.MustCompile(`^\[\d+\.\d+\] \d+\.\d+> `)
	zirconUnrelated    = []*regexp.Regexp{
		regexp.MustCompile(`^$`),
		regexp.MustCompile(`stopping other cpus`),
		regexp.MustCompile(`^halting cpu`),
		regexp.MustCompile(`^dso: `),
		regexp.MustCompile(`^UPTIME: `),
		regexp.MustCompile(`^BUILDID `),
		regexp.MustCompile(`^Halting\.\.\.`),
	}
)

func ctorFuchsia(cfg *config) (Reporter, []string, error) {
	ctx := &fuchsia{
		config: cfg,
	}
	if ctx.kernelObj != "" {
		ctx.obj = filepath.Join(ctx.kernelObj, ctx.target.KernelObject)
	}
	suppressions := []string{
		"fatal exception: process /tmp/syz-fuzzer", // OOM presumably
	}
	return ctx, suppressions, nil
}

func (ctx *fuchsia) ContainsCrash(output []byte) bool {
	return containsCrash(output, zirconOopses, ctx.ignores)
}

func (ctx *fuchsia) Parse(output []byte) *Report {
	// We symbolize here because zircon output does not contain even function names.
	symbolized := ctx.symbolize(output)
	rep := simpleLineParser(symbolized, zirconOopses, zirconStackParams, ctx.ignores)
	if rep == nil {
		return nil
	}
	rep.Output = output
	if report := ctx.shortenReport(rep.Report); len(report) != 0 {
		rep.Report = report
	}
	return rep
}

func (ctx *fuchsia) shortenReport(report []byte) []byte {
	out := new(bytes.Buffer)
	for s := bufio.NewScanner(bytes.NewReader(report)); s.Scan(); {
		line := zirconLinePrefix.ReplaceAll(s.Bytes(), nil)
		if matchesAny(line, zirconUnrelated) {
			continue
		}
		if bytes.Contains(line, zirconReportEnd) {
			break
		}
		out.Write(line)
		out.WriteByte('\n')
	}
	return out.Bytes()
}

func (ctx *fuchsia) symbolize(output []byte) []byte {
	symb := symbolizer.NewSymbolizer(ctx.config.target)
	defer symb.Close()
	out := new(bytes.Buffer)
	for s := bufio.NewScanner(bytes.NewReader(output)); s.Scan(); {
		line := s.Bytes()
		if bytes.Contains(line, zirconAssertFailed) && len(line) == 127 {
			// This is super hacky: but zircon splits the most important information in long assert lines
			// (and they are always long) into several lines in irreversible way. Try to restore full line.
			line = append([]byte{}, line...)
			if s.Scan() {
				line = append(line, s.Bytes()...)
			}
		}
		if ctx.obj != "" {
			if match := zirconRIP.FindSubmatchIndex(line); match != nil {
				if ctx.processPC(out, symb, line, match, false) {
					continue
				}
			} else if match := zirconBT.FindSubmatchIndex(line); match != nil {
				if ctx.processPC(out, symb, line, match, true) {
					continue
				}
			}
		}
		out.Write(line)
		out.WriteByte('\n')
	}
	return out.Bytes()
}

func (ctx *fuchsia) processPC(out *bytes.Buffer, symb *symbolizer.Symbolizer,
	line []byte, match []int, call bool) bool {
	prefix := line[match[0]:match[1]]
	pcStart := match[2] - match[0]
	pcEnd := match[3] - match[0]
	pcStr := prefix[pcStart:pcEnd]
	pc, err := strconv.ParseUint(string(pcStr), 0, 64)
	if err != nil {
		return false
	}
	shortPC := pc & 0xfffffff
	pc = 0xffffffff80000000 | shortPC
	if call {
		pc--
	}
	frames, err := symb.Symbolize(ctx.obj, pc)
	if err != nil || len(frames) == 0 {
		return false
	}
	for _, frame := range frames {
		file := ctx.trimFile(frame.File)
		name := demangle.Filter(frame.Func, demangle.NoParams, demangle.NoTemplateParams)
		if strings.Contains(name, "<lambda(") {
			// Demangling produces super long (full) names for lambdas.
			name = "lambda"
		}
		id := "[ inline ]"
		if !frame.Inline {
			id = fmt.Sprintf("0x%08x", shortPC)
		}
		start := replace(append([]byte{}, prefix...), pcStart, pcEnd, []byte(id))
		fmt.Fprintf(out, "%s %v %v:%v\n", start, name, file, frame.Line)
	}
	return true
}

func (ctx *fuchsia) trimFile(file string) string {
	const (
		prefix1 = "zircon/kernel/"
		prefix2 = "zircon/"
	)
	if pos := strings.LastIndex(file, prefix1); pos != -1 {
		return file[pos+len(prefix1):]
	}
	if pos := strings.LastIndex(file, prefix2); pos != -1 {
		return file[pos+len(prefix2):]
	}
	return file
}

func (ctx *fuchsia) Symbolize(rep *Report) error {
	// We symbolize in Parse because zircon stacktraces don't contain even function names.
	return nil
}

var zirconStackParams = &stackParams{
	frameRes: []*regexp.Regexp{
		compile(` RIP: 0x[0-9a-f]{8} +([a-zA-Z0-9_:~]+)`),
		compile(` RIP: \[ inline \] +([a-zA-Z0-9_:~]+)`),
		compile(`^bt#[0-9]+: 0x[0-9a-f]{8} +([a-zA-Z0-9_:~]+)`),
		compile(`^bt#[0-9]+: \[ inline \] +([a-zA-Z0-9_:~]+)`),
	},
	skipPatterns: []string{
		"^platform_halt$",
		"^exception_die$",
		"^_panic$",
	},
}

var zirconOopses = append([]*oops{
	{
		[]byte("ZIRCON KERNEL PANIC"),
		[]oopsFormat{
			{
				title: compile("ZIRCON KERNEL PANIC(?:.*\\n)+?.*ASSERT FAILED(?:.*\\n)+?.*bt#00:"),
				fmt:   "ASSERT FAILED in %[1]v",
				stack: &stackFmt{
					parts: []*regexp.Regexp{
						parseStackTrace,
					},
				},
			},
			{
				// Some debug asserts don't contain stack trace.
				title:        compile("ZIRCON KERNEL PANIC(?:.*\\n)+?.*ASSERT FAILED at \\(.+?\\): (.*)"),
				fmt:          "ASSERT FAILED: %[1]v",
				noStackTrace: true,
			},
			{
				title: compile("ZIRCON KERNEL PANIC(?:.*\\n)+?.*double fault, halting(?:.*\\n)+?.*bt#00:"),
				fmt:   "double fault in %[1]v",
				stack: &stackFmt{
					parts: []*regexp.Regexp{
						parseStackTrace,
					},
				},
			},
			{
				// Some double faults don't contain stack trace.
				title:        compile("ZIRCON KERNEL PANIC(?:.*\\n)+?.*double fault, halting"),
				fmt:          "double fault",
				noStackTrace: true,
			},
			{
				title: compile("ZIRCON KERNEL PANIC(?:.*\\n)+?.*Supervisor Page Fault exception, halting"),
				fmt:   "Supervisor Fault in %[1]v",
				stack: &stackFmt{
					parts: []*regexp.Regexp{
						parseStackTrace,
					},
				},
			},
			{
				title: compile("ZIRCON KERNEL PANIC(?:.*\\n)+?.*recursion in interrupt handler"),
				fmt:   "recursion in interrupt handler in %[1]v",
				stack: &stackFmt{
					parts: []*regexp.Regexp{
						parseStackTrace,
					},
				},
			},
			{
				title:        compile("ZIRCON KERNEL PANIC(?:.*\\n)+?.*KVM internal error"),
				fmt:          "KVM internal error",
				noStackTrace: true,
			},
			{
				title: compile("ZIRCON KERNEL PANIC"),
				fmt:   "KERNEL PANIC in %[1]v",
				stack: &stackFmt{
					parts: []*regexp.Regexp{
						parseStackTrace,
					},
				},
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte("recursion in interrupt handler"),
		[]oopsFormat{
			{
				title: compile("recursion in interrupt handler(?:.*\\n)+?.*(?:bt#00:|RIP:)"),
				fmt:   "recursion in interrupt handler in %[1]v",
				stack: &stackFmt{
					parts: []*regexp.Regexp{
						parseStackTrace,
					},
				},
			},
			{
				title:        compile("recursion in interrupt handler"),
				fmt:          "recursion in interrupt handler",
				noStackTrace: true,
			},
		},
		[]*regexp.Regexp{},
	},
	// We should detect just "stopping other cpus" as some kernel crash rather then as "lost connection",
	// but if we add oops for "stopping other cpus", then it will interfere with other formats,
	// because "stopping other cpus" usually goes after "ZIRCON KERNEL PANIC", but sometimes before. Mess.
	// {
	//	[]byte("stopping other cpus"),
	// },
	{
		[]byte("welcome to Zircon"),
		[]oopsFormat{
			{
				title:        compile("welcome to Zircon"),
				fmt:          unexpectedKernelReboot,
				noStackTrace: true,
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte("KVM internal error"),
		[]oopsFormat{
			{
				title:        compile("KVM internal error"),
				fmt:          "KVM internal error",
				noStackTrace: true,
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte("<== fatal exception"),
		[]oopsFormat{
			{
				title:        compile("<== fatal exception"),
				report:       compile("<== fatal exception: process ([a-zA-Z0-9_/-]+)"),
				fmt:          "fatal exception in %[1]v",
				noStackTrace: true,
			},
		},
		[]*regexp.Regexp{
			compile("<== fatal exception: process .+?syz.+?\\["),
		},
	},
}, commonOopses...)
