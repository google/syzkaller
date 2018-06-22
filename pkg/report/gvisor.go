// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"bytes"
	"regexp"

	"github.com/google/syzkaller/pkg/symbolizer"
)

type gvisor struct {
	ignores []*regexp.Regexp
}

func ctorGvisor(kernelSrc, kernelObj string, symbols map[string][]symbolizer.Symbol,
	ignores []*regexp.Regexp) (Reporter, error) {
	ctx := &gvisor{
		ignores: ignores,
	}
	return ctx, nil
}

func (ctx *gvisor) ContainsCrash(output []byte) bool {
	return containsCrash(output, gvisorOopses, ctx.ignores)
}

func (ctx *gvisor) Parse(output []byte) *Report {
	rep := &Report{
		Output: output,
	}
	var oops *oops
	for pos := 0; pos < len(output); {
		next := bytes.IndexByte(output[pos:], '\n')
		if next != -1 {
			next += pos
		} else {
			next = len(output)
		}
		line := output[pos:next]
		for _, oops1 := range gvisorOopses {
			match := matchOops(line, oops1, ctx.ignores)
			if match != -1 {
				oops = oops1
				rep.StartPos = pos
				break
			}
		}
		if oops != nil {
			break
		}
		pos = next + 1
	}
	if oops == nil {
		return nil
	}
	title, corrupted, _ := extractDescription(output[rep.StartPos:], oops, nil)
	rep.Title = title
	rep.Report = ctx.shortenReport(output[rep.StartPos:])
	rep.Corrupted = corrupted != ""
	rep.corruptedReason = corrupted
	return rep
}

func (ctx *gvisor) shortenReport(report []byte) []byte {
	// gvisor panics include stacks of all goroutines.
	// This output is too lengthy for report and not very useful.
	// So we always take 5 lines from report and then cut it at the next empty line.
	// The intention is to capture panic header and traceback of the first goroutine.
	pos := 0
	for i := 0; i < 5; i++ {
		pos1 := bytes.IndexByte(report[pos:], '\n')
		if pos1 == -1 {
			return report
		}
		pos += pos1 + 1
	}
	end := bytes.Index(report[pos:], []byte{'\n', '\n'})
	if end == -1 {
		return report
	}
	if bytes.Contains(report, []byte("WARNING: DATA RACE")) {
		// For data races extract both stacks.
		end2 := bytes.Index(report[pos+end+2:], []byte{'\n', '\n'})
		if end2 != -1 {
			end += end2 + 2
		}
	}
	return report[:pos+end+1]
}

func (ctx *gvisor) Symbolize(rep *Report) error {
	return nil
}

var gvisorOopses = []*oops{
	&oops{
		[]byte("panic:"),
		[]oopsFormat{
			{
				title:        compile("panic:(.*)"),
				fmt:          "panic:%[1]v",
				noStackTrace: true,
			},
		},
		[]*regexp.Regexp{},
	},
	&oops{
		[]byte("Panic:"),
		[]oopsFormat{
			{
				title:        compile("Panic:(.*)"),
				fmt:          "Panic:%[1]v",
				noStackTrace: true,
			},
		},
		[]*regexp.Regexp{},
	},
	&oops{
		[]byte("fatal error:"),
		[]oopsFormat{
			{
				title:        compile("fatal error:(.*)"),
				fmt:          "fatal error:%[1]v",
				noStackTrace: true,
			},
		},
		[]*regexp.Regexp{},
	},
	&oops{
		[]byte("runtime error:"),
		[]oopsFormat{
			{
				title:        compile("runtime error:(.*)"),
				fmt:          "runtime error:%[1]v",
				noStackTrace: true,
			},
		},
		[]*regexp.Regexp{},
	},
	&oops{
		[]byte("signal SIGSEGV"),
		[]oopsFormat{
			{
				title:        compile("signal SIGSEGV(.*)"),
				fmt:          "signal SIGSEGV%[1]v",
				noStackTrace: true,
			},
		},
		[]*regexp.Regexp{},
	},
	&oops{
		[]byte("signal SIGBUS"),
		[]oopsFormat{
			{
				title:        compile("signal SIGBUS(.*)"),
				fmt:          "signal SIGBUS%[1]v",
				noStackTrace: true,
			},
		},
		[]*regexp.Regexp{},
	},
	&oops{
		[]byte("WARNING: DATA RACE"),
		[]oopsFormat{
			{
				title:        compile("WARNING: DATA RACE"),
				report:       compile("WARNING: DATA RACE\n(?:.*\n)*?  (?:[a-zA-Z0-9./-_]+/)([a-zA-Z0-9.()*_]+)\\(\\)\n"),
				fmt:          "DATA RACE in %[1]v",
				noStackTrace: true,
			},
		},
		[]*regexp.Regexp{},
	},
}
