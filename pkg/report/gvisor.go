// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"bytes"
	"regexp"
)

type gvisor struct {
	*config
}

func ctorGvisor(cfg *config) (Reporter, []string, error) {
	ctx := &gvisor{
		config: cfg,
	}
	suppressions := []string{
		"fatal error: runtime: out of memory",
		"fatal error: runtime: cannot allocate memory",
		"fatal error: newosproc",
		"panic: ptrace sysemu failed: no such process",                                          // OOM kill
		`panic: ptrace (s|g)et fpregs.* failed: no such process`,                                // OOM kill
		`panic: ptrace (s|g)et regs.* failed: no such process`,                                  // OOM kill
		"panic: error initializing first thread: resource temporarily unavailable",              // PID exhaustion
		"panic: unable to activate mm: creating stub process: resource temporarily unavailable", // PID exhaustion
		"panic: executor failed: pthread_create failed",                                         // PID exhaustion
		"panic: failed to start executor binary",
		"panic: error mapping run data: error mapping runData: cannot allocate memory",
		"race: limit on 8128 simultaneously alive goroutines is exceeded, dying",
		"ERROR: ThreadSanitizer", // Go race failing due to OOM.
		"FATAL: ThreadSanitizer",
	}
	return ctx, suppressions, nil
}

func (ctx *gvisor) ContainsCrash(output []byte) bool {
	return containsCrash(output, gvisorOopses, ctx.ignores)
}

func (ctx *gvisor) Parse(output []byte) *Report {
	rep := simpleLineParser(output, gvisorOopses, nil, ctx.ignores)
	if rep == nil {
		return nil
	}
	rep.Title = replaceTable(gvisorTitleReplacement, rep.Title)
	rep.Report = ctx.shortenReport(rep.Report)
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

var gvisorTitleReplacement = []replacement{
	{
		regexp.MustCompile(`container ".*"`),
		"container NAME",
	},
	{
		regexp.MustCompile(`sandbox ".*"`),
		"sandbox NAME",
	},
	{
		regexp.MustCompile(`(pid|PID) [0-9]+`),
		"pid X",
	},
}

var gvisorOopses = append([]*oops{
	{
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
	{
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
	{
		[]byte("SIGSEGV:"),
		[]oopsFormat{
			{
				title:        compile("SIGSEGV:(.*)"),
				fmt:          "SIGSEGV:%[1]v",
				noStackTrace: true,
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte("SIGBUS:"),
		[]oopsFormat{
			{
				title:        compile("SIGBUS:(.*)"),
				fmt:          "SIGBUS:%[1]v",
				noStackTrace: true,
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte("FATAL ERROR:"),
		[]oopsFormat{
			{
				title:        compile("FATAL ERROR:(.*)"),
				fmt:          "FATAL ERROR:%[1]v",
				noStackTrace: true,
			},
		},
		[]*regexp.Regexp{},
	},
	{
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
	{
		[]byte("Invalid request partialResult"),
		[]oopsFormat{
			{
				title:        compile("Invalid request partialResult"),
				report:       compile("Invalid request partialResult .* for (.*) operation"),
				fmt:          "Invalid request partialResult in %[1]v",
				noStackTrace: true,
			},
		},
		[]*regexp.Regexp{},
	},
}, commonOopses...)
