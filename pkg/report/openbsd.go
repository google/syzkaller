// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"bufio"
	"bytes"
	"regexp"

	"github.com/google/syzkaller/sys/targets"
)

type openbsd struct {
	kernelSrc string
	kernelObj string
	ignores   []*regexp.Regexp
}

func ctorOpenbsd(target *targets.Target, kernelSrc, kernelObj string,
	ignores []*regexp.Regexp) (Reporter, []string, error) {
	ctx := &openbsd{
		kernelSrc: kernelSrc,
		kernelObj: kernelObj,
		ignores:   ignores,
	}
	return ctx, nil, nil
}

func (ctx *openbsd) ContainsCrash(output []byte) bool {
	return containsCrash(output, openbsdOopses, ctx.ignores)
}

func (ctx *openbsd) Parse(output []byte) *Report {
	stripped := bytes.Replace(output, []byte{'\r'}, nil, -1)
	rep := simpleLineParser(stripped, openbsdOopses, nil, ctx.ignores)
	if rep == nil {
		return nil
	}
	rep.Output = output
	if report := ctx.shortenReport(rep.Report); len(report) != 0 {
		rep.Report = report
	}
	return rep
}

func (ctx *openbsd) Symbolize(rep *Report) error {
	return nil
}

func (ctx *openbsd) shortenReport(report []byte) []byte {
	out := new(bytes.Buffer)
	for s := bufio.NewScanner(bytes.NewReader(report)); s.Scan(); {
		line := s.Bytes()
		out.Write(line)
		// Kernel splits lines at 79 column.
		if len(line) != 79 {
			out.WriteByte('\n')
		}
	}
	return out.Bytes()
}

var openbsdOopses = []*oops{
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
		[]byte("uvm_fault"),
		[]oopsFormat{
			{
				title: compile("uvm_fault\\((?:.*\\n)+?.*Stopped at[ ]+([^\\+]+)"),
				fmt:   "uvm_fault: %[1]v",
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte("panic"),
		[]oopsFormat{
			{
				title: compile("panic: pool_do_put: ([^:]+): double pool_put"),
				fmt:   "pool: double put: %[1]v",
			},
			{
				title: compile("panic: pool_do_get: ([^:]+) free list modified"),
				fmt:   "pool: free list modified: %[1]v",
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte("kernel:"),
		[]oopsFormat{},
		[]*regexp.Regexp{
			compile("reorder_kernel"),
		},
	},
}
