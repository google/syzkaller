// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"bytes"
	"regexp"
)

type openbsd struct {
	kernelSrc string
	kernelObj string
	ignores   []*regexp.Regexp
}

func ctorOpenbsd(kernelSrc, kernelObj string, ignores []*regexp.Regexp) (Reporter, []string, error) {
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
		for _, oops1 := range openbsdOopses {
			match := matchOops(output[pos:next], oops1, ctx.ignores)
			if match == -1 {
				continue
			}
			if oops == nil {
				oops = oops1
				rep.StartPos = pos
				rep.Title = string(output[pos+match : next])
			}
			rep.EndPos = next
		}
		if oops != nil {
			lineBegin := pos
			if output[pos] == '\r' {
				lineBegin++
			}
			rep.Report = append(rep.Report, output[lineBegin:next]...)
			rep.Report = append(rep.Report, '\n')
		}
		pos = next + 1
	}
	if oops == nil {
		return nil
	}
	title, corrupted, _ := extractDescription(output[rep.StartPos:], oops, openbsdStackParams)
	rep.Title = title
	rep.Corrupted = corrupted != ""
	rep.CorruptedReason = corrupted
	return rep
}

func (ctx *openbsd) Symbolize(rep *Report) error {
	return nil
}

var openbsdStackParams = &stackParams{}

var openbsdOopses = []*oops{
	&oops{
		[]byte("cleaned vnode"),
		[]oopsFormat{
			{
				title: compile("cleaned vnode: "),
				fmt:   "panic: cleaned vnode isn't",
			},
		},
		[]*regexp.Regexp{},
	},
	&oops{
		[]byte("uvm_fault"),
		[]oopsFormat{
			{
				title: compile("uvm_fault\\((?:.*\\n)+?.*Stopped at[ ]+([^\\+]+)"),
				fmt:   "uvm_fault: %[1]v",
			},
		},
		[]*regexp.Regexp{},
	},
	&oops{
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
	&oops{
		[]byte("kernel:"),
		[]oopsFormat{},
		[]*regexp.Regexp{
			compile("kernel relinking failed"),
		},
	},
}
