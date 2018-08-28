// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
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
	return simpleLineParser(output, openbsdOopses, nil, ctx.ignores)
}

func (ctx *openbsd) Symbolize(rep *Report) error {
	return nil
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
			compile("kernel relinking failed"),
		},
	},
}
