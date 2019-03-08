// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"regexp"

	"github.com/google/syzkaller/sys/targets"
)

type netbsd struct {
	kernelSrc string
	kernelObj string
	ignores   []*regexp.Regexp
}

func ctorNetbsd(target *targets.Target, kernelSrc, kernelObj string,
	ignores []*regexp.Regexp) (Reporter, []string, error) {
	ignores = append(ignores, regexp.MustCompile("event_init: unable to initialize")) // postfix output
	ctx := &netbsd{
		kernelSrc: kernelSrc,
		kernelObj: kernelObj,
		ignores:   ignores,
	}
	return ctx, nil, nil
}

func (ctx *netbsd) ContainsCrash(output []byte) bool {
	return containsCrash(output, netbsdOopses, ctx.ignores)
}

func (ctx *netbsd) Parse(output []byte) *Report {
	return simpleLineParser(output, netbsdOopses, nil, ctx.ignores)
}

func (ctx *netbsd) Symbolize(rep *Report) error {
	return nil
}

// nolint: lll
var netbsdOopses = []*oops{
	{
		[]byte("fault in supervisor mode"),
		[]oopsFormat{
			{
				title:  compile("fatal (?:page|protection) fault in supervisor mode"),
				report: compile(`fatal (?:page|protection) fault in supervisor mode(?:.*\n)+?--- trap.*?\n(.*?)\(`),
				fmt:    "page fault in %[1]v",
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
				report: compile(`panic: lock error:(?:.*\n)+?.*?Begin traceback.*?\n(?:.*(?:panic|printf|lockdebug|abort|mutex).*\n)*(.*?)\(`),
				fmt:    "lock error in %[1]v",
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte("ASan:"),
		[]oopsFormat{
			{
				title:  compile("ASan: Unauthorized Access"),
				report: compile(`ASan: Unauthorized Access (?:.*\n)+?.*in (.*)\<`),
				fmt:    "ASan: Unauthorized Access in %[1]v",
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
}
