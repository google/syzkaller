// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"regexp"
)

func ctorNetbsd(cfg *config) (Reporter, []string, error) {
	symbolizeRes := []*regexp.Regexp{
		// stack
		regexp.MustCompile(` at netbsd:([A-Za-z0-9_]+)\+0x([0-9a-f]+)`),
		// witness
		regexp.MustCompile(`#[0-9]+ +([A-Za-z0-9_]+)\+0x([0-9a-f]+)`),
	}
	cfg.ignores = append(cfg.ignores, regexp.MustCompile("event_init: unable to initialize")) // postfix output
	ctx, err := ctorBSD(cfg, netbsdOopses, symbolizeRes)
	return ctx, nil, err
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
			{
				title:  compile("UBSan: Undefined Behavior"),
				report: compile(`UBSan: Undefined Behavior (?:.*\n)+(?:Handle|__ubsan).*\n(.*)\(`),
				fmt:    "UBSan: Undefined Behavior in %[1]v",
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
