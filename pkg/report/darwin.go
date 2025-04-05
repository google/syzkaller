// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"regexp"

	"github.com/google/syzkaller/pkg/report/crash"
)

func ctorDarwin(cfg *config) (reporterImpl, []string, error) {
	symbolizeRes := []*regexp.Regexp{}
	ctx, err := ctorBSD(cfg, darwinOopses, symbolizeRes)
	return ctx, nil, err
}

var darwinOopses = append([]*oops{
	{
		[]byte("panic(cpu "),
		[]oopsFormat{
			{
				title: compile("panic\\(.+\\): (assertion failed: .*), file"),
				fmt:   "panic: %[1]v",
			},
			{
				title: compile("panic\\(.+\\): Kernel trap at 0x[0-9a-f]+, (type .*), registers"),
				fmt:   "panic: Kernel trap %[1]v",
			},
			{
				title: compile("panic\\(.+\\): \"in6p_route_copyout: wrong or corrupted route:"),
				fmt:   "panic: in6p_route_copyout: wrong or corrupted route",
			},
			{
				title: compile("panic\\(.+\\): \"(zalloc:.+)\\([0-9]+ elements\\)( .*)\""),
				fmt:   "panic: %[1]v%[2]v",
			},
			{
				title: compile("panic\\(.+\\): \"(.*)\""),
				fmt:   "panic: %[1]v",
			},
			{
				title: compile("panic\\(.+\\): (.*)"),
				fmt:   "panic: %[1]v",
			},
		},
		[]*regexp.Regexp{},
		crash.UnknownType,
	},
	{
		[]byte("Debugger: Unexpected kernel trap number:"),
		[]oopsFormat{
			{
				title: compile("Debugger: (Unexpected kernel trap number: 0x[0-9a-f]+)"),
				fmt:   "debugger: %[1]v",
			},
		},
		[]*regexp.Regexp{},
		crash.UnknownType,
	},
	&groupGoRuntimeErrors,
}, commonOopses...)
