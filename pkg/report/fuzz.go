// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build gofuzz

package report

import (
	"regexp"
)

var reporter, _ = NewReporter("linux", "", "", nil, []*regexp.Regexp{regexp.MustCompile("foo")})

func FuzzLinux(data []byte) int {
	containsCrash := reporter.ContainsCrash(data)
	rep := reporter.Parse(data)
	if containsCrash != (rep != nil) {
		panic("ContainsCrash and Parse disagree")
	}
	if rep == nil {
		return 0
	}
	if rep.Title == "" {
		panic("rep.Title == \"\"")
	}
	if len(rep.Report) == 0 {
		panic("len(rep.Report) == 0")
	}
	if len(rep.Output) == 0 {
		panic("len(rep.Output) == 0")
	}
	if rep.StartPos >= rep.EndPos {
		panic("rep.StartPos >= rep.EndPos")
	}
	return 1
}
