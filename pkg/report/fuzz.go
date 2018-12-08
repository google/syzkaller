// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"fmt"

	"github.com/google/syzkaller/pkg/mgrconfig"
)

func Fuzz(data []byte) int {
	res := 0
	for _, reporter := range fuzzReporters {
		typ := reporter.(*reporterWrapper).typ
		containsCrash := reporter.ContainsCrash(data)
		rep := reporter.Parse(data)
		if containsCrash != (rep != nil) {
			panic(fmt.Sprintf("%v: ContainsCrash and Parse disagree", typ))
		}
		if rep == nil {
			continue
		}
		res = 1
		reporter.Symbolize(rep)
		if rep.Title == "" {
			panic(fmt.Sprintf("%v: Title is empty", typ))
		}
		if len(rep.Report) == 0 {
			panic(fmt.Sprintf("%v: len(Report) == 0", typ))
		}
		if len(rep.Output) == 0 {
			panic(fmt.Sprintf("%v: len(Output) == 0", typ))
		}
		if rep.StartPos != 0 && rep.EndPos != 0 && rep.StartPos >= rep.EndPos {
			panic(fmt.Sprintf("%v: StartPos=%v >= EndPos=%v", typ, rep.StartPos, rep.EndPos))
		}
		if rep.EndPos > len(rep.Output) {
			panic(fmt.Sprintf("%v: EndPos=%v > len(Output)=%v", typ, rep.EndPos, len(rep.Output)))
		}
	}
	return res
}

var fuzzReporters = func() []Reporter {
	var reporters []Reporter
	for os := range ctors {
		if os == "windows" {
			continue
		}
		cfg := &mgrconfig.Config{
			TargetOS:   os,
			TargetArch: "amd64",
		}
		reporter, err := NewReporter(cfg)
		if err != nil {
			panic(err)
		}
		if _, ok := reporter.(*stub); ok {
			continue
		}
		reporters = append(reporters, reporter)
	}
	return reporters
}()
