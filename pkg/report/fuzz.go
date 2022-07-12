// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"fmt"

	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/sys/targets"
)

func Fuzz(data []byte) int {
	res := 0
	for os, reporter := range fuzzReporters {
		typ := reporter.typ
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
		if os == targets.Fuchsia {
			// Fuchsia has Start/End/SkipPos set incorrectly because it symbolizes before parsing.
			continue
		}
		if rep.StartPos != 0 && rep.EndPos != 0 && rep.StartPos >= rep.EndPos {
			panic(fmt.Sprintf("%v: bad StartPos\nStartPos=%v >= EndPos=%v",
				typ, rep.StartPos, rep.EndPos))
		}
		if rep.EndPos > len(rep.Output) {
			panic(fmt.Sprintf("%v: bad EndPos\nEndPos=%v > len(Output)=%v",
				typ, rep.EndPos, len(rep.Output)))
		}
		if rep.SkipPos <= rep.StartPos || rep.SkipPos > rep.EndPos {
			panic(fmt.Sprintf("%v: bad SkipPos\nSkipPos=%v: StartPos=%v EndPos=%v",
				typ, rep.SkipPos, rep.StartPos, rep.EndPos))
		}
		// If we parse from StartPos, we must find the same report.
		rep1 := reporter.ParseFrom(data, rep.StartPos)
		if rep1 == nil || rep1.Title != rep.Title || rep1.StartPos != rep.StartPos {
			title, startPos := "", -1
			if rep1 != nil {
				title, startPos = rep1.Title, rep1.StartPos
			}
			panic(fmt.Sprintf("%v: did not find the same reports at StartPos\n"+
				"StartPos=%v/%v\nTitle0=%q\nTitle1=%q",
				typ, rep.StartPos, startPos, rep.Title, title))
		}
	}
	return res
}

var fuzzReporters = func() map[string]*Reporter {
	reporters := make(map[string]*Reporter)
	for os := range ctors {
		if os == targets.Windows {
			continue
		}
		target := targets.Get(os, targets.AMD64)
		if target == nil {
			continue
		}
		cfg := &mgrconfig.Config{
			Derived: mgrconfig.Derived{
				SysTarget:  target,
				TargetOS:   os,
				TargetArch: targets.AMD64,
			},
		}
		reporter, err := NewReporter(cfg)
		if err != nil {
			panic(err)
		}
		if _, ok := reporter.impl.(*stub); ok {
			continue
		}
		reporters[os] = reporter
	}
	return reporters
}()
