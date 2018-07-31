// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"bytes"
	"regexp"
)

type freebsd struct {
	kernelSrc string
	kernelObj string
	ignores   []*regexp.Regexp
}

func ctorFreebsd(kernelSrc, kernelObj string, ignores []*regexp.Regexp) (Reporter, []string, error) {
	ctx := &freebsd{
		kernelSrc: kernelSrc,
		kernelObj: kernelObj,
		ignores:   ignores,
	}
	return ctx, nil, nil
}

func (ctx *freebsd) ContainsCrash(output []byte) bool {
	return containsCrash(output, freebsdOopses, ctx.ignores)
}

func (ctx *freebsd) Parse(output []byte) *Report {
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
		for _, oops1 := range freebsdOopses {
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
		// Console output is indistinguishable from fuzzer output,
		// so we just collect everything after the oops.
		if oops != nil {
			lineEnd := next
			if lineEnd != 0 && output[lineEnd-1] == '\r' {
				lineEnd--
			}
			rep.Report = append(rep.Report, output[pos:lineEnd]...)
			rep.Report = append(rep.Report, '\n')
		}
		pos = next + 1
	}
	if oops == nil {
		return nil
	}
	title, corrupted, _ := extractDescription(output[rep.StartPos:], oops, freebsdStackParams)
	rep.Title = title
	rep.Corrupted = corrupted != ""
	rep.CorruptedReason = corrupted
	return rep
}

func (ctx *freebsd) Symbolize(rep *Report) error {
	return nil
}

var freebsdStackParams = &stackParams{}

var freebsdOopses = []*oops{
	{
		[]byte("Fatal trap"),
		[]oopsFormat{
			{
				title: compile("Fatal trap (.+?)\\r?\\n(?:.*\\n)+?" +
					"KDB: stack backtrace:\\r?\\n" +
					"(?:#[0-9]+ {{ADDR}} at (?:kdb_backtrace|vpanic|panic|trap_fatal|" +
					"trap_pfault|trap|calltrap|m_copydata|__rw_wlock_hard)" +
					"\\+{{ADDR}}\\r?\\n)*#[0-9]+ {{ADDR}} at {{FUNC}}{{ADDR}}"),
				fmt: "Fatal trap %[1]v in %[2]v",
			},
		},
		[]*regexp.Regexp{},
	},
	{
		[]byte("panic:"),
		[]oopsFormat{
			{
				title: compile("panic: ffs_write: type {{ADDR}} [0-9]+ \\([0-9]+,[0-9]+\\)"),
				fmt:   "panic: ffs_write: type ADDR X (Y,Z)",
			},
		},
		[]*regexp.Regexp{},
	},
}
