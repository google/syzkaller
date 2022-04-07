// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"bytes"
	"regexp"
)

type freebsd struct {
	*config
}

func ctorFreebsd(cfg *config) (reporterImpl, []string, error) {
	ctx := &freebsd{
		config: cfg,
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
			if !matchOops(output[pos:next], oops1, ctx.ignores) {
				continue
			}
			if oops == nil {
				oops = oops1
				rep.StartPos = pos
			}
			rep.EndPos = next
		}
		// Console output is indistinguishable from fuzzer output,
		// so we just collect everything after the oops.
		if oops != nil {
			rep.Report = append(rep.Report, output[pos:next]...)
			rep.Report = append(rep.Report, '\n')
		}
		pos = next + 1
	}
	if oops == nil {
		return nil
	}
	title, corrupted, altTitles, _ := extractDescription(output[rep.StartPos:], oops, freebsdStackParams)
	rep.Title = title
	rep.AltTitles = altTitles
	rep.Corrupted = corrupted != ""
	rep.CorruptedReason = corrupted
	return rep
}

func (ctx *freebsd) Symbolize(rep *Report) error {
	return nil
}

var freebsdStackParams = &stackParams{}

var freebsdOopses = append([]*oops{
	{
		[]byte("Fatal trap"),
		[]oopsFormat{
			{
				title: compile("Fatal trap (.+?)\\n(?:.*\\n)+?" +
					"KDB: stack backtrace:\\n" +
					"(?:#[0-9]+ {{ADDR}} at (?:kdb_backtrace|vpanic|panic|trap_fatal|" +
					"trap_pfault|trap|calltrap|m_copydata|__rw_wlock_hard)" +
					"\\+{{ADDR}}\\n)*#[0-9]+ {{ADDR}} at {{FUNC}}{{ADDR}}"),
				fmt: "Fatal trap %[1]v in %[2]v",
			},
			{
				title: compile("(Fatal trap [0-9]+:.*) while in (?:user|kernel) mode\\n(?:.*\\n)+?" +
					"KDB: stack backtrace:\\n" +
					"(?:[a-zA-Z0-9_]+\\(\\) at [a-zA-Z0-9_]+\\+0x.*\\n)*" +
					"--- trap 0x[0-9a-fA-F]+.* ---\\n" +
					"([a-zA-Z0-9_]+)\\(\\) at [a-zA-Z0-9_]+\\+0x.*\\n"),
				fmt: "%[1]v in %[2]v",
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
			{
				title: compile("panic: ([a-zA-Z]+[a-zA-Z0-9_]*\\(\\)) of destroyed (mutex|rmlock|rwlock|sx) @ " +
					"/.*/(sys/.*:[0-9]+)"),
				fmt: "panic: %[1]v of destroyed %[2]v at %[3]v",
			},
			{
				title: compile("panic: No chunks on the queues for sid [0-9]+\\.\\n"),
				fmt:   "panic: sctp: no chunks on the queues",
			},
			{
				title: compile("panic: size_on_all_streams = [0-9]+ smaller than control length [0-9]+\\n"),
				fmt:   "panic: size_on_all_streams smaller than control length",
			},
			{
				title: compile("panic: sbflush_internal: ccc [0-9]+ mb [0-9]+ mbcnt [0-9]+\\n"),
				fmt:   "panic: sbflush_internal: residual data",
			},
			{
				title: compile("(panic: sx lock still held)\\n(?:.*\\n)+?" +
					"KDB: stack backtrace:\\n" +
					"(?:[a-zA-Z0-9_]+\\(\\) at [a-zA-Z0-9_]+\\+0x.*\\n)*" +
					"sx_destroy\\(\\) at [a-zA-Z0-9_+/ ]+\\n" +
					"([a-zA-Z0-9_]+)\\(\\) at [a-zA-Z0-9_+/ ]+\\+0x.*\\n"),
				fmt: "%[1]v in %[2]v",
			},
			{
				title: compile("panic: pfi_dynaddr_setup: dyn is 0x[0-9a-f]+\\n"),
				fmt:   "panic: pfi_dynaddr_setup: non-NULL dyn",
			},
			{
				title: compile("(panic: ASan: Invalid access, [0-9]+-byte (?:read|write)) at {{ADDR}},.*\\n(?:.*\\n)+?" +
					"KDB: stack backtrace:\\n" +
					"(?:[a-zA-Z0-9_]+\\(\\) at [a-zA-Z0-9_]+\\+0x.*\\n)*" +
					"__asan_.*\\(\\) at [a-zA-Z0-9_+/ ]+\\n" +
					"([a-zA-Z0-9_]+)\\(\\) at [a-zA-Z0-9_+/ ]+\\+0x.*\\n"),
				fmt: "%[1]v in %[2]v",
			},
		},
		[]*regexp.Regexp{},
	},
}, commonOopses...)
