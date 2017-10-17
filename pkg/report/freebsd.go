// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"bytes"
	"fmt"
	"regexp"

	"github.com/google/syzkaller/pkg/symbolizer"
)

type freebsd struct {
	kernelSrc string
	kernelObj string
	symbols   map[string][]symbolizer.Symbol
	ignores   []*regexp.Regexp
}

func ctorFreebsd(kernelSrc, kernelObj string, symbols map[string][]symbolizer.Symbol,
	ignores []*regexp.Regexp) (Reporter, error) {
	ctx := &freebsd{
		kernelSrc: kernelSrc,
		kernelObj: kernelObj,
		symbols:   symbols,
		ignores:   ignores,
	}
	return ctx, nil
}

func (ctx *freebsd) ContainsCrash(output []byte) bool {
	return containsCrash(output, freebsdOopses, ctx.ignores)
}

func (ctx *freebsd) Parse(output []byte) (desc string, text []byte, start int, end int) {
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
				start = pos
				desc = string(output[pos+match : next])
			}
			end = next
		}
		// Console output is indistinguishable from fuzzer output,
		// so we just collect everything after the oops.
		if oops != nil {
			lineEnd := next
			if lineEnd != 0 && output[lineEnd-1] == '\r' {
				lineEnd--
			}
			text = append(text, output[pos:lineEnd]...)
			text = append(text, '\n')
		}
		pos = next + 1
	}
	if oops == nil {
		return
	}
	desc = extractDescription(output[start:], oops)
	return
}

func (ctx *freebsd) Symbolize(text []byte) ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}

func (ctx *freebsd) ExtractConsoleOutput(output []byte) (result []byte) {
	return output
}

func (ctx *freebsd) ExtractGuiltyFile(report []byte) string {
	return ""
}

func (ctx *freebsd) GetMaintainers(file string) ([]string, error) {
	return nil, fmt.Errorf("not implemented")
}

var freebsdOopses = []*oops{
	&oops{
		[]byte("Fatal trap"),
		[]oopsFormat{
			{
				compile("Fatal trap (.+?)\\r?\\n(?:.*\\n)+?" +
					"KDB: stack backtrace:\\r?\\n" +
					"(?:#[0-9]+ {{ADDR}} at (?:kdb_backtrace|vpanic|panic|trap_fatal|" +
					"trap_pfault|trap|calltrap|m_copydata|__rw_wlock_hard)" +
					"\\+{{ADDR}}\\r?\\n)*#[0-9]+ {{ADDR}} at {{FUNC}}{{ADDR}}"),
				"Fatal trap %[1]v in %[2]v",
			},
		},
		[]*regexp.Regexp{},
	},
	&oops{
		[]byte("panic:"),
		[]oopsFormat{
			{
				compile("panic: ffs_write: type {{ADDR}} [0-9]+ \\([0-9]+,[0-9]+\\)"),
				"panic: ffs_write: type ADDR X (Y,Z)",
			},
		},
		[]*regexp.Regexp{},
	},
}
